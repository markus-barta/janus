package main

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound     = errors.New("descriptor not found")
	ErrPolicyDenied = errors.New("policy denied")
)

type PrincipalChain struct {
	HumanSubject string `json:"human_subject"`
	HumanEmail   string `json:"human_email,omitempty"`
	Authn        string `json:"authn"`
	Source       string `json:"source"`
}

func principalFromSession(session Session) PrincipalChain {
	return PrincipalChain{
		HumanSubject: session.Subject,
		HumanEmail:   session.Email,
		Authn:        "zitadel_oidc",
		Source:       "janus_web",
	}
}

type SecretProvider interface {
	Name() string
	Find(ref string) (SecretDescriptor, bool)
}

type AgeMetadataProvider struct {
	store *Store
}

func (p AgeMetadataProvider) Name() string {
	return "agenix"
}

func (p AgeMetadataProvider) Find(ref string) (SecretDescriptor, bool) {
	return p.store.FindDescriptor(ref)
}

type Broker struct {
	provider    SecretProvider
	store       *Store
	scopePolicy ScopePolicy
}

func NewBroker(store *Store) *Broker {
	return &Broker{
		provider:    AgeMetadataProvider{store: store},
		store:       store,
		scopePolicy: ScopePolicy{AllowedScopes: map[string]bool{"csb1": true}, Strict: true},
	}
}

func (b *Broker) WithScopePolicy(policy ScopePolicy) *Broker {
	b.scopePolicy = policy
	return b
}

func (b *Broker) Descriptors(_ PrincipalChain) []SecretDescriptor {
	return b.scopePolicy.Filter(b.store.Descriptors())
}

type HandleRequest struct {
	Ref    string `json:"ref"`
	Reason string `json:"reason,omitempty"`
}

type SecretHandle struct {
	HandleID      string    `json:"handle_id"`
	SecretRef     string    `json:"secret_ref"`
	DisplayName   string    `json:"display_name"`
	Provider      string    `json:"provider"`
	ExpiresAt     time.Time `json:"expires_at"`
	Capabilities  []string  `json:"capabilities"`
	ValueReturned bool      `json:"value_returned"`
}

func (b *Broker) ResolveHandle(principal PrincipalChain, req HandleRequest) (SecretHandle, error) {
	desc, ok := b.provider.Find(req.Ref)
	if !ok {
		return SecretHandle{}, ErrNotFound
	}
	if !b.scopePolicy.Allows(desc.Scope) {
		return SecretHandle{}, ErrPolicyDenied
	}
	if principal.HumanSubject == "" {
		return SecretHandle{}, ErrPolicyDenied
	}
	return SecretHandle{
		HandleID:      "h_" + randomToken(18),
		SecretRef:     desc.ID,
		DisplayName:   desc.DisplayName,
		Provider:      desc.Provider,
		ExpiresAt:     time.Now().UTC().Add(5 * time.Minute),
		Capabilities:  []string{"describe", "permit_request"},
		ValueReturned: false,
	}, nil
}

type PermitRequest struct {
	Ref         string `json:"ref"`
	Action      string `json:"action"`
	Destination string `json:"destination,omitempty"`
	Reason      string `json:"reason"`
}

type Permit struct {
	ID               string    `json:"id"`
	SecretRef        string    `json:"secret_ref"`
	Action           string    `json:"action"`
	Destination      string    `json:"destination,omitempty"`
	Reason           string    `json:"reason"`
	Status           string    `json:"status"`
	DenialReason     string    `json:"denial_reason,omitempty"`
	ExecutionAllowed bool      `json:"execution_allowed"`
	ValueReturned    bool      `json:"value_returned"`
	PrincipalHash    string    `json:"principal_hash"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type PermitRunResult struct {
	PermitID       string `json:"permit_id"`
	Status         string `json:"status"`
	Reason         string `json:"reason"`
	OutputScrubbed bool   `json:"output_scrubbed"`
	ValueReturned  bool   `json:"value_returned"`
}

func (b *Broker) CreatePermit(principal PrincipalChain, req PermitRequest) (Permit, error) {
	desc, ok := b.provider.Find(req.Ref)
	if !ok {
		return Permit{}, ErrNotFound
	}
	if !b.scopePolicy.Allows(desc.Scope) {
		return Permit{}, ErrPolicyDenied
	}
	if principal.HumanSubject == "" {
		return Permit{}, ErrPolicyDenied
	}
	if stringsTrim(req.Reason) == "" {
		return Permit{}, fmt.Errorf("%w: reason required", ErrPolicyDenied)
	}

	action := stringsTrim(req.Action)
	if action == "" {
		action = "metadata_use"
	}

	permit := Permit{
		ID:            "p_" + randomToken(18),
		SecretRef:     desc.ID,
		Action:        action,
		Destination:   stringsTrim(req.Destination),
		Reason:        stringsTrim(req.Reason),
		Status:        "approved_metadata_only",
		ValueReturned: false,
		PrincipalHash: actorHash(principal.HumanSubject),
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(10 * time.Minute),
	}

	switch action {
	case "metadata_use", "resolve_handle":
		permit.ExecutionAllowed = false
		permit.DenialReason = "no execution connector configured in V1.1"
	default:
		permit.Status = "denied"
		permit.DenialReason = "unsupported action"
	}
	return permit, nil
}

func RunPermit(permit Permit) PermitRunResult {
	if time.Now().UTC().After(permit.ExpiresAt) {
		return PermitRunResult{
			PermitID:       permit.ID,
			Status:         "denied",
			Reason:         "permit expired",
			OutputScrubbed: true,
			ValueReturned:  false,
		}
	}
	if !permit.ExecutionAllowed {
		reason := permit.DenialReason
		if reason == "" {
			reason = "execution is not enabled for this permit"
		}
		return PermitRunResult{
			PermitID:       permit.ID,
			Status:         "not_executed",
			Reason:         reason,
			OutputScrubbed: true,
			ValueReturned:  false,
		}
	}
	return PermitRunResult{
		PermitID:       permit.ID,
		Status:         "not_executed",
		Reason:         "execution connector intentionally absent in V1.1",
		OutputScrubbed: true,
		ValueReturned:  false,
	}
}

type PermitStore struct {
	mu      sync.RWMutex
	permits map[string]Permit
}

func NewPermitStore() *PermitStore {
	return &PermitStore{permits: make(map[string]Permit)}
}

func (s *PermitStore) Put(permit Permit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.permits[permit.ID] = permit
}

func (s *PermitStore) Get(id string) (Permit, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	permit, ok := s.permits[id]
	return permit, ok
}

func stringsTrim(value string) string {
	return strings.TrimSpace(value)
}
