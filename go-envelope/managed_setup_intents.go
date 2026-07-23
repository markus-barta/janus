package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	managedSignedIntentSchema       = "inspr.janus.signed-managed-service-setup-intent.v1"
	managedSetupIntentSchema        = "inspr.janus.managed-service-setup-intent.v1"
	managedVerificationKeysSchema   = "inspr.janus.managed-service-setup-verification-keys.v1"
	managedReplayStoreSchema        = "inspr.janus.managed-service-setup-replay-store.v1"
	managedManifestSchema           = "inspr.pharos.managed-service-declarations.v1"
	managedIntentDenialSchema       = "inspr.pharos.managed-service-setup-intent-delivery.v1"
	managedIntentSignatureDomain    = "inspr.janus.signed-managed-service-setup-intent.v1"
	managedHumanSessionRefDomain    = "inspr.managed-service-human-session.v1"
	managedIntentContractVersion    = 1
	managedIntentMaxTTLSeconds      = int64(300)
	managedIntentClockSkewSeconds   = int64(30)
	managedIntentMaxEnvelopeBytes   = int64(64 * 1024)
	managedManifestMaxBytes         = int64(64 * 1024)
	managedVerificationMaxBytes     = int64(32 * 1024)
	managedInternalTokenMaxBytes    = int64(8 * 1024)
	managedReplayMaxBytes           = int64(2 * 1024 * 1024)
	managedReplayMaximumEntries     = 4096
	managedSetupExpectedIssuerRef   = "sys_pharos_control_plane_v1"
	managedSetupExpectedAudienceRef = "sys_janus_secret_custody_v1"
)

type managedSignedIntent struct {
	Schema             string `json:"schema"`
	SchemaVersion      int    `json:"schema_version"`
	KeyID              string `json:"key_id"`
	PayloadBase64URL   string `json:"payload_base64url"`
	SignatureBase64URL string `json:"signature_base64url"`
}

type managedSetupIntent struct {
	Schema                 string `json:"schema"`
	SchemaVersion          int    `json:"schema_version"`
	IntentRef              string `json:"intent_ref"`
	OperationKind          string `json:"operation_kind"`
	Source                 string `json:"source"`
	HostRef                string `json:"host_ref"`
	ServiceRef             string `json:"service_ref"`
	SlotRef                string `json:"slot_ref"`
	HumanSessionRef        string `json:"human_session_ref"`
	IssuerRef              string `json:"issuer_ref"`
	AudienceRef            string `json:"audience_ref"`
	NonceRef               string `json:"nonce_ref"`
	DeclarationFingerprint string `json:"declaration_fingerprint"`
	IssuedAtUnixSeconds    int64  `json:"issued_at_unix_secs"`
	ExpiresAtUnixSeconds   int64  `json:"expires_at_unix_secs"`
	ReturnTarget           string `json:"return_target"`
}

type managedVerificationKeyDocument struct {
	Schema        string                   `json:"schema"`
	SchemaVersion int                      `json:"schema_version"`
	Keys          []managedVerificationKey `json:"keys"`
}

type managedVerificationKey struct {
	KeyID              string `json:"key_id"`
	PublicKeyBase64URL string `json:"public_key_base64url"`
}

type managedIntentKeyring map[string]ed25519.PublicKey

type managedSetupRuntimeConfig struct {
	PharosOrigin       string
	PharosReturnOrigin string
	InternalToken      string
	Keyring            managedIntentKeyring
	ManifestPaths      []string
	TransactionSocket  string
}

func loadManagedSetupRuntimeConfigFromEnv() (*managedSetupRuntimeConfig, error) {
	pharosOrigin := strings.TrimSpace(os.Getenv("JANUS_MANAGED_SETUP_PHAROS_ORIGIN"))
	returnOrigin := strings.TrimSpace(os.Getenv("JANUS_MANAGED_SETUP_PHAROS_RETURN_ORIGIN"))
	tokenFile := strings.TrimSpace(os.Getenv("JANUS_MANAGED_SETUP_INTERNAL_TOKEN_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("JANUS_MANAGED_SETUP_VERIFICATION_KEYS_FILE"))
	manifestRaw := strings.TrimSpace(os.Getenv("JANUS_MANAGED_SETUP_MANIFEST_PATHS"))
	transactionSocket := strings.TrimSpace(os.Getenv("JANUS_MANAGED_WEB_TRANSACTION_SOCKET"))
	if pharosOrigin == "" && returnOrigin == "" && tokenFile == "" && keyFile == "" && manifestRaw == "" && transactionSocket == "" {
		return nil, nil
	}
	if pharosOrigin == "" || tokenFile == "" || keyFile == "" || manifestRaw == "" || transactionSocket == "" {
		return nil, errors.New("managed setup configuration is partial")
	}
	if returnOrigin == "" {
		returnOrigin = pharosOrigin
	}
	if _, err := parseManagedOrigin(pharosOrigin); err != nil {
		return nil, errors.New("managed setup Pharos origin is invalid")
	}
	if _, err := parseManagedOrigin(returnOrigin); err != nil {
		return nil, errors.New("managed setup Pharos return origin is invalid")
	}
	tokenBytes, err := readBoundedPrivateFile(tokenFile, managedInternalTokenMaxBytes)
	if err != nil {
		return nil, errors.New("managed setup internal token is unavailable")
	}
	token := strings.TrimSpace(string(tokenBytes))
	if len(token) < 32 || strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return nil, errors.New("managed setup internal token contract is invalid")
	}
	keyring, err := loadManagedIntentKeyring(keyFile)
	if err != nil {
		return nil, err
	}
	var manifestPaths []string
	seen := map[string]bool{}
	for _, item := range strings.Split(manifestRaw, ",") {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			return nil, errors.New("managed setup manifest path contract is invalid")
		}
		seen[item] = true
		manifestPaths = append(manifestPaths, item)
	}
	if len(manifestPaths) == 0 || len(manifestPaths) > 64 {
		return nil, errors.New("managed setup manifest path contract is invalid")
	}
	if !filepath.IsAbs(transactionSocket) || filepath.Clean(transactionSocket) != transactionSocket {
		return nil, errors.New("managed setup transaction socket contract is invalid")
	}
	return &managedSetupRuntimeConfig{
		PharosOrigin:       pharosOrigin,
		PharosReturnOrigin: returnOrigin,
		InternalToken:      token,
		Keyring:            keyring,
		ManifestPaths:      manifestPaths,
		TransactionSocket:  transactionSocket,
	}, nil
}

func newManagedSetupIntentConsumer(config managedSetupRuntimeConfig, dataDir string) (*managedSetupIntentConsumer, error) {
	fetcher, err := newManagedHTTPIntentFetcher(config.PharosOrigin, config.InternalToken, nil)
	if err != nil {
		return nil, err
	}
	replays, err := newManagedReplayStore(filepath.Join(dataDir, "managed-setup-replays.json"))
	if err != nil {
		return nil, err
	}
	return &managedSetupIntentConsumer{
		fetcher:     fetcher,
		keyring:     config.Keyring,
		declaration: managedManifestResolver{paths: append([]string(nil), config.ManifestPaths...)},
		replays:     replays,
		issuerRef:   managedSetupExpectedIssuerRef,
		audienceRef: managedSetupExpectedAudienceRef,
		now:         time.Now,
	}, nil
}

func loadManagedIntentKeyring(path string) (managedIntentKeyring, error) {
	raw, err := readBoundedFile(path, managedVerificationMaxBytes)
	if err != nil {
		return nil, errors.New("managed_intent_verification_keys_unavailable")
	}
	var document managedVerificationKeyDocument
	if err := decodeStrictJSON(raw, &document); err != nil ||
		document.Schema != managedVerificationKeysSchema ||
		document.SchemaVersion != managedIntentContractVersion ||
		len(document.Keys) == 0 ||
		len(document.Keys) > 16 {
		return nil, errors.New("managed_intent_verification_keys_invalid")
	}
	keyring := make(managedIntentKeyring, len(document.Keys))
	for _, item := range document.Keys {
		if !validManagedRef("key_", item.KeyID) {
			return nil, errors.New("managed_intent_verification_keys_invalid")
		}
		decoded, err := base64.RawURLEncoding.DecodeString(item.PublicKeyBase64URL)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, errors.New("managed_intent_verification_keys_invalid")
		}
		if _, exists := keyring[item.KeyID]; exists {
			return nil, errors.New("managed_intent_verification_keys_invalid")
		}
		keyring[item.KeyID] = ed25519.PublicKey(append([]byte(nil), decoded...))
	}
	return keyring, nil
}

type managedIntentFetcher interface {
	Fetch(context.Context, string) (managedSignedIntent, error)
}

type managedHTTPIntentFetcher struct {
	origin *url.URL
	token  string
	client *http.Client
}

func newManagedHTTPIntentFetcher(origin, token string, transport http.RoundTripper) (*managedHTTPIntentFetcher, error) {
	parsed, err := parseManagedOrigin(origin)
	if err != nil || len(token) < 32 || strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return nil, errors.New("managed_intent_fetch_config_invalid")
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &managedHTTPIntentFetcher{
		origin: parsed,
		token:  token,
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("managed_intent_redirect_rejected")
			},
		},
	}, nil
}

func (fetcher *managedHTTPIntentFetcher) Fetch(ctx context.Context, intentRef string) (managedSignedIntent, error) {
	if !validManagedRef("intent_", intentRef) {
		return managedSignedIntent{}, managedIntentError("managed_intent_unknown")
	}
	target := *fetcher.origin
	target.Path = "/internal/managed-service-setup-intents/" + intentRef
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return managedSignedIntent{}, managedIntentError("managed_intent_pharos_unavailable")
	}
	request.Header.Set("Authorization", "Bearer "+fetcher.token)
	request.Header.Set("Accept", "application/json")
	response, err := fetcher.client.Do(request)
	if err != nil {
		return managedSignedIntent{}, managedIntentError("managed_intent_pharos_unavailable")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, managedIntentMaxEnvelopeBytes+1))
	if err != nil || int64(len(raw)) > managedIntentMaxEnvelopeBytes {
		return managedSignedIntent{}, managedIntentError("managed_intent_pharos_unavailable")
	}
	if response.StatusCode != http.StatusOK {
		var denial struct {
			Schema        string `json:"schema"`
			SchemaVersion int    `json:"schema_version"`
			Outcome       string `json:"outcome"`
			ReasonCode    string `json:"reason_code"`
			ValueReturned bool   `json:"value_returned"`
		}
		if decodeStrictJSON(raw, &denial) == nil &&
			denial.Schema == managedIntentDenialSchema &&
			denial.SchemaVersion == managedIntentContractVersion &&
			denial.Outcome == "denied" &&
			!denial.ValueReturned &&
			validManagedDenialReason(denial.ReasonCode) {
			return managedSignedIntent{}, managedIntentError(denial.ReasonCode)
		}
		return managedSignedIntent{}, managedIntentError("managed_intent_pharos_unavailable")
	}
	var envelope managedSignedIntent
	if err := decodeStrictJSON(raw, &envelope); err != nil {
		return managedSignedIntent{}, managedIntentError("managed_intent_envelope_invalid")
	}
	return envelope, nil
}

type managedDeclarationResolver interface {
	Matches(managedSetupIntent) error
}

type managedManifestResolver struct {
	paths []string
}

func (resolver managedManifestResolver) Matches(intent managedSetupIntent) error {
	if len(resolver.paths) == 0 {
		return managedIntentError("managed_intent_declaration_unavailable")
	}
	found := false
	seenHosts := map[string]bool{}
	seenServices := map[string]bool{}
	seenSlots := map[string]bool{}
	for _, path := range resolver.paths {
		raw, err := readBoundedFile(path, managedManifestMaxBytes)
		if err != nil {
			return managedIntentError("managed_intent_declaration_unavailable")
		}
		var manifest managedManifest
		if err := decodeStrictJSON(raw, &manifest); err != nil || validateManagedManifest(manifest) != nil {
			return managedIntentError("managed_intent_declaration_unavailable")
		}
		if seenHosts[manifest.HostRef] {
			return managedIntentError("managed_intent_declaration_unavailable")
		}
		seenHosts[manifest.HostRef] = true
		for _, service := range manifest.Services {
			if seenServices[service.ServiceRef] {
				return managedIntentError("managed_intent_declaration_unavailable")
			}
			seenServices[service.ServiceRef] = true
			for _, slot := range service.Slots {
				if seenSlots[slot.SlotRef] {
					return managedIntentError("managed_intent_declaration_unavailable")
				}
				seenSlots[slot.SlotRef] = true
				if manifest.HostRef == intent.HostRef &&
					service.ServiceRef == intent.ServiceRef &&
					slot.SlotRef == intent.SlotRef &&
					manifest.DeclarationFingerprint == intent.DeclarationFingerprint &&
					containsManagedSource(slot.AllowedSources, intent.Source) {
					found = true
				}
			}
		}
	}
	if !found {
		return managedIntentError("managed_intent_declaration_drift")
	}
	return nil
}

type managedManifest struct {
	Schema                 string                   `json:"schema"`
	SchemaVersion          int                      `json:"schema_version"`
	GeneratedBy            string                   `json:"generated_by"`
	HostRef                string                   `json:"host_ref"`
	DeclarationFingerprint string                   `json:"declaration_fingerprint"`
	Services               []managedManifestService `json:"services"`
}

type managedManifestService struct {
	ServiceRef  string                `json:"service_ref"`
	SafeLabel   string                `json:"safe_label"`
	RuntimeKind string                `json:"runtime_kind"`
	Slots       []managedManifestSlot `json:"slots"`
}

type managedManifestSlot struct {
	SlotRef        string                  `json:"slot_ref"`
	SafeLabel      string                  `json:"safe_label"`
	ConsumerKind   string                  `json:"consumer_kind"`
	Delivery       managedManifestDelivery `json:"delivery"`
	Reload         managedManifestReload   `json:"reload"`
	Health         managedManifestHealth   `json:"health"`
	AllowedSources []string                `json:"allowed_sources"`
}

type managedManifestDelivery struct {
	Kind       string `json:"kind"`
	ProfileRef string `json:"profile_ref"`
}

type managedManifestReload struct {
	Method     string `json:"method"`
	ProfileRef string `json:"profile_ref"`
}

type managedManifestHealth struct {
	Probe      string `json:"probe"`
	ProfileRef string `json:"profile_ref"`
}

type managedCanonicalManifest struct {
	HostRef  string                            `json:"host_ref"`
	Services []managedCanonicalManifestService `json:"services"`
}

type managedCanonicalManifestService struct {
	RuntimeKind string                         `json:"runtime_kind"`
	SafeLabel   string                         `json:"safe_label"`
	ServiceRef  string                         `json:"service_ref"`
	Slots       []managedCanonicalManifestSlot `json:"slots"`
}

type managedCanonicalManifestSlot struct {
	AllowedSources []string                `json:"allowed_sources"`
	ConsumerKind   string                  `json:"consumer_kind"`
	Delivery       managedManifestDelivery `json:"delivery"`
	Health         managedManifestHealth   `json:"health"`
	Reload         managedManifestReload   `json:"reload"`
	SafeLabel      string                  `json:"safe_label"`
	SlotRef        string                  `json:"slot_ref"`
}

func validateManagedManifest(manifest managedManifest) error {
	if manifest.Schema != managedManifestSchema ||
		manifest.SchemaVersion != managedIntentContractVersion ||
		manifest.GeneratedBy != "nixcfg" ||
		!validManagedRef("host_", manifest.HostRef) ||
		!validManagedRef("decl_", manifest.DeclarationFingerprint) ||
		len(manifest.Services) == 0 ||
		len(manifest.Services) > 64 {
		return errors.New("managed_intent_declaration_invalid")
	}
	canonical := managedCanonicalManifest{HostRef: manifest.HostRef}
	lastService := ""
	seenSlots := map[string]bool{}
	for _, service := range manifest.Services {
		if !validManagedRef("svc_", service.ServiceRef) ||
			!validManagedSafeLabel(service.SafeLabel) ||
			service.RuntimeKind != "compose" ||
			service.ServiceRef <= lastService ||
			len(service.Slots) == 0 ||
			len(service.Slots) > 32 {
			return errors.New("managed_intent_declaration_invalid")
		}
		lastService = service.ServiceRef
		canonicalService := managedCanonicalManifestService{
			RuntimeKind: service.RuntimeKind,
			SafeLabel:   service.SafeLabel,
			ServiceRef:  service.ServiceRef,
		}
		lastSlot := ""
		for _, slot := range service.Slots {
			if !validManagedRef("slot_", slot.SlotRef) ||
				seenSlots[slot.SlotRef] ||
				slot.SlotRef <= lastSlot ||
				!validManagedSafeLabel(slot.SafeLabel) ||
				slot.ConsumerKind != "managed_service" ||
				slot.Delivery.Kind != "private_env_file" ||
				!validManagedRef("delivery_", slot.Delivery.ProfileRef) ||
				slot.Reload.Method != "compose_recreate" ||
				!validManagedRef("reload_", slot.Reload.ProfileRef) ||
				slot.Health.Probe != "compose_healthcheck" ||
				!validManagedRef("health_", slot.Health.ProfileRef) ||
				!validManagedSourcePolicy(slot.AllowedSources) {
				return errors.New("managed_intent_declaration_invalid")
			}
			seenSlots[slot.SlotRef] = true
			lastSlot = slot.SlotRef
			canonicalService.Slots = append(canonicalService.Slots, managedCanonicalManifestSlot{
				AllowedSources: slot.AllowedSources,
				ConsumerKind:   slot.ConsumerKind,
				Delivery:       slot.Delivery,
				Health:         slot.Health,
				Reload:         slot.Reload,
				SafeLabel:      slot.SafeLabel,
				SlotRef:        slot.SlotRef,
			})
		}
		canonical.Services = append(canonical.Services, canonicalService)
	}
	raw, err := encodeManagedCanonicalJSON(canonical)
	if err != nil {
		return errors.New("managed_intent_declaration_invalid")
	}
	digest := sha256.Sum256(raw)
	expected := "decl_" + hex.EncodeToString(digest[:])
	if manifest.DeclarationFingerprint != expected {
		return errors.New("managed_intent_declaration_invalid")
	}
	return nil
}

type managedReplayStore struct {
	path     string
	mu       sync.Mutex
	document managedReplayDocument
}

type managedReplayDocument struct {
	Schema        string                         `json:"schema"`
	SchemaVersion int                            `json:"schema_version"`
	Intents       map[string]managedReplayRecord `json:"intents"`
	Nonces        map[string]string              `json:"nonces"`
}

type managedReplayRecord struct {
	OperationRef         string `json:"operation_ref"`
	ConsumedAtUnixSecond int64  `json:"consumed_at_unix_secs"`
	ExpiresAtUnixSecond  int64  `json:"expires_at_unix_secs"`
}

func newManagedReplayStore(path string) (*managedReplayStore, error) {
	document := managedReplayDocument{
		Schema:        managedReplayStoreSchema,
		SchemaVersion: managedIntentContractVersion,
		Intents:       map[string]managedReplayRecord{},
		Nonces:        map[string]string{},
	}
	raw, err := readBoundedFile(path, managedReplayMaxBytes)
	if err == nil {
		if decodeStrictJSON(raw, &document) != nil || validateManagedReplayDocument(document) != nil {
			return nil, errors.New("managed_intent_replay_store_invalid")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("managed_intent_replay_store_unavailable")
	}
	return &managedReplayStore{path: path, document: document}, nil
}

func (store *managedReplayStore) consume(intent managedSetupIntent, now int64) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for ref, record := range store.document.Intents {
		if record.ExpiresAtUnixSecond <= now {
			delete(store.document.Intents, ref)
		}
	}
	for nonce, intentRef := range store.document.Nonces {
		if _, exists := store.document.Intents[intentRef]; !exists {
			delete(store.document.Nonces, nonce)
		}
	}
	if _, exists := store.document.Intents[intent.IntentRef]; exists {
		return "", managedIntentError("managed_intent_replayed")
	}
	if _, exists := store.document.Nonces[intent.NonceRef]; exists {
		return "", managedIntentError("managed_intent_replayed")
	}
	if len(store.document.Intents) >= managedReplayMaximumEntries {
		return "", managedIntentError("managed_intent_replay_capacity")
	}
	operationRef, err := randomManagedRef("op_")
	if err != nil {
		return "", managedIntentError("managed_intent_replay_store_unavailable")
	}
	record := managedReplayRecord{
		OperationRef:         operationRef,
		ConsumedAtUnixSecond: now,
		ExpiresAtUnixSecond:  intent.ExpiresAtUnixSeconds,
	}
	store.document.Intents[intent.IntentRef] = record
	store.document.Nonces[intent.NonceRef] = intent.IntentRef
	if err := atomicWriteManagedJSON(store.path, store.document); err != nil {
		if !managedFinalFileReplaced(err) {
			delete(store.document.Intents, intent.IntentRef)
			delete(store.document.Nonces, intent.NonceRef)
		}
		return "", managedIntentError("managed_intent_replay_store_unavailable")
	}
	return operationRef, nil
}

type managedAcceptedIntent struct {
	Intent       managedSetupIntent
	OperationRef string
}

type managedSetupIntentAuthority interface {
	Inspect(context.Context, string, string) (managedSetupIntent, error)
	Consume(context.Context, string, string) (managedAcceptedIntent, error)
}

type managedSetupIntentConsumer struct {
	fetcher     managedIntentFetcher
	keyring     managedIntentKeyring
	declaration managedDeclarationResolver
	replays     *managedReplayStore
	issuerRef   string
	audienceRef string
	now         func() time.Time
}

func (consumer *managedSetupIntentConsumer) Inspect(ctx context.Context, intentRef, humanSessionRef string) (managedSetupIntent, error) {
	if !validManagedRef("intent_", intentRef) || !validManagedRef("hsn_", humanSessionRef) {
		return managedSetupIntent{}, managedIntentError("managed_intent_invalid_request")
	}
	envelope, err := consumer.fetcher.Fetch(ctx, intentRef)
	if err != nil {
		return managedSetupIntent{}, normalizeManagedIntentError(err)
	}
	intent, err := verifyManagedSetupIntent(envelope, consumer.keyring)
	if err != nil {
		return managedSetupIntent{}, err
	}
	now := consumer.now().Unix()
	if intent.IntentRef != intentRef {
		return managedSetupIntent{}, managedIntentError("managed_intent_reference_mismatch")
	}
	if intent.IssuerRef != consumer.issuerRef {
		return managedSetupIntent{}, managedIntentError("managed_intent_wrong_issuer")
	}
	if intent.AudienceRef != consumer.audienceRef {
		return managedSetupIntent{}, managedIntentError("managed_intent_wrong_audience")
	}
	if intent.HumanSessionRef != humanSessionRef {
		return managedSetupIntent{}, managedIntentError("managed_intent_wrong_user")
	}
	if intent.IssuedAtUnixSeconds > now+managedIntentClockSkewSeconds {
		return managedSetupIntent{}, managedIntentError("managed_intent_not_yet_valid")
	}
	if now >= intent.ExpiresAtUnixSeconds {
		return managedSetupIntent{}, managedIntentError("managed_intent_expired")
	}
	if err := consumer.declaration.Matches(intent); err != nil {
		return managedSetupIntent{}, normalizeManagedIntentError(err)
	}
	return intent, nil
}

func (consumer *managedSetupIntentConsumer) Consume(ctx context.Context, intentRef, humanSessionRef string) (managedAcceptedIntent, error) {
	intent, err := consumer.Inspect(ctx, intentRef, humanSessionRef)
	if err != nil {
		return managedAcceptedIntent{}, err
	}
	now := consumer.now().Unix()
	operationRef, err := consumer.replays.consume(intent, now)
	if err != nil {
		return managedAcceptedIntent{}, normalizeManagedIntentError(err)
	}
	return managedAcceptedIntent{Intent: intent, OperationRef: operationRef}, nil
}

func verifyManagedSetupIntent(envelope managedSignedIntent, keyring managedIntentKeyring) (managedSetupIntent, error) {
	if envelope.Schema != managedSignedIntentSchema ||
		envelope.SchemaVersion != managedIntentContractVersion ||
		!validManagedRef("key_", envelope.KeyID) {
		return managedSetupIntent{}, managedIntentError("managed_intent_version_unsupported")
	}
	publicKey, exists := keyring[envelope.KeyID]
	if !exists {
		return managedSetupIntent{}, managedIntentError("managed_intent_signing_key_unknown")
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.PayloadBase64URL)
	if err != nil || len(payload) == 0 || int64(len(payload)) > managedIntentMaxEnvelopeBytes {
		return managedSetupIntent{}, managedIntentError("managed_intent_envelope_invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.SignatureBase64URL)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, managedIntentSignatureMessage(envelope.KeyID, payload), signature) {
		return managedSetupIntent{}, managedIntentError("managed_intent_signature_invalid")
	}
	var intent managedSetupIntent
	if err := decodeStrictJSON(payload, &intent); err != nil || validateManagedSetupIntent(intent) != nil {
		return managedSetupIntent{}, managedIntentError("managed_intent_payload_invalid")
	}
	return intent, nil
}

func validateManagedSetupIntent(intent managedSetupIntent) error {
	ttl := intent.ExpiresAtUnixSeconds - intent.IssuedAtUnixSeconds
	if intent.Schema != managedSetupIntentSchema ||
		intent.SchemaVersion != managedIntentContractVersion ||
		!validManagedRef("intent_", intent.IntentRef) ||
		!validManagedRef("host_", intent.HostRef) ||
		!validManagedRef("svc_", intent.ServiceRef) ||
		!validManagedRef("slot_", intent.SlotRef) ||
		!validManagedRef("hsn_", intent.HumanSessionRef) ||
		!validManagedRef("sys_", intent.IssuerRef) ||
		!validManagedRef("sys_", intent.AudienceRef) ||
		!validManagedRef("nonce_", intent.NonceRef) ||
		!validManagedRef("decl_", intent.DeclarationFingerprint) ||
		(intent.OperationKind != "create" && intent.OperationKind != "replace") ||
		(intent.Source != "generated" && intent.Source != "import") ||
		intent.ReturnTarget != "pharos_service" ||
		intent.IssuedAtUnixSeconds <= 0 ||
		ttl <= 0 ||
		ttl > managedIntentMaxTTLSeconds {
		return errors.New("managed_intent_payload_invalid")
	}
	return nil
}

func managedIntentSignatureMessage(keyID string, payload []byte) []byte {
	message := make([]byte, 0, len(managedIntentSignatureDomain)+len(keyID)+len(payload)+2)
	message = append(message, managedIntentSignatureDomain...)
	message = append(message, 0)
	message = append(message, keyID...)
	message = append(message, 0)
	message = append(message, payload...)
	return message
}

func managedHumanSessionRef(issuer, subject string) string {
	hasher := sha256.New()
	hasher.Write([]byte(managedHumanSessionRefDomain))
	hasher.Write([]byte{0})
	hasher.Write([]byte(strings.TrimRight(issuer, "/")))
	hasher.Write([]byte{0})
	hasher.Write([]byte(subject))
	return "hsn_" + hex.EncodeToString(hasher.Sum(nil))
}

func managedReturnURL(pharosOrigin, operationRef string) (string, error) {
	origin, err := parseManagedOrigin(pharosOrigin)
	if err != nil || !validManagedRef("op_", operationRef) {
		return "", errors.New("managed_intent_return_target_invalid")
	}
	target := *origin
	target.Path = "/managed-service/operations/" + operationRef
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	return target.String(), nil
}

type managedIntentError string

func (err managedIntentError) Error() string { return string(err) }

func normalizeManagedIntentError(err error) error {
	var managed managedIntentError
	if errors.As(err, &managed) && validManagedDenialReason(string(managed)) {
		return managed
	}
	return managedIntentError("managed_intent_internal_failure")
}

func validManagedDenialReason(reason string) bool {
	if len(reason) < len("managed_intent_")+3 || len(reason) > 96 || !strings.HasPrefix(reason, "managed_intent_") {
		return false
	}
	for _, character := range reason {
		if (character < 'a' || character > 'z') && character != '_' {
			return false
		}
	}
	return true
}

func validManagedRef(prefix, value string) bool {
	if len(value) < len(prefix)+8 || len(value) > 96 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' {
			return false
		}
	}
	return true
}

func validManagedSafeLabel(value string) bool {
	if value == "" || len(value) > 120 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f ||
			(character >= 0x80 && character <= 0x9f) ||
			(unicode.IsSpace(character) && character != ' ') ||
			character == 0x061c ||
			(character >= 0x200b && character <= 0x200f) ||
			(character >= 0x202a && character <= 0x202e) ||
			(character >= 0x2060 && character <= 0x2069) ||
			character == 0xfeff {
			return false
		}
	}
	return true
}

func validManagedSourcePolicy(sources []string) bool {
	if len(sources) == 0 || len(sources) > 2 {
		return false
	}
	copyOfSources := append([]string(nil), sources...)
	sort.Strings(copyOfSources)
	for index, source := range copyOfSources {
		if (source != "generated" && source != "import") ||
			index > 0 && source == copyOfSources[index-1] ||
			source != sources[index] {
			return false
		}
	}
	return true
}

func containsManagedSource(sources []string, expected string) bool {
	for _, source := range sources {
		if source == expected {
			return true
		}
	}
	return false
}

func parseManagedOrigin(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("managed_origin_invalid")
	}
	hostname := parsed.Hostname()
	loopbackHTTP := parsed.Scheme == "http" &&
		(hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1")
	if parsed.Scheme != "https" && !loopbackHTTP {
		return nil, errors.New("managed_origin_invalid")
	}
	parsed.Path = ""
	return parsed, nil
}

func decodeStrictJSON(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func encodeManagedCanonicalJSON(value any) ([]byte, error) {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}), nil
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("file contract invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("file contract invalid")
	}
	return raw, nil
}

func readBoundedPrivateFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Size() <= 0 ||
		info.Size() > maximum ||
		runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private file contract invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("private file contract invalid")
	}
	return raw, nil
}

func randomManagedRef(prefix string) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(random), nil
}

func validateManagedReplayDocument(document managedReplayDocument) error {
	if document.Schema != managedReplayStoreSchema ||
		document.SchemaVersion != managedIntentContractVersion ||
		document.Intents == nil ||
		document.Nonces == nil ||
		len(document.Intents) > managedReplayMaximumEntries ||
		len(document.Nonces) > managedReplayMaximumEntries {
		return errors.New("managed_intent_replay_store_invalid")
	}
	for intentRef, record := range document.Intents {
		if !validManagedRef("intent_", intentRef) ||
			!validManagedRef("op_", record.OperationRef) ||
			record.ConsumedAtUnixSecond <= 0 ||
			record.ExpiresAtUnixSecond <= record.ConsumedAtUnixSecond {
			return errors.New("managed_intent_replay_store_invalid")
		}
	}
	for nonceRef, intentRef := range document.Nonces {
		if !validManagedRef("nonce_", nonceRef) {
			return errors.New("managed_intent_replay_store_invalid")
		}
		if _, exists := document.Intents[intentRef]; !exists {
			return errors.New("managed_intent_replay_store_invalid")
		}
	}
	return nil
}

func atomicWriteManagedJSON(path string, value any) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if int64(len(encoded)) > managedReplayMaxBytes {
		return errors.New("managed replay store exceeds its bounded contract")
	}
	temporary, err := os.CreateTemp(parent, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(parent)
	if err != nil {
		return managedAtomicWriteError{cause: err, finalFileReplaced: true}
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return managedAtomicWriteError{cause: err, finalFileReplaced: true}
	}
	return nil
}

type managedAtomicWriteError struct {
	cause             error
	finalFileReplaced bool
}

func (err managedAtomicWriteError) Error() string {
	return err.cause.Error()
}

func (err managedAtomicWriteError) Unwrap() error {
	return err.cause
}

func managedFinalFileReplaced(err error) bool {
	var writeError managedAtomicWriteError
	return errors.As(err, &writeError) && writeError.finalFileReplaced
}
