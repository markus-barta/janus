package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const externalEvidenceAttestation = "external_evidence_exists"

type EvidenceAttachmentRequest struct {
	ControlKey  string `json:"control_key"`
	Attestation string `json:"attestation,omitempty"`
}

type EvidenceAttachmentRecord struct {
	ControlKey          string    `json:"control_key"`
	Label               string    `json:"label"`
	OwnerRole           string    `json:"owner_role"`
	State               string    `json:"state"`
	Attachment          string    `json:"attachment"`
	EvidenceSignal      string    `json:"evidence_signal"`
	AttachedAt          time.Time `json:"attached_at"`
	ActorHash           string    `json:"actor_hash"`
	EvidenceRefReturned bool      `json:"evidence_ref_returned"`
	ValueReturned       bool      `json:"value_returned"`
}

type EvidenceAttachmentStore struct {
	mu      sync.RWMutex
	file    string
	records map[string]EvidenceAttachmentRecord
}

type evidenceAttachmentSnapshot struct {
	Version       int                        `json:"version"`
	Records       []EvidenceAttachmentRecord `json:"records"`
	ValueReturned bool                       `json:"value_returned"`
}

type ExternalEvidencePosture struct {
	Label               string                        `json:"label"`
	Summary             string                        `json:"summary"`
	Status              string                        `json:"status"`
	Persisted           bool                          `json:"persisted"`
	Required            int                           `json:"required"`
	Attached            int                           `json:"attached"`
	Missing             int                           `json:"missing"`
	ReviewCount         int                           `json:"review_count"`
	Items               []ExternalEvidencePostureItem `json:"items"`
	EvidenceRefReturned bool                          `json:"evidence_ref_returned"`
	ValueReturned       bool                          `json:"value_returned"`
}

type ExternalEvidencePostureItem struct {
	Key                 string `json:"key"`
	Label               string `json:"label"`
	OwnerRole           string `json:"owner_role"`
	State               string `json:"state"`
	Attachment          string `json:"attachment"`
	EvidenceSignal      string `json:"evidence_signal"`
	Next                string `json:"next"`
	Required            bool   `json:"required"`
	CanAttach           bool   `json:"can_attach"`
	Tone                string `json:"tone"`
	EvidenceRefReturned bool   `json:"evidence_ref_returned"`
	ValueReturned       bool   `json:"value_returned"`
}

func NewEvidenceAttachmentStore(dataDir string) (*EvidenceAttachmentStore, error) {
	store := &EvidenceAttachmentStore{records: make(map[string]EvidenceAttachmentRecord)}
	if strings.TrimSpace(dataDir) == "" {
		return store, nil
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	store.file = filepath.Join(dataDir, "enterprise-evidence.json")
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *EvidenceAttachmentStore) load() error {
	raw, err := os.ReadFile(s.file)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return nil
	}
	var snapshot evidenceAttachmentSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return err
	}
	for _, record := range snapshot.Records {
		if strings.TrimSpace(record.ControlKey) == "" {
			continue
		}
		record.State = "attached"
		record.Attachment = "attached_presence_only"
		record.EvidenceSignal = "presence_only_workflow"
		record.EvidenceRefReturned = false
		record.ValueReturned = false
		s.records[record.ControlKey] = record
	}
	return nil
}

func (s *EvidenceAttachmentStore) Put(record EvidenceAttachmentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record.ControlKey = strings.TrimSpace(record.ControlKey)
	record.State = "attached"
	record.Attachment = "attached_presence_only"
	record.EvidenceSignal = "presence_only_workflow"
	record.EvidenceRefReturned = false
	record.ValueReturned = false
	s.records[record.ControlKey] = record
	return s.persistLocked()
}

func (s *EvidenceAttachmentStore) Map() map[string]EvidenceAttachmentRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]EvidenceAttachmentRecord, len(s.records))
	for key, record := range s.records {
		record.EvidenceRefReturned = false
		record.ValueReturned = false
		out[key] = record
	}
	return out
}

func (s *EvidenceAttachmentStore) Posture(enterprise EnterpriseValidation, session Session) ExternalEvidencePosture {
	return ExternalEvidencePostureFor(enterprise, s.Map(), s.file != "", session)
}

func (s *EvidenceAttachmentStore) persistLocked() error {
	if s.file == "" {
		return nil
	}
	records := make([]EvidenceAttachmentRecord, 0, len(s.records))
	for _, record := range s.records {
		record.EvidenceRefReturned = false
		record.ValueReturned = false
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].AttachedAt.Equal(records[j].AttachedAt) {
			return records[i].ControlKey < records[j].ControlKey
		}
		return records[i].AttachedAt.After(records[j].AttachedAt)
	})
	raw, err := json.MarshalIndent(evidenceAttachmentSnapshot{
		Version:       1,
		Records:       records,
		ValueReturned: false,
	}, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := s.file + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.file); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func NewEvidenceAttachmentRecord(spec enterpriseValidationSpec, subject string) EvidenceAttachmentRecord {
	return EvidenceAttachmentRecord{
		ControlKey:          spec.Key,
		Label:               spec.Label,
		OwnerRole:           spec.OwnerRole,
		State:               "attached",
		Attachment:          "attached_presence_only",
		EvidenceSignal:      "presence_only_workflow",
		AttachedAt:          time.Now().UTC(),
		ActorHash:           actorHash(subject),
		EvidenceRefReturned: false,
		ValueReturned:       false,
	}
}

func ExternalEvidencePostureFor(enterprise EnterpriseValidation, records map[string]EvidenceAttachmentRecord, persisted bool, session Session) ExternalEvidencePosture {
	posture := ExternalEvidencePosture{
		Label:               "External evidence workflow",
		Summary:             "External evidence workflow records presence only; files, URLs, refs, notes, and values stay outside Janus.",
		Status:              "review",
		Persisted:           persisted,
		EvidenceRefReturned: false,
		ValueReturned:       false,
	}
	for _, control := range enterprise.Controls {
		if !strings.HasPrefix(control.EvidenceSignal, "presence_only") {
			continue
		}
		item := ExternalEvidencePostureItem{
			Key:                 control.Key,
			Label:               control.Label,
			OwnerRole:           control.OwnerRole,
			State:               control.State,
			Attachment:          control.Attachment,
			EvidenceSignal:      control.EvidenceSignal,
			Next:                control.Next,
			Required:            control.Required,
			CanAttach:           HasRole(session, control.OwnerRole),
			Tone:                control.Tone,
			EvidenceRefReturned: false,
			ValueReturned:       false,
		}
		if item.State == "" {
			item.State = "not_claimed"
		}
		if item.Attachment == "" {
			item.Attachment = "not_claimed"
		}
		if item.Tone == "" {
			item.Tone = "info"
		}
		if _, ok := records[control.Key]; ok {
			item.State = "attached"
			item.Attachment = "attached_presence_only"
			item.EvidenceSignal = "presence_only_workflow"
			item.Next = "Keep the external evidence reviewed outside Janus; only presence is recorded here."
			item.Tone = "ok"
		}
		if item.Required {
			posture.Required++
		}
		switch item.Attachment {
		case "attached_presence_only":
			posture.Attached++
		case "missing":
			posture.Missing++
			posture.ReviewCount++
		default:
			posture.ReviewCount++
		}
		posture.Items = append(posture.Items, item)
	}
	if posture.Missing > 0 {
		posture.Status = "blocked"
		posture.Summary = "External evidence workflow is blocked by missing presence attestations."
	} else if posture.Attached > 0 && posture.ReviewCount == 0 {
		posture.Status = "candidate"
		posture.Summary = "External evidence presence is attached; keep actual evidence reviewed outside Janus."
	} else if posture.Attached > 0 {
		posture.Status = "partial"
		posture.Summary = "Some external evidence presence is attached; remaining review items stay visible."
	}
	return posture
}
