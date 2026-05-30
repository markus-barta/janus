package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type EvidenceIntegrity struct {
	Algorithm     string    `json:"algorithm"`
	PackHash      string    `json:"pack_hash"`
	AuditLastHash string    `json:"audit_last_hash,omitempty"`
	ChainVerified bool      `json:"chain_verified"`
	GeneratedAt   time.Time `json:"generated_at"`
	ValueReturned bool      `json:"value_returned"`
}

type EvidenceReceipt struct {
	State           string `json:"state"`
	Algorithm       string `json:"algorithm"`
	PackHash        string `json:"pack_hash,omitempty"`
	HashAvailable   bool   `json:"hash_available"`
	ChainVerified   bool   `json:"chain_verified"`
	HashHeader      string `json:"hash_header"`
	AlgorithmHeader string `json:"algorithm_header"`
	BodyField       string `json:"body_field"`
	Coverage        string `json:"coverage"`
	Verification    string `json:"verification"`
	Redaction       string `json:"redaction"`
	Audience        string `json:"audience"`
	ValueReturned   bool   `json:"value_returned"`
}

func EvidenceIntegrityFor(pack EvidencePack) EvidenceIntegrity {
	unsigned := pack
	unsigned.Integrity = nil
	unsigned.Receipt = nil
	raw, _ := json.Marshal(unsigned)
	sum := sha256.Sum256(raw)
	return EvidenceIntegrity{
		Algorithm:     "sha256-json-v1",
		PackHash:      hex.EncodeToString(sum[:]),
		AuditLastHash: pack.AuditPosture.LastHash,
		ChainVerified: pack.AuditPosture.ChainVerified,
		GeneratedAt:   pack.GeneratedAt,
		ValueReturned: false,
	}
}

func EvidenceReceiptFor(boundary EvidenceBoundary, integrity *EvidenceIntegrity) EvidenceReceipt {
	receipt := EvidenceReceipt{
		State:           "role_gated",
		Algorithm:       "sha256-json-v1",
		HashHeader:      "X-Janus-Evidence-Hash",
		AlgorithmHeader: "X-Janus-Evidence-Algorithm",
		BodyField:       "integrity.pack_hash",
		Coverage:        "evidence_json_without_integrity_or_receipt",
		Verification:    "Use an auditor session to download evidence and compare the header hash with integrity.pack_hash.",
		Redaction:       boundary.RedactionModel,
		Audience:        boundary.Audience,
		ValueReturned:   false,
	}
	if boundary.Gate == "export_ready" {
		receipt.State = "ready"
		receipt.Verification = "For the exact download, X-Janus-Evidence-Hash matches integrity.pack_hash."
	}
	if integrity != nil && integrity.PackHash != "" {
		receipt.PackHash = integrity.PackHash
		receipt.HashAvailable = true
		receipt.ChainVerified = integrity.ChainVerified
	}
	return receipt
}
