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

const (
	actionReceiptSchema       = "janus-action-receipt-v1"
	actionReceiptAlgorithm    = "sha256-json-v1"
	actionReceiptCoverage     = "schema, action, outcome, request_id, checks, boundary, next, value flags"
	actionReceiptVerification = "Recompute the SHA-256 hash over the covered fields; receipt_id is ar_<first 16 hash chars>."
)

type actionReceiptProofPayload struct {
	Schema              string `json:"schema"`
	Algorithm           string `json:"algorithm"`
	Action              string `json:"action"`
	Outcome             string `json:"outcome"`
	RequestID           string `json:"request_id"`
	RoleChecked         bool   `json:"role_checked"`
	CSRFChecked         bool   `json:"csrf_checked"`
	ReadinessChecked    bool   `json:"readiness_checked"`
	AuditRecorded       bool   `json:"audit_recorded"`
	Boundary            string `json:"boundary"`
	Coverage            string `json:"coverage"`
	TamperEvident       bool   `json:"tamper_evident"`
	Next                string `json:"next"`
	SecretValueReturned bool   `json:"secret_value_returned"`
	RequestBodyReturned bool   `json:"request_body_returned"`
	ValueReturned       bool   `json:"value_returned"`
}

func ActionReceiptIntegrityFor(receipt ActionReceipt) ActionReceipt {
	receipt.Schema = actionReceiptSchema
	receipt.Algorithm = actionReceiptAlgorithm
	receipt.Coverage = actionReceiptCoverage
	receipt.Verification = actionReceiptVerification
	receipt.TamperEvident = true

	payload := actionReceiptProofPayload{
		Schema:              receipt.Schema,
		Algorithm:           receipt.Algorithm,
		Action:              receipt.Action,
		Outcome:             receipt.Outcome,
		RequestID:           receipt.RequestID,
		RoleChecked:         receipt.RoleChecked,
		CSRFChecked:         receipt.CSRFChecked,
		ReadinessChecked:    receipt.ReadinessChecked,
		AuditRecorded:       receipt.AuditRecorded,
		Boundary:            receipt.Boundary,
		Coverage:            receipt.Coverage,
		TamperEvident:       receipt.TamperEvident,
		Next:                receipt.Next,
		SecretValueReturned: receipt.SecretValueReturned,
		RequestBodyReturned: receipt.RequestBodyReturned,
		ValueReturned:       receipt.ValueReturned,
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	receipt.ReceiptHash = hex.EncodeToString(sum[:])
	receipt.ReceiptID = "ar_" + receipt.ReceiptHash[:16]
	return receipt
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
