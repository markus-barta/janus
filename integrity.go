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

func EvidenceIntegrityFor(pack EvidencePack) EvidenceIntegrity {
	unsigned := pack
	unsigned.Integrity = nil
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
