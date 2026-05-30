package main

import (
	"strings"
	"time"
)

type CatalogGate struct {
	SecretRef string `json:"secret_ref"`
	Severity  string `json:"severity"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}

type ApprovedUsePosture struct {
	Profile             string `json:"profile"`
	Enforced            bool   `json:"enforced"`
	DescriptorCount     int    `json:"descriptor_count"`
	ProfiledCount       int    `json:"profiled_count"`
	BlockedCount        int    `json:"blocked_count"`
	SecretValuesAllowed bool   `json:"secret_values_allowed"`
	ValueReturned       bool   `json:"value_returned"`
}

type EvidencePack struct {
	GeneratedAt      time.Time          `json:"generated_at"`
	Service          string             `json:"service"`
	Mode             string             `json:"mode"`
	Posture          map[string]any     `json:"posture"`
	EvidenceBoundary EvidenceBoundary   `json:"evidence_boundary"`
	Descriptors      []SecretDescriptor `json:"descriptors"`
	CatalogGates     []CatalogGate      `json:"catalog_gates"`
	ScopePosture     ScopePosture       `json:"scope_posture"`
	LifecyclePosture LifecyclePosture   `json:"lifecycle_posture"`
	PermitPosture    PermitPosture      `json:"permit_posture"`
	AccessPosture    AccessPosture      `json:"access_posture"`
	AuditPosture     AuditPosture       `json:"audit_posture"`
	RecentAudit      []AuditEntry       `json:"recent_audit"`
	Integrity        *EvidenceIntegrity `json:"integrity,omitempty"`
	ValueReturned    bool               `json:"value_returned"`
	RedactionModel   string             `json:"redaction_model"`
}

type EvidenceBoundary struct {
	Audience       string   `json:"audience"`
	Gate           string   `json:"gate"`
	Integrity      string   `json:"integrity"`
	HashAvailable  bool     `json:"hash_available"`
	Includes       []string `json:"includes"`
	Excludes       []string `json:"excludes"`
	RedactionModel string   `json:"redaction_model"`
	ValueReturned  bool     `json:"value_returned"`
}

func EvidenceBoundaryFor(canExport, hashAvailable bool) EvidenceBoundary {
	gate := "auditor_required"
	if canExport {
		gate = "export_ready"
	}
	return EvidenceBoundary{
		Audience:      "auditor",
		Gate:          gate,
		Integrity:     "sha256-json-v1",
		HashAvailable: hashAvailable,
		Includes: []string{
			"posture",
			"descriptor_metadata",
			"catalog_gates",
			"scope_posture",
			"lifecycle_posture",
			"permit_posture",
			"audit_posture",
			"recent_audit_refs",
			"integrity_hash",
		},
		Excludes: []string{
			"secret_values",
			"request_bodies",
			"prompt_text",
			"command_output",
			"env_dumps",
			"backend_source_paths",
			"cookie_secrets",
		},
		RedactionModel: "metadata_only",
		ValueReturned:  false,
	}
}

func ApprovedUsePostureFor(descriptors []SecretDescriptor) ApprovedUsePosture {
	posture := ApprovedUsePosture{
		Profile:             "metadata_only",
		Enforced:            true,
		DescriptorCount:     len(descriptors),
		SecretValuesAllowed: false,
		ValueReturned:       false,
	}
	for _, desc := range descriptors {
		if desc.UseEnabled {
			posture.ProfiledCount++
		} else {
			posture.BlockedCount++
		}
	}
	return posture
}

func ValidateCatalog(descriptors []SecretDescriptor) []CatalogGate {
	var gates []CatalogGate
	for _, desc := range descriptors {
		ref := desc.ID
		if strings.TrimSpace(ref) == "" {
			ref = "unknown"
			gates = append(gates, CatalogGate{
				SecretRef: ref,
				Severity:  "high",
				Code:      "missing_id",
				Message:   "Descriptor is missing a stable id.",
			})
		}
		if strings.TrimSpace(desc.Owner) == "" {
			gates = append(gates, CatalogGate{
				SecretRef: ref,
				Severity:  "high",
				Code:      "missing_owner",
				Message:   "Secret needs an accountable owner.",
			})
		}
		if strings.TrimSpace(desc.Classification) == "" || desc.Classification == "internal" {
			gates = append(gates, CatalogGate{
				SecretRef: ref,
				Severity:  "medium",
				Code:      "weak_classification",
				Message:   "Secret needs an explicit risk class before enterprise use.",
			})
		}
		if strings.TrimSpace(desc.Scope) == "" {
			gates = append(gates, CatalogGate{
				SecretRef: ref,
				Severity:  "high",
				Code:      "missing_scope",
				Message:   "Secret needs org/project/host/environment scope.",
			})
		}
		if strings.TrimSpace(desc.Source) == "" {
			gates = append(gates, CatalogGate{
				SecretRef: ref,
				Severity:  "medium",
				Code:      "missing_source",
				Message:   "Secret needs a value-free custody/source pointer.",
			})
		}
		if desc.ConsumerCount == 0 {
			gates = append(gates, CatalogGate{
				SecretRef: ref,
				Severity:  "medium",
				Code:      "missing_consumers",
				Message:   "Secret has no declared consumers; one-click rotation stays blocked.",
			})
		}
		if !desc.UseEnabled {
			gates = append(gates, CatalogGate{
				SecretRef: ref,
				Severity:  "medium",
				Code:      "no_approved_use_profile",
				Message:   "Secret has no approved use profile; agent/use execution stays blocked.",
			})
		}
		if desc.UseEnabled && isHighValue(desc) && (desc.EgressMode == "" || desc.EgressMode == "declared-only" || desc.EgressMode == "hook-guarded") {
			gates = append(gates, CatalogGate{
				SecretRef: ref,
				Severity:  "high",
				Code:      "weak_egress",
				Message:   "High-value secret needs connector/proxy/sandbox egress enforcement.",
			})
		}
	}
	return gates
}

func isHighValue(desc SecretDescriptor) bool {
	class := strings.ToLower(strings.TrimSpace(desc.Classification))
	return class == "high" || class == "critical"
}
