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
