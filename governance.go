package main

import (
	"fmt"
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
	Operational      OperationalStatus  `json:"operational_status"`
	AssuranceSummary AssuranceSummary   `json:"assurance_summary"`
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

type AssuranceSummary struct {
	Verdict       string          `json:"verdict"`
	Summary       string          `json:"summary"`
	Proven        []AssuranceItem `json:"proven"`
	Review        []AssuranceItem `json:"review"`
	ValueReturned bool            `json:"value_returned"`
}

type AssuranceItem struct {
	Label  string `json:"label"`
	State  string `json:"state"`
	Detail string `json:"detail"`
	Tone   string `json:"tone"`
}

type OperationalStatus struct {
	Verdict       string                  `json:"verdict"`
	Summary       string                  `json:"summary"`
	Items         []OperationalStatusItem `json:"items"`
	ValueReturned bool                    `json:"value_returned"`
}

type OperationalStatusItem struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	State  string `json:"state"`
	Detail string `json:"detail"`
	Tone   string `json:"tone"`
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

func AssuranceSummaryFor(mode string, ready bool, openGateCount, catalogGateCount int, access AccessPosture, audit AuditPosture, boundary EvidenceBoundary) AssuranceSummary {
	summary := AssuranceSummary{
		Verdict:       "review_needed",
		Summary:       "Janus keeps proven controls visible and calls out review items without exposing values.",
		ValueReturned: false,
	}
	clearSelfHosted := ready && openGateCount == 0 && catalogGateCount == 0 && access.ExplicitBindings && audit.ChainVerified && boundary.Gate == "export_ready" && !boundary.ValueReturned
	if clearSelfHosted && mode == "enterprise" {
		summary.Verdict = "enterprise_review_needed"
		summary.Summary = "Self-hosted controls are present, but enterprise evidence still needs review."
	} else if clearSelfHosted {
		summary.Verdict = "self_hosted_ready"
		summary.Summary = "Self-hosted readiness is proven without claiming enterprise evidence."
	}

	summary.add(ready, "Readiness", "ready", "blocked", "Public readiness is redacted and dependency checks are healthy.", "Readiness is degraded; sensitive actions stay blocked.")
	summary.add(openGateCount+catalogGateCount == 0, "Open gates", "clear", "review", "No readiness or catalog gates are open.", "Readiness or catalog gates need review.")
	summary.add(!boundary.ValueReturned, "Value boundary", "withheld", "blocked", "Secret values, backend source paths, request bodies, and command output are excluded.", "Evidence must not return secret values.")
	summary.add(true, "Browser and API boundary", "hardened", "", "No-script CSP, security headers, request IDs, deny-by-default CORS, and safe errors are covered.", "")
	summary.add(access.ExplicitBindings, "Role gates", "explicit", "bootstrap", "Explicit admin, auditor, and operator bindings are configured.", "Bootstrap role policy is still a review item.")
	summary.add(audit.ChainVerified, "Audit evidence", "verified", "review", "Local tamper-evident audit chain verifies.", "Audit chain needs review before stronger claims.")
	summary.add(boundary.Gate == "export_ready", "Evidence export", "ready", "auditor_required", "Auditor evidence export has integrity metadata and a value-free boundary.", "Evidence export is role-gated from this session.")
	if mode == "enterprise" {
		summary.add(false, "Enterprise claim", "candidate", "blocked", "", "Enterprise evidence still requires external controls and review.")
	} else {
		summary.add(true, "Enterprise claim", "not_claimed", "", "Current mode does not claim enterprise evidence.", "")
	}
	return summary
}

func (s *AssuranceSummary) add(ok bool, label, okState, reviewState, okDetail, reviewDetail string) {
	if ok {
		s.Proven = append(s.Proven, AssuranceItem{Label: label, State: okState, Detail: okDetail, Tone: "ok"})
		return
	}
	s.Review = append(s.Review, AssuranceItem{Label: label, State: reviewState, Detail: reviewDetail, Tone: "warn"})
}

func OperationalStatusFor(ready bool, scope ScopePosture, assurance AssuranceSummary, boundary EvidenceBoundary, roles []RoleAvailability) OperationalStatus {
	status := OperationalStatus{
		Verdict:       "review",
		Summary:       "Janus is serving value-free posture; review items stay visible.",
		ValueReturned: false,
	}

	availableRoles := 0
	for _, role := range roles {
		if role.State == "available" {
			availableRoles++
		}
	}
	roleTotal := len(roles)
	roleClear := roleTotal > 0 && availableRoles == roleTotal
	scopeClear := scope.Strict && scope.GateCount == 0
	assuranceClear := len(assurance.Review) == 0 && !assurance.ValueReturned
	evidenceClear := boundary.Gate == "export_ready" && !boundary.ValueReturned
	valueClear := !boundary.ValueReturned

	if ready && scopeClear && assuranceClear && evidenceClear && roleClear && valueClear {
		status.Verdict = "operational"
		status.Summary = "Current session is ready, scoped, role-complete, and value-free."
	}

	status.add(ready, "readiness", "Readiness", "ready", "review", "Redacted public checks are healthy.", "Readiness needs review before sensitive actions.")
	status.add(assuranceClear, "assurance_verdict", "Assurance verdict", assurance.Verdict, assurance.Verdict, "No assurance review items are open.", fmt.Sprintf("%d assurance review items are visible.", len(assurance.Review)))
	status.add(evidenceClear, "evidence_export", "Evidence export", "export ready", boundary.Gate, "Auditor evidence export is available with integrity metadata.", "Evidence export is role-gated or waiting for integrity metadata.")

	roleState := fmt.Sprintf("%d of %d", availableRoles, roleTotal)
	roleTone := "warn"
	roleDetail := "Unavailable duties stay hidden or blocked for this session."
	if roleClear {
		roleTone = "ok"
		roleDetail = "Posture, use, audit export, and admin duties are available."
	}
	status.Items = append(status.Items, OperationalStatusItem{
		Key:    "role_duties",
		Label:  "Role duties",
		State:  roleState,
		Detail: roleDetail,
		Tone:   roleTone,
	})

	scopeDetail := "Strict scope allowlist is active."
	if len(scope.AllowedScopes) > 0 {
		scopeDetail = "Strict scope allowlist: " + strings.Join(scope.AllowedScopes, ", ") + "."
	}
	status.add(scopeClear, "scope_boundary", "Scope boundary", "strict", "review", scopeDetail, "Scope allowlist needs review.")
	status.add(valueClear, "value_boundary", "Value boundary", "withheld", "blocked", "Secret values, backend paths, request bodies, and command output stay out.", "Evidence must not return secret values.")
	return status
}

func (s *OperationalStatus) add(ok bool, key, label, okState, reviewState, okDetail, reviewDetail string) {
	if ok {
		s.Items = append(s.Items, OperationalStatusItem{Key: key, Label: label, State: okState, Detail: okDetail, Tone: "ok"})
		return
	}
	s.Items = append(s.Items, OperationalStatusItem{Key: key, Label: label, State: reviewState, Detail: reviewDetail, Tone: "warn"})
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
