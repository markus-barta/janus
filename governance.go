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
	GeneratedAt      time.Time             `json:"generated_at"`
	Service          string                `json:"service"`
	Mode             string                `json:"mode"`
	Posture          map[string]any        `json:"posture"`
	Operational      OperationalStatus     `json:"operational_status"`
	AssuranceGates   AssuranceGates        `json:"assurance_gates"`
	NegativePath     NegativePathAssurance `json:"negative_path_assurance"`
	Guidance         DegradedGuidance      `json:"degraded_guidance"`
	AssuranceSummary AssuranceSummary      `json:"assurance_summary"`
	Enterprise       EnterpriseValidation  `json:"enterprise_validation"`
	Privacy          PrivacyPosture        `json:"privacy_posture"`
	EvidenceBoundary EvidenceBoundary      `json:"evidence_boundary"`
	Descriptors      []SecretDescriptor    `json:"descriptors"`
	CatalogGates     []CatalogGate         `json:"catalog_gates"`
	ScopePosture     ScopePosture          `json:"scope_posture"`
	LifecyclePosture LifecyclePosture      `json:"lifecycle_posture"`
	PermitPosture    PermitPosture         `json:"permit_posture"`
	AccessPosture    AccessPosture         `json:"access_posture"`
	AuditPosture     AuditPosture          `json:"audit_posture"`
	RecentAudit      []AuditEntry          `json:"recent_audit"`
	Integrity        *EvidenceIntegrity    `json:"integrity,omitempty"`
	ValueReturned    bool                  `json:"value_returned"`
	RedactionModel   string                `json:"redaction_model"`
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

type AssuranceGates struct {
	Summary       string              `json:"summary"`
	Gates         []AssuranceGateItem `json:"gates"`
	ReviewCount   int                 `json:"review_count"`
	ValueReturned bool                `json:"value_returned"`
}

type AssuranceGateItem struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	State  string `json:"state"`
	Detail string `json:"detail"`
	Tone   string `json:"tone"`
}

type NegativePathAssurance struct {
	Summary       string             `json:"summary"`
	Cases         []NegativePathCase `json:"cases"`
	CoveredCount  int                `json:"covered_count"`
	ReviewCount   int                `json:"review_count"`
	ValueReturned bool               `json:"value_returned"`
}

type NegativePathCase struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	State  string `json:"state"`
	Detail string `json:"detail"`
	Tone   string `json:"tone"`
}

type DegradedGuidance struct {
	Summary       string                 `json:"summary"`
	Items         []DegradedGuidanceItem `json:"items"`
	BlockedCount  int                    `json:"blocked_count"`
	ReviewCount   int                    `json:"review_count"`
	ValueReturned bool                   `json:"value_returned"`
}

type DegradedGuidanceItem struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	State  string `json:"state"`
	Impact string `json:"impact"`
	Action string `json:"action"`
	Role   string `json:"role"`
	Tone   string `json:"tone"`
}

type EnterpriseValidation struct {
	Mode          string                        `json:"mode"`
	Status        string                        `json:"status"`
	Summary       string                        `json:"summary"`
	MissingCount  int                           `json:"missing_count"`
	Controls      []EnterpriseValidationControl `json:"controls"`
	ValueReturned bool                          `json:"value_returned"`
}

type EnterpriseValidationControl struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	State    string `json:"state"`
	Required bool   `json:"required"`
	Detail   string `json:"detail"`
	Tone     string `json:"tone"`
}

type PrivacyPosture struct {
	Summary       string           `json:"summary"`
	Redaction     string           `json:"redaction"`
	Retention     string           `json:"retention"`
	Surfaces      []PrivacySurface `json:"surfaces"`
	Excluded      []string         `json:"excluded"`
	ReviewCount   int              `json:"review_count"`
	ValueReturned bool             `json:"value_returned"`
}

type PrivacySurface struct {
	Key       string `json:"key"`
	Label     string `json:"label"`
	State     string `json:"state"`
	Retention string `json:"retention"`
	Detail    string `json:"detail"`
	Tone      string `json:"tone"`
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

func AssuranceGatesFor(ready bool, catalogGateCount int, access AccessPosture) AssuranceGates {
	gates := AssuranceGates{
		Summary:       "Abuse gates are enforced by tests and surfaced here without secret values.",
		ValueReturned: false,
	}

	roleReady := access.RoleDutyMatrix && len(access.RequiredRoles) > 0
	gates.add(roleReady, "role_denial", "Role denial", "enforced", "review", "Viewer requests to operator and auditor routes are denied and audited.", "Role boundary tests need review.")

	catalogClear := catalogGateCount == 0
	catalogState := "clear"
	catalogDetail := "Catalog metadata has owners, classes, scope, consumers, and approved-use profiles."
	if !catalogClear {
		catalogState = fmt.Sprintf("%d open", catalogGateCount)
		catalogDetail = "Malformed or incomplete catalog metadata stays visible before stronger claims."
	}
	gates.add(catalogClear, "catalog_metadata", "Catalog metadata", catalogState, catalogState, catalogDetail, catalogDetail)

	degradedState := "armed"
	degradedDetail := "Sensitive actions are guarded by readiness checks."
	if !ready {
		degradedState = "blocking"
		degradedDetail = "Readiness is degraded; sensitive actions are blocked."
	}
	gates.add(true, "degraded_actions", "Degraded actions", degradedState, degradedState, degradedDetail, degradedDetail)

	gates.add(true, "value_leak_sentinel", "Value leak sentinel", "active", "review", "Public, API, and UI routes are checked for value-free responses.", "Route value-leak sentinel needs review.")
	return gates
}

func (g *AssuranceGates) add(ok bool, key, label, okState, reviewState, okDetail, reviewDetail string) {
	tone := "ok"
	state := okState
	detail := okDetail
	if !ok {
		tone = "warn"
		state = reviewState
		detail = reviewDetail
		g.ReviewCount++
	}
	g.Gates = append(g.Gates, AssuranceGateItem{Key: key, Label: label, State: state, Detail: detail, Tone: tone})
}

func NegativePathAssuranceFor(ready bool, catalogGateCount int, access AccessPosture, audit AuditPosture) NegativePathAssurance {
	proof := NegativePathAssurance{
		Summary:       "Janus proves common bad paths fail closed before stronger claims are trusted.",
		ValueReturned: false,
	}

	roleReady := access.RoleDutyMatrix && len(access.RequiredRoles) > 0
	proof.add(roleReady, "role_denial", "Wrong role", "covered", "review", "Viewer sessions are denied from auditor and operator routes, with denial audit when the sink is healthy.", "Role denial coverage needs review.")

	catalogClear := catalogGateCount == 0
	catalogState := "covered"
	catalogDetail := "Malformed descriptor metadata opens catalog gates before use or enterprise claims."
	if !catalogClear {
		catalogState = fmt.Sprintf("%d open", catalogGateCount)
		catalogDetail = "Open catalog gates stay visible and block stronger claims."
	}
	proof.add(catalogClear, "catalog_gate", "Catalog gate", catalogState, catalogState, catalogDetail, catalogDetail)

	auditReady := audit.SinkWritable && audit.ChainVerified
	auditState := "armed"
	auditDetail := "Audit sink and chain are healthy; a degraded sink makes readiness fail."
	if !auditReady {
		auditState = "blocking"
		auditDetail = "Audit sink or chain is degraded; sensitive actions stay blocked."
	}
	proof.add(auditReady, "audit_sink_degraded", "Audit down", auditState, auditState, auditDetail, auditDetail)

	sensitiveState := "armed"
	sensitiveDetail := "Sensitive API and UI actions check readiness before broker or permit work."
	if !ready {
		sensitiveState = "blocking"
		sensitiveDetail = "Readiness is degraded; sensitive actions return safe denial responses."
	}
	proof.add(true, "sensitive_action_guard", "Sensitive action", sensitiveState, sensitiveState, sensitiveDetail, sensitiveDetail)

	proof.add(true, "value_leak_sentinel", "Value leak check", "active", "review", "Denials and evidence exclude request bodies, secret-like literals, backend paths, and cookie/OIDC secrets.", "Value-leak sentinel needs review.")
	proof.add(true, "request_correlation", "Request id", "active", "review", "JSON denials include a request id so operators can investigate without exposing values.", "Request correlation needs review.")
	return proof
}

func (p *NegativePathAssurance) add(ok bool, key, label, okState, reviewState, okDetail, reviewDetail string) {
	tone := "ok"
	state := okState
	detail := okDetail
	if !ok {
		tone = "warn"
		state = reviewState
		detail = reviewDetail
		p.ReviewCount++
	} else {
		p.CoveredCount++
	}
	p.Cases = append(p.Cases, NegativePathCase{Key: key, Label: label, State: state, Detail: detail, Tone: tone})
}

func DegradedGuidanceFor(ready bool, audit AuditPosture, boundary EvidenceBoundary, enterprise EnterpriseValidation) DegradedGuidance {
	guidance := DegradedGuidance{
		Summary:       "Janus names blocked states and the next safe action without exposing sensitive data.",
		ValueReturned: false,
	}

	readinessState := "ready"
	readinessTone := "ok"
	readinessImpact := "Sensitive actions may continue through the normal role gates."
	readinessAction := "Keep monitoring posture and evidence."
	if !ready {
		readinessState = "blocked"
		readinessTone = "warn"
		readinessImpact = "Sensitive actions are stopped until readiness recovers."
		readinessAction = "Restore the failed readiness check before retrying."
		guidance.BlockedCount++
	}
	guidance.add(DegradedGuidanceItem{
		Key:    "readiness",
		Label:  "Readiness",
		State:  readinessState,
		Impact: readinessImpact,
		Action: readinessAction,
		Role:   "operator",
		Tone:   readinessTone,
	})

	auditState := "ready"
	auditTone := "ok"
	auditImpact := "Audit events can be written and the local chain verifies."
	auditAction := "Keep audit storage writable and included in backup."
	if !audit.SinkWritable || !audit.ChainVerified {
		auditState = "blocked"
		auditTone = "warn"
		auditImpact = "Required-audit actions stay blocked while audit evidence is unsafe."
		auditAction = "Recover audit storage, then confirm the chain verifies."
		guidance.BlockedCount++
	}
	guidance.add(DegradedGuidanceItem{
		Key:    "audit_sink",
		Label:  "Audit storage",
		State:  auditState,
		Impact: auditImpact,
		Action: auditAction,
		Role:   "operator",
		Tone:   auditTone,
	})

	evidenceState := "available"
	evidenceTone := "ok"
	evidenceImpact := "Evidence export is available with integrity metadata."
	evidenceAction := "Download evidence from an auditor session when needed."
	if boundary.Gate != "export_ready" {
		evidenceState = "role gated"
		evidenceTone = "warn"
		evidenceImpact = "Evidence JSON is hidden from this session."
		evidenceAction = "Use an auditor session to download evidence."
		guidance.ReviewCount++
	}
	guidance.add(DegradedGuidanceItem{
		Key:    "evidence_export",
		Label:  "Evidence export",
		State:  evidenceState,
		Impact: evidenceImpact,
		Action: evidenceAction,
		Role:   boundary.Audience,
		Tone:   evidenceTone,
	})

	enterpriseState := enterprise.Status
	if enterpriseState == "" {
		enterpriseState = "not_claimed"
	}
	enterpriseTone := "info"
	enterpriseImpact := "Current mode does not claim enterprise readiness."
	enterpriseAction := "Keep self-hosted evidence clear before making enterprise claims."
	if enterpriseState == "candidate" {
		enterpriseTone = "ok"
		enterpriseImpact = "Enterprise controls are attached for review."
		enterpriseAction = "Keep external review evidence with the release."
	} else if enterpriseState == "blocked" {
		enterpriseTone = "warn"
		enterpriseImpact = fmt.Sprintf("%d enterprise controls need evidence.", enterprise.MissingCount)
		enterpriseAction = "Attach external evidence before claiming enterprise readiness."
		guidance.BlockedCount++
		guidance.ReviewCount++
	}
	guidance.add(DegradedGuidanceItem{
		Key:    "enterprise_controls",
		Label:  "Enterprise controls",
		State:  enterpriseState,
		Impact: enterpriseImpact,
		Action: enterpriseAction,
		Role:   "admin",
		Tone:   enterpriseTone,
	})

	return guidance
}

func (g *DegradedGuidance) add(item DegradedGuidanceItem) {
	g.Items = append(g.Items, item)
}

func PrivacyPostureFor(boundary EvidenceBoundary, audit AuditPosture) PrivacyPosture {
	posture := PrivacyPosture{
		Summary:       "Janus keeps evidence useful by recording metadata and excluding secret-bearing payloads.",
		Redaction:     "metadata_only",
		Retention:     "local_evidence_until_operator_cleanup",
		ValueReturned: false,
		Excluded:      append([]string{}, boundary.Excludes...),
	}
	if len(posture.Excluded) == 0 {
		posture.Excluded = []string{
			"secret_values",
			"request_bodies",
			"prompt_text",
			"command_output",
			"env_dumps",
			"backend_source_paths",
			"cookie_secrets",
		}
	}

	auditState := "metadata only"
	auditTone := "ok"
	auditDetail := "Audit stores action, actor, scope, request id, severity, and hashes; values stay out."
	if !audit.SinkWritable || !audit.ChainVerified {
		auditState = "review"
		auditTone = "warn"
		auditDetail = "Audit sink or chain needs review before stronger privacy claims."
		posture.ReviewCount++
	}
	posture.Surfaces = append(posture.Surfaces, PrivacySurface{
		Key:       "audit_events",
		Label:     "Audit events",
		State:     auditState,
		Retention: "local durable log",
		Detail:    auditDetail,
		Tone:      auditTone,
	})

	exportState := "redacted"
	exportTone := "ok"
	exportDetail := "Evidence export includes posture, metadata, gates, audit refs, and integrity hashes."
	if boundary.Gate != "export_ready" {
		exportState = "role gated"
		exportTone = "warn"
		exportDetail = "Evidence export is restricted to auditor sessions."
		posture.ReviewCount++
	}
	posture.Surfaces = append(posture.Surfaces,
		PrivacySurface{Key: "evidence_export", Label: "Evidence export", State: exportState, Retention: "downloaded by auditor", Detail: exportDetail, Tone: exportTone},
		PrivacySurface{Key: "request_bodies", Label: "Request bodies", State: "excluded", Retention: "not retained", Detail: "Mutation bodies are parsed for the action and are not stored in audit or evidence.", Tone: "ok"},
		PrivacySurface{Key: "prompt_command_env", Label: "Prompts, command output, env dumps", State: "excluded", Retention: "not retained", Detail: "Prompt text, model output, command output, and environment dumps are outside Janus evidence.", Tone: "ok"},
		PrivacySurface{Key: "raw_metadata", Label: "Raw metadata", State: "role gated", Retention: "review before broader views", Detail: "Default views use safe labels and descriptors; broader raw metadata remains a deliberate admin/auditor path.", Tone: "warn"},
		PrivacySurface{Key: "auth_cookie_secrets", Label: "Auth and cookie secrets", State: "excluded", Retention: "not exported", Detail: "OIDC client secrets, cookie keys, nonces, and PKCE verifiers are never returned in evidence.", Tone: "ok"},
	)
	posture.ReviewCount++
	return posture
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
