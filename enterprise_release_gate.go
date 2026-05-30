package main

import (
	"fmt"
	"strings"
)

type EnterpriseReleaseGate struct {
	Label                 string                      `json:"label"`
	Summary               string                      `json:"summary"`
	Status                string                      `json:"status"`
	Verdict               string                      `json:"verdict"`
	Claim                 string                      `json:"claim"`
	CurrentMode           string                      `json:"current_mode"`
	TargetMode            string                      `json:"target_mode"`
	Required              int                         `json:"required"`
	Passed                int                         `json:"passed"`
	Blocked               int                         `json:"blocked"`
	ReviewCount           int                         `json:"review_count"`
	EvidenceSignal        string                      `json:"evidence_signal"`
	EvidenceGate          string                      `json:"evidence_gate"`
	ReleaseCadence        string                      `json:"release_cadence"`
	Next                  string                      `json:"next"`
	Checks                []EnterpriseReleaseGateItem `json:"checks"`
	EvidenceRefReturned   bool                        `json:"evidence_ref_returned"`
	ProcedureReturned     bool                        `json:"procedure_returned"`
	TicketURLReturned     bool                        `json:"ticket_url_returned"`
	BackendPathReturned   bool                        `json:"backend_path_returned"`
	RequestBodyReturned   bool                        `json:"request_body_returned"`
	EnvReturned           bool                        `json:"env_returned"`
	ScannerOutputReturned bool                        `json:"scanner_output_returned"`
	ArtifactReturned      bool                        `json:"artifact_returned"`
	PayloadReturned       bool                        `json:"payload_returned"`
	ValueReturned         bool                        `json:"value_returned"`
}

type EnterpriseReleaseGateItem struct {
	Key                 string `json:"key"`
	Label               string `json:"label"`
	State               string `json:"state"`
	Required            bool   `json:"required"`
	OwnerRole           string `json:"owner_role"`
	EvidenceSignal      string `json:"evidence_signal"`
	Detail              string `json:"detail"`
	Next                string `json:"next"`
	Tone                string `json:"tone"`
	EvidenceRefReturned bool   `json:"evidence_ref_returned"`
	ValueReturned       bool   `json:"value_returned"`
}

func EnterpriseReleaseGateFor(currentMode string, claim EnterpriseClaimReview, supplyChain SupplyChainPosture, remoteAudit RemoteAuditWorkflow, restore RestoreDrillWorkflow, release ReleaseProvenanceWorkflow, privacy PrivacyRetentionWorkflow, integration IntegrationConformanceWorkflow, breakGlass BreakGlassReviewWorkflow, audit AuditPosture, access AccessPosture, rolePolicy RolePolicy, boundary EvidenceBoundary) EnterpriseReleaseGate {
	currentMode = strings.TrimSpace(currentMode)
	if currentMode == "" {
		currentMode = "self_hosted"
	}
	targetMode := defaultString(claim.TargetMode, "enterprise")
	releaseClaim := defaultString(claim.Claim, "self_hosted_not_enterprise")
	if currentMode != "enterprise" {
		releaseClaim = "self_hosted_not_enterprise"
	}

	gate := EnterpriseReleaseGate{
		Label:                 "Enterprise release gate",
		Status:                "blocked",
		Verdict:               "enterprise_blocked",
		Claim:                 releaseClaim,
		CurrentMode:           currentMode,
		TargetMode:            targetMode,
		EvidenceSignal:        "presence_only_enterprise_release_gate",
		EvidenceGate:          boundary.Gate,
		ReleaseCadence:        "before enterprise mode, before each release, and after identity, audit, recovery, integration, privacy, dependency, or break-glass changes",
		Next:                  "Resolve blocked gates before enterprise mode or release promotion.",
		EvidenceRefReturned:   false,
		ProcedureReturned:     false,
		TicketURLReturned:     false,
		BackendPathReturned:   false,
		RequestBodyReturned:   false,
		EnvReturned:           false,
		ScannerOutputReturned: false,
		ArtifactReturned:      false,
		PayloadReturned:       false,
		ValueReturned:         false,
	}

	claimOK := currentMode == "enterprise" && claim.Status == "candidate" && claim.Claim == "enterprise_candidate" && !claim.ValueReturned
	claimState := claim.Status
	claimDetail := "Enterprise claim must be explicit and candidate before the release gate can pass."
	claimNext := claim.Next
	if currentMode != "enterprise" {
		claimState = "not_claimed"
		claimDetail = "Current deployment is self-hosted; the release gate cannot claim enterprise mode."
		claimNext = "Review external evidence, then switch mode explicitly before claiming enterprise."
	}
	gate.add(claimOK, "enterprise_claim", "Enterprise claim", claimState, claimDetail, claimNext, RoleAdmin, claim.EvidenceSignal)

	supplyOK := supplyChain.Status == "clean" && supplyChain.OpenAlerts == 0 && !supplyChain.ScannerOutputReturned && !supplyChain.PackageLockReturned && !supplyChain.BackendPathReturned && !supplyChain.EnvReturned && !supplyChain.EvidenceRefReturned && !supplyChain.ValueReturned
	gate.add(supplyOK, "supply_chain", "Supply chain", supplyChain.Status, "Dependency, builder, module, and vulnerability posture must be clean for this release.", supplyChain.Next, RoleOperator, supplyChain.EvidenceSignal)

	gate.add(remoteAudit.Attached && !remoteAudit.Missing && !remoteAudit.ValueReturned && !remoteAudit.EndpointReturned && !remoteAudit.PayloadReturned && !remoteAudit.AuditTokenReturned && !remoteAudit.EvidenceRefReturned, "remote_audit", remoteAudit.Label, workflowState(remoteAudit.Attached, remoteAudit.Missing, remoteAudit.Status), remoteAudit.Summary, remoteAudit.Next, remoteAudit.OwnerRole, remoteAudit.EvidenceSignal)
	gate.add(restore.Attached && !restore.Missing && !restore.ValueReturned && !restore.EvidenceRefReturned, "restore_drill", restore.Label, workflowState(restore.Attached, restore.Missing, restore.Status), restore.Summary, restore.Next, restore.OwnerRole, restore.EvidenceSignal)
	gate.add(release.Attached && !release.Missing && !release.ValueReturned && !release.ArtifactReturned && !release.EvidenceRefReturned, "release_provenance", release.Label, workflowState(release.Attached, release.Missing, release.Status), release.Summary, release.Next, release.OwnerRole, release.EvidenceSignal)
	gate.add(privacy.Attached && !privacy.Missing && !privacy.ValueReturned && !privacy.PolicyDocReturned && !privacy.RawMetadataReturned && !privacy.EvidenceRefReturned, "privacy_retention", privacy.Label, workflowState(privacy.Attached, privacy.Missing, privacy.Status), privacy.Summary, privacy.Next, privacy.OwnerRole, privacy.EvidenceSignal)
	gate.add(integration.Attached && !integration.Missing && !integration.ValueReturned && !integration.ConnectorConfigReturned && !integration.EndpointReturned && !integration.PayloadReturned && !integration.EvidenceRefReturned, "integration_conformance", integration.Label, workflowState(integration.Attached, integration.Missing, integration.Status), integration.Summary, integration.Next, integration.OwnerRole, integration.EvidenceSignal)
	gate.add(breakGlass.Attached && !breakGlass.Missing && !breakGlass.ValueReturned && !breakGlass.ProcedureReturned && !breakGlass.ContactPathReturned && !breakGlass.AccessTargetReturned && !breakGlass.CredentialReturned && !breakGlass.EvidenceRefReturned, "break_glass_review", breakGlass.Label, workflowState(breakGlass.Attached, breakGlass.Missing, breakGlass.Status), breakGlass.Summary, breakGlass.Next, breakGlass.OwnerRole, breakGlass.EvidenceSignal)

	auditOK := audit.ChainVerified && audit.SinkWritable
	auditState := "verified"
	auditDetail := "Local audit chain and sink must be healthy before enterprise release promotion."
	auditNext := "Keep audit chain verification and sink writes healthy."
	if !auditOK {
		auditState = "blocked"
		auditNext = "Repair audit chain or sink before relying on enterprise release evidence."
	}
	gate.add(auditOK, "audit_health", "Audit health", auditState, auditDetail, auditNext, RoleAuditor, "local_audit_posture")

	roleOK := access.ExplicitBindings && rolePolicyReleaseReady(rolePolicy) && !access.BootstrapOwner && !access.ValueReturned
	roleState := "explicit"
	roleDetail := "Enterprise release requires explicit admin, auditor, and operator binding lanes without bootstrap owner."
	roleNext := "Configure explicit Zitadel subject or group bindings for elevated roles."
	if !roleOK {
		roleState = "review"
	}
	gate.add(roleOK, "role_policy", "Role policy", roleState, roleDetail, roleNext, RoleAdmin, "explicit_role_policy")

	boundaryOK := boundary.Gate == "export_ready" && boundary.HashAvailable && boundary.RedactionModel == "metadata_only" && !boundary.ValueReturned
	boundaryState := "ready"
	boundaryDetail := "Enterprise release evidence must be exportable with a hash and a metadata-only boundary."
	boundaryNext := "Use an auditor session and keep evidence hash receipt available."
	if !boundaryOK {
		boundaryState = "review"
	}
	gate.add(boundaryOK, "evidence_boundary", "Evidence boundary", boundaryState, boundaryDetail, boundaryNext, RoleAuditor, "metadata_only_evidence_export")

	if gate.Blocked == 0 && currentMode == "enterprise" {
		gate.Status = "candidate"
		gate.Verdict = "enterprise_release_candidate"
		gate.Claim = "enterprise_candidate"
		gate.Summary = "Enterprise release gate is candidate; all required gates are present as value-free evidence signals."
		gate.Next = "Keep owner evidence current outside Janus before every release."
	} else if gate.Blocked == 0 {
		gate.Status = "ready_for_review"
		gate.Verdict = "self_hosted_ready_for_enterprise_review"
		gate.Claim = "self_hosted_not_enterprise"
		gate.Summary = "Enterprise release evidence is ready for review, but the current deployment is not claiming enterprise mode."
		gate.Next = "Complete owner review, then switch mode explicitly before claiming enterprise."
	} else {
		gate.Summary = fmt.Sprintf("Enterprise release gate is blocked by %d required gates.", gate.Blocked)
		if currentMode != "enterprise" {
			gate.Claim = "self_hosted_not_enterprise"
		}
	}
	return gate
}

func (g *EnterpriseReleaseGate) add(ok bool, key, label, state, detail, next, ownerRole, evidenceSignal string) {
	tone := "ok"
	if !ok {
		tone = "warn"
		g.Blocked++
		g.ReviewCount++
	} else {
		g.Passed++
	}
	g.Required++
	g.Checks = append(g.Checks, EnterpriseReleaseGateItem{
		Key:                 key,
		Label:               defaultString(label, key),
		State:               defaultString(state, "review"),
		Required:            true,
		OwnerRole:           defaultString(ownerRole, RoleAdmin),
		EvidenceSignal:      defaultString(evidenceSignal, "presence_only_release_gate"),
		Detail:              detail,
		Next:                next,
		Tone:                tone,
		EvidenceRefReturned: false,
		ValueReturned:       false,
	})
}

func workflowState(attached, missing bool, status string) string {
	if attached {
		return "attached"
	}
	if missing {
		return "missing"
	}
	return defaultString(status, "review")
}

func rolePolicyReleaseReady(policy RolePolicy) bool {
	return roleLaneConfigured(policy.AdminSubjects, policy.AdminGroups) &&
		roleLaneConfigured(policy.AuditorSubjects, policy.AuditorGroups) &&
		roleLaneConfigured(policy.OperatorSubjects, policy.OperatorGroups)
}

func roleLaneConfigured(subjects, groups map[string]bool) bool {
	return len(subjects)+len(groups) > 0
}
