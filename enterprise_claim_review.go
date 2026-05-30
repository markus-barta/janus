package main

import "strings"

type EnterpriseClaimReview struct {
	Label               string                       `json:"label"`
	Summary             string                       `json:"summary"`
	Status              string                       `json:"status"`
	Claim               string                       `json:"claim"`
	CurrentMode         string                       `json:"current_mode"`
	TargetMode          string                       `json:"target_mode"`
	Required            int                          `json:"required"`
	Ready               int                          `json:"ready"`
	Attached            int                          `json:"attached"`
	Missing             int                          `json:"missing"`
	ReviewCount         int                          `json:"review_count"`
	EvidenceSignal      string                       `json:"evidence_signal"`
	EvidenceGate        string                       `json:"evidence_gate"`
	ReviewCadence       string                       `json:"review_cadence"`
	Next                string                       `json:"next"`
	Owners              []EnterpriseClaimOwnerReview `json:"owners"`
	Checks              []EnterpriseClaimReviewItem  `json:"checks"`
	EvidenceRefReturned bool                         `json:"evidence_ref_returned"`
	ProcedureReturned   bool                         `json:"procedure_returned"`
	TicketURLReturned   bool                         `json:"ticket_url_returned"`
	BackendPathReturned bool                         `json:"backend_path_returned"`
	RequestBodyReturned bool                         `json:"request_body_returned"`
	EnvReturned         bool                         `json:"env_returned"`
	ValueReturned       bool                         `json:"value_returned"`
}

type EnterpriseClaimOwnerReview struct {
	Role          string `json:"role"`
	Required      int    `json:"required"`
	Ready         int    `json:"ready"`
	Attached      int    `json:"attached"`
	Missing       int    `json:"missing"`
	ReviewCount   int    `json:"review_count"`
	ValueReturned bool   `json:"value_returned"`
}

type EnterpriseClaimReviewItem struct {
	Key                 string `json:"key"`
	Label               string `json:"label"`
	State               string `json:"state"`
	Required            bool   `json:"required"`
	OwnerRole           string `json:"owner_role"`
	Attachment          string `json:"attachment"`
	EvidenceSignal      string `json:"evidence_signal"`
	Detail              string `json:"detail"`
	Next                string `json:"next"`
	Tone                string `json:"tone"`
	EvidenceRefReturned bool   `json:"evidence_ref_returned"`
	ValueReturned       bool   `json:"value_returned"`
}

func EnterpriseClaimReviewFor(currentMode string, enterprise EnterpriseValidation, dryRun EnterpriseDryRun, boundary EvidenceBoundary) EnterpriseClaimReview {
	currentMode = strings.TrimSpace(currentMode)
	if currentMode == "" {
		currentMode = "self_hosted"
	}
	targetMode := strings.TrimSpace(dryRun.TargetMode)
	if targetMode == "" {
		targetMode = "enterprise"
	}

	review := EnterpriseClaimReview{
		Label:               "Enterprise claim review",
		Status:              "not_claimed",
		Claim:               "self_hosted_not_enterprise",
		CurrentMode:         currentMode,
		TargetMode:          targetMode,
		EvidenceSignal:      "presence_only_enterprise_claim_review",
		EvidenceGate:        boundary.Gate,
		ReviewCadence:       "before enterprise mode and after evidence, owner, identity, audit, release, dependency, or break-glass changes",
		Next:                "Keep self-hosted posture honest until every required external evidence presence is reviewed.",
		EvidenceRefReturned: false,
		ProcedureReturned:   false,
		TicketURLReturned:   false,
		BackendPathReturned: false,
		RequestBodyReturned: false,
		EnvReturned:         false,
		ValueReturned:       false,
	}

	if dryRun.Required > 0 {
		review.Required = dryRun.Required
		review.Ready = dryRun.Ready
		review.Attached = dryRun.Attached
		review.Missing = dryRun.Missing
	}
	if review.Missing > 0 {
		review.Status = "blocked"
		review.Summary = "Enterprise claim is blocked; required external evidence presence is still missing."
		review.Next = "Attach presence-only evidence after external owner review, then rerun the enterprise dry-run."
	} else if currentMode == "enterprise" && strings.TrimSpace(enterprise.Status) == "candidate" {
		review.Status = "candidate"
		review.Claim = "enterprise_candidate"
		review.Summary = "Enterprise claim is a candidate; keep external evidence current before relying on it."
		review.Next = "Keep owner evidence reviewed outside Janus and monitor drift before every release."
	} else {
		review.Status = "ready_for_review"
		review.Summary = "Enterprise evidence appears complete for review, but the current deployment is not claiming enterprise mode."
		review.Next = "Review external evidence with owners before switching to enterprise mode."
	}
	if currentMode != "enterprise" {
		review.Claim = "self_hosted_not_enterprise"
	}

	for _, check := range dryRun.Checks {
		item := EnterpriseClaimReviewItem{
			Key:                 check.Key,
			Label:               check.Label,
			State:               defaultString(check.State, "not_claimed"),
			Required:            check.Required,
			OwnerRole:           defaultString(check.OwnerRole, RoleAdmin),
			Attachment:          defaultString(check.Attachment, "not_claimed"),
			EvidenceSignal:      defaultString(check.EvidenceSignal, "presence_only_env_flag"),
			Detail:              check.Detail,
			Next:                check.Next,
			Tone:                defaultString(check.Tone, "info"),
			EvidenceRefReturned: false,
			ValueReturned:       false,
		}
		if item.Required && (item.State == "missing" || item.State == "review" || item.Attachment == "missing") {
			review.ReviewCount++
			item.Tone = "warn"
		}
		review.Checks = append(review.Checks, item)
		review.addOwner(item)
	}
	return review
}

func (r *EnterpriseClaimReview) addOwner(item EnterpriseClaimReviewItem) {
	owner := r.ensureOwner(item.OwnerRole)
	if item.Required {
		owner.Required++
	}
	if item.State == "ready" || item.State == "attached" {
		owner.Ready++
	}
	if item.Attachment == "attached_presence_only" {
		owner.Attached++
	}
	if item.Required && (item.State == "missing" || item.State == "review" || item.Attachment == "missing") {
		owner.Missing++
		owner.ReviewCount++
	}
}

func (r *EnterpriseClaimReview) ensureOwner(role string) *EnterpriseClaimOwnerReview {
	role = defaultString(role, RoleAdmin)
	for i := range r.Owners {
		if r.Owners[i].Role == role {
			return &r.Owners[i]
		}
	}
	r.Owners = append(r.Owners, EnterpriseClaimOwnerReview{Role: role, ValueReturned: false})
	return &r.Owners[len(r.Owners)-1]
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
