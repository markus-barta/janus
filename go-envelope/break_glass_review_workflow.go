package main

import "strings"

const breakGlassReviewControlKey = "break_glass_review"

type BreakGlassReviewWorkflow struct {
	Label                string                         `json:"label"`
	Summary              string                         `json:"summary"`
	Mode                 string                         `json:"mode"`
	Status               string                         `json:"status"`
	ControlKey           string                         `json:"control_key"`
	OwnerRole            string                         `json:"owner_role"`
	Required             bool                           `json:"required"`
	Attached             bool                           `json:"attached"`
	Missing              bool                           `json:"missing"`
	CanAttach            bool                           `json:"can_attach"`
	Attachment           string                         `json:"attachment"`
	EvidenceSignal       string                         `json:"evidence_signal"`
	ReviewCadence        string                         `json:"review_cadence"`
	Next                 string                         `json:"next"`
	Checks               []BreakGlassReviewWorkflowItem `json:"checks"`
	ProcedureReturned    bool                           `json:"procedure_returned"`
	ContactPathReturned  bool                           `json:"contact_path_returned"`
	AccessTargetReturned bool                           `json:"access_target_returned"`
	CredentialReturned   bool                           `json:"credential_returned"`
	EvidenceRefReturned  bool                           `json:"evidence_ref_returned"`
	ValueReturned        bool                           `json:"value_returned"`
}

type BreakGlassReviewWorkflowItem struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	State         string `json:"state"`
	Detail        string `json:"detail"`
	Next          string `json:"next"`
	Tone          string `json:"tone"`
	ValueReturned bool   `json:"value_returned"`
}

func BreakGlassReviewWorkflowFor(enterprise EnterpriseValidation, records map[string]EvidenceAttachmentRecord, session Session) BreakGlassReviewWorkflow {
	control := enterpriseControlByKey(enterprise.Controls, breakGlassReviewControlKey)
	mode := strings.TrimSpace(enterprise.Mode)
	if mode == "" {
		mode = "self_hosted"
	}
	ownerRole := control.OwnerRole
	if ownerRole == "" {
		ownerRole = RoleAdmin
	}
	attachment := control.Attachment
	if attachment == "" {
		attachment = "not_claimed"
	}
	evidenceSignal := control.EvidenceSignal
	if evidenceSignal == "" {
		evidenceSignal = "presence_only_env_flag"
	}
	attached := attachment == "attached_presence_only" || evidenceAttachmentPresent(records, breakGlassReviewControlKey)

	workflow := BreakGlassReviewWorkflow{
		Label:                "Break-glass review workflow",
		Summary:              "Break-glass review workflow records only that reviewed emergency-access evidence exists outside Janus.",
		Mode:                 mode,
		Status:               "review",
		ControlKey:           breakGlassReviewControlKey,
		OwnerRole:            ownerRole,
		Required:             control.Required,
		Attached:             attached,
		Missing:              false,
		CanAttach:            HasRole(session, ownerRole),
		Attachment:           attachment,
		EvidenceSignal:       evidenceSignal,
		ReviewCadence:        "before enterprise claim and after emergency access, role, identity, or recovery changes",
		Next:                 "Use an admin session after the external break-glass review evidence exists.",
		ProcedureReturned:    false,
		ContactPathReturned:  false,
		AccessTargetReturned: false,
		CredentialReturned:   false,
		EvidenceRefReturned:  false,
		ValueReturned:        false,
	}
	if attached {
		workflow.Status = "attached"
		workflow.Attachment = "attached_presence_only"
		workflow.EvidenceSignal = "presence_only_workflow"
		workflow.Next = "Keep the emergency-access review evidence outside Janus; refresh it after break-glass path changes."
	} else if mode == "enterprise" {
		workflow.Status = "blocked"
		workflow.Missing = true
		workflow.Attachment = "missing"
		workflow.Next = "Attach break-glass review presence after emergency-access evidence is reviewed outside Janus."
	} else {
		workflow.Next = "Mark presence only after reviewed break-glass evidence exists outside Janus."
	}

	state := "review"
	tone := "info"
	next := workflow.Next
	if workflow.Attached {
		state = "attached"
		tone = "ok"
	} else if workflow.Missing {
		state = "missing"
		tone = "warn"
	}
	workflow.add(BreakGlassReviewWorkflowItem{
		Key:    "owner_review",
		Label:  "Owner review",
		State:  state,
		Detail: "External evidence proves emergency-access ownership and review responsibility are defined.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(BreakGlassReviewWorkflowItem{
		Key:    "emergency_scope",
		Label:  "Emergency scope",
		State:  state,
		Detail: "External evidence proves when break-glass use is allowed and which Janus duties it can affect.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(BreakGlassReviewWorkflowItem{
		Key:    "step_up_review",
		Label:  "Step-up review",
		State:  state,
		Detail: "External evidence proves emergency access has an approved review path before stronger claims.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(BreakGlassReviewWorkflowItem{
		Key:    "time_boxing",
		Label:  "Time-boxing",
		State:  state,
		Detail: "External evidence proves emergency access is temporary, reviewed, and cleaned up after use.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(BreakGlassReviewWorkflowItem{
		Key:    "post_use_audit",
		Label:  "Post-use audit",
		State:  state,
		Detail: "External evidence proves break-glass use creates reviewable audit and follow-up evidence.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(BreakGlassReviewWorkflowItem{
		Key:    "emergency_boundary",
		Label:  "Emergency boundary",
		State:  "withheld",
		Detail: "Emergency procedures, contact paths, access targets, credentials, ticket URLs, refs, incident details, and values stay outside Janus.",
		Next:   "Keep break-glass procedures and incident details in the external emergency-access system.",
		Tone:   "ok",
	})
	return workflow
}

func (w *BreakGlassReviewWorkflow) add(item BreakGlassReviewWorkflowItem) {
	item.ValueReturned = false
	w.Checks = append(w.Checks, item)
}
