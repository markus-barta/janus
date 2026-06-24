package main

import "strings"

const restoreDrillControlKey = "restore_drill"

type RestoreDrillWorkflow struct {
	Label               string                     `json:"label"`
	Summary             string                     `json:"summary"`
	Mode                string                     `json:"mode"`
	Status              string                     `json:"status"`
	ControlKey          string                     `json:"control_key"`
	OwnerRole           string                     `json:"owner_role"`
	Required            bool                       `json:"required"`
	Attached            bool                       `json:"attached"`
	Missing             bool                       `json:"missing"`
	CanAttach           bool                       `json:"can_attach"`
	Attachment          string                     `json:"attachment"`
	EvidenceSignal      string                     `json:"evidence_signal"`
	ReviewCadence       string                     `json:"review_cadence"`
	Next                string                     `json:"next"`
	Checks              []RestoreDrillWorkflowItem `json:"checks"`
	EvidenceRefReturned bool                       `json:"evidence_ref_returned"`
	ValueReturned       bool                       `json:"value_returned"`
}

type RestoreDrillWorkflowItem struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	State         string `json:"state"`
	Detail        string `json:"detail"`
	Next          string `json:"next"`
	Tone          string `json:"tone"`
	ValueReturned bool   `json:"value_returned"`
}

func RestoreDrillWorkflowFor(enterprise EnterpriseValidation, records map[string]EvidenceAttachmentRecord, session Session) RestoreDrillWorkflow {
	control := enterpriseControlByKey(enterprise.Controls, restoreDrillControlKey)
	mode := strings.TrimSpace(enterprise.Mode)
	if mode == "" {
		mode = "self_hosted"
	}
	ownerRole := control.OwnerRole
	if ownerRole == "" {
		ownerRole = RoleOperator
	}
	attachment := control.Attachment
	if attachment == "" {
		attachment = "not_claimed"
	}
	evidenceSignal := control.EvidenceSignal
	if evidenceSignal == "" {
		evidenceSignal = "presence_only_env_flag"
	}
	attached := attachment == "attached_presence_only" || evidenceAttachmentPresent(records, restoreDrillControlKey)

	workflow := RestoreDrillWorkflow{
		Label:               "Restore drill workflow",
		Summary:             "Restore drill workflow records only that reviewed recovery evidence exists outside Janus.",
		Mode:                mode,
		Status:              "review",
		ControlKey:          restoreDrillControlKey,
		OwnerRole:           ownerRole,
		Required:            control.Required,
		Attached:            attached,
		Missing:             false,
		CanAttach:           HasRole(session, ownerRole),
		Attachment:          attachment,
		EvidenceSignal:      evidenceSignal,
		ReviewCadence:       "before enterprise claim and after backup, identity, policy, or storage changes",
		Next:                "Use an operator session after the external restore drill record exists.",
		EvidenceRefReturned: false,
		ValueReturned:       false,
	}
	if attached {
		workflow.Status = "attached"
		workflow.Attachment = "attached_presence_only"
		workflow.EvidenceSignal = "presence_only_workflow"
		workflow.Next = "Keep the drill record reviewed outside Janus; refresh it after meaningful recovery changes."
	} else if mode == "enterprise" {
		workflow.Status = "blocked"
		workflow.Missing = true
		workflow.Attachment = "missing"
		workflow.Next = "Attach restore drill presence after the recovery record is reviewed outside Janus."
	} else {
		workflow.Next = "Mark presence only after the restore drill record exists outside Janus."
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
	workflow.add(RestoreDrillWorkflowItem{
		Key:    "metadata_inventory",
		Label:  "Metadata inventory",
		State:  state,
		Detail: "Descriptors, owners, classes, scope, lifecycle, and approved-use metadata come back after restore.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(RestoreDrillWorkflowItem{
		Key:    "audit_chain",
		Label:  "Audit chain",
		State:  state,
		Detail: "Audit entries and hash-chain continuity come back after restore.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(RestoreDrillWorkflowItem{
		Key:    "policy_identity",
		Label:  "Policy and identity",
		State:  state,
		Detail: "Role bindings, scope filters, catalog gates, and identity mapping come back with the service.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(RestoreDrillWorkflowItem{
		Key:    "readiness_after_restore",
		Label:  "Readiness",
		State:  state,
		Detail: "Public readiness returns healthy, redacted, and value-free after restore.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(RestoreDrillWorkflowItem{
		Key:    "evidence_boundary",
		Label:  "Evidence boundary",
		State:  "withheld",
		Detail: "Restore drill files, URLs, refs, notes, request bodies, and values stay outside Janus.",
		Next:   "Keep the drill artifact in the external evidence system.",
		Tone:   "ok",
	})
	return workflow
}

func (w *RestoreDrillWorkflow) add(item RestoreDrillWorkflowItem) {
	item.ValueReturned = false
	w.Checks = append(w.Checks, item)
}
