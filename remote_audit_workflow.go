package main

import "strings"

const remoteAuditControlKey = "remote_audit"

type RemoteAuditWorkflow struct {
	Label               string                    `json:"label"`
	Summary             string                    `json:"summary"`
	Mode                string                    `json:"mode"`
	Status              string                    `json:"status"`
	ControlKey          string                    `json:"control_key"`
	OwnerRole           string                    `json:"owner_role"`
	Required            bool                      `json:"required"`
	Attached            bool                      `json:"attached"`
	Missing             bool                      `json:"missing"`
	CanAttach           bool                      `json:"can_attach"`
	Attachment          string                    `json:"attachment"`
	EvidenceSignal      string                    `json:"evidence_signal"`
	ReviewCadence       string                    `json:"review_cadence"`
	Next                string                    `json:"next"`
	Checks              []RemoteAuditWorkflowItem `json:"checks"`
	EndpointReturned    bool                      `json:"endpoint_returned"`
	PayloadReturned     bool                      `json:"payload_returned"`
	AuditTokenReturned  bool                      `json:"audit_token_returned"`
	EvidenceRefReturned bool                      `json:"evidence_ref_returned"`
	ValueReturned       bool                      `json:"value_returned"`
}

type RemoteAuditWorkflowItem struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	State         string `json:"state"`
	Detail        string `json:"detail"`
	Next          string `json:"next"`
	Tone          string `json:"tone"`
	ValueReturned bool   `json:"value_returned"`
}

func RemoteAuditWorkflowFor(enterprise EnterpriseValidation, records map[string]EvidenceAttachmentRecord, session Session) RemoteAuditWorkflow {
	control := enterpriseControlByKey(enterprise.Controls, remoteAuditControlKey)
	mode := strings.TrimSpace(enterprise.Mode)
	if mode == "" {
		mode = "self_hosted"
	}
	ownerRole := control.OwnerRole
	if ownerRole == "" {
		ownerRole = RoleAuditor
	}
	attachment := control.Attachment
	if attachment == "" {
		attachment = "not_claimed"
	}
	evidenceSignal := control.EvidenceSignal
	if evidenceSignal == "" {
		evidenceSignal = "presence_only_env_flag"
	}
	attached := attachment == "attached_presence_only" || evidenceAttachmentPresent(records, remoteAuditControlKey)

	workflow := RemoteAuditWorkflow{
		Label:               "Remote audit workflow",
		Summary:             "Remote audit workflow records only that reviewed audit shipping evidence exists outside Janus.",
		Mode:                mode,
		Status:              "review",
		ControlKey:          remoteAuditControlKey,
		OwnerRole:           ownerRole,
		Required:            control.Required,
		Attached:            attached,
		Missing:             false,
		CanAttach:           HasRole(session, ownerRole),
		Attachment:          attachment,
		EvidenceSignal:      evidenceSignal,
		ReviewCadence:       "before enterprise claim and after audit sink, SIEM, retention, or identity changes",
		Next:                "Use an auditor session after the external remote audit evidence exists.",
		EndpointReturned:    false,
		PayloadReturned:     false,
		AuditTokenReturned:  false,
		EvidenceRefReturned: false,
		ValueReturned:       false,
	}
	if attached {
		workflow.Status = "attached"
		workflow.Attachment = "attached_presence_only"
		workflow.EvidenceSignal = "presence_only_workflow"
		workflow.Next = "Keep the remote audit evidence reviewed outside Janus; refresh it after audit path changes."
	} else if mode == "enterprise" {
		workflow.Status = "blocked"
		workflow.Missing = true
		workflow.Attachment = "missing"
		workflow.Next = "Attach remote audit presence after shipping evidence is reviewed outside Janus."
	} else {
		workflow.Next = "Mark presence only after reviewed remote audit evidence exists outside Janus."
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
	workflow.add(RemoteAuditWorkflowItem{
		Key:    "shipping_path",
		Label:  "Shipping path",
		State:  state,
		Detail: "External evidence proves audit metadata leaves the host and reaches the reviewed audit destination.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(RemoteAuditWorkflowItem{
		Key:    "chain_continuity",
		Label:  "Chain continuity",
		State:  state,
		Detail: "External evidence proves hash-chain state and local audit posture remain reviewable after shipping.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(RemoteAuditWorkflowItem{
		Key:    "request_correlation",
		Label:  "Request correlation",
		State:  state,
		Detail: "External evidence proves request ids can connect Janus UI/API actions to downstream audit records.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(RemoteAuditWorkflowItem{
		Key:    "custody_review",
		Label:  "Custody review",
		State:  state,
		Detail: "External evidence proves auditor ownership, retention, and downstream custody are reviewed.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(RemoteAuditWorkflowItem{
		Key:    "alert_review",
		Label:  "Alert review",
		State:  state,
		Detail: "External evidence proves high-severity Janus events are visible to the review path.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(RemoteAuditWorkflowItem{
		Key:    "audit_boundary",
		Label:  "Audit boundary",
		State:  "withheld",
		Detail: "Shipping endpoints, tokens, webhook secrets, SIEM payloads, URLs, refs, request bodies, and values stay outside Janus.",
		Next:   "Keep audit shipping proof and downstream destination details in the external audit system.",
		Tone:   "ok",
	})
	return workflow
}

func (w *RemoteAuditWorkflow) add(item RemoteAuditWorkflowItem) {
	item.ValueReturned = false
	w.Checks = append(w.Checks, item)
}
