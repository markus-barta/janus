package main

import "strings"

const privacyPolicyControlKey = "privacy_policy"

type PrivacyRetentionWorkflow struct {
	Label               string                         `json:"label"`
	Summary             string                         `json:"summary"`
	Mode                string                         `json:"mode"`
	Status              string                         `json:"status"`
	ControlKey          string                         `json:"control_key"`
	OwnerRole           string                         `json:"owner_role"`
	Required            bool                           `json:"required"`
	Attached            bool                           `json:"attached"`
	Missing             bool                           `json:"missing"`
	CanAttach           bool                           `json:"can_attach"`
	Attachment          string                         `json:"attachment"`
	EvidenceSignal      string                         `json:"evidence_signal"`
	ReviewCadence       string                         `json:"review_cadence"`
	Next                string                         `json:"next"`
	Checks              []PrivacyRetentionWorkflowItem `json:"checks"`
	PolicyDocReturned   bool                           `json:"policy_doc_returned"`
	EvidenceRefReturned bool                           `json:"evidence_ref_returned"`
	RawMetadataReturned bool                           `json:"raw_metadata_returned"`
	ValueReturned       bool                           `json:"value_returned"`
}

type PrivacyRetentionWorkflowItem struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	State         string `json:"state"`
	Detail        string `json:"detail"`
	Next          string `json:"next"`
	Tone          string `json:"tone"`
	ValueReturned bool   `json:"value_returned"`
}

func PrivacyRetentionWorkflowFor(enterprise EnterpriseValidation, records map[string]EvidenceAttachmentRecord, session Session) PrivacyRetentionWorkflow {
	control := enterpriseControlByKey(enterprise.Controls, privacyPolicyControlKey)
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
	attached := attachment == "attached_presence_only" || evidenceAttachmentPresent(records, privacyPolicyControlKey)

	workflow := PrivacyRetentionWorkflow{
		Label:               "Privacy and retention workflow",
		Summary:             "Privacy and retention workflow records only that reviewed policy evidence exists outside Janus.",
		Mode:                mode,
		Status:              "review",
		ControlKey:          privacyPolicyControlKey,
		OwnerRole:           ownerRole,
		Required:            control.Required,
		Attached:            attached,
		Missing:             false,
		CanAttach:           HasRole(session, ownerRole),
		Attachment:          attachment,
		EvidenceSignal:      evidenceSignal,
		ReviewCadence:       "before enterprise claim and after data, audit, evidence, identity, or retention changes",
		Next:                "Use an admin session after the external privacy and retention policy exists.",
		PolicyDocReturned:   false,
		EvidenceRefReturned: false,
		RawMetadataReturned: false,
		ValueReturned:       false,
	}
	if attached {
		workflow.Status = "attached"
		workflow.Attachment = "attached_presence_only"
		workflow.EvidenceSignal = "presence_only_workflow"
		workflow.Next = "Keep the policy record reviewed outside Janus; refresh it when data or retention rules change."
	} else if mode == "enterprise" {
		workflow.Status = "blocked"
		workflow.Missing = true
		workflow.Attachment = "missing"
		workflow.Next = "Attach privacy policy presence after the policy is reviewed outside Janus."
	} else {
		workflow.Next = "Mark presence only after the reviewed privacy and retention policy exists outside Janus."
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
	workflow.add(PrivacyRetentionWorkflowItem{
		Key:    "data_classes",
		Label:  "Data classes",
		State:  state,
		Detail: "The external policy names Janus metadata classes, audit records, evidence presence, and exported evidence.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(PrivacyRetentionWorkflowItem{
		Key:    "retention_window",
		Label:  "Retention window",
		State:  state,
		Detail: "The external policy defines retention, cleanup ownership, and review timing for local evidence.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(PrivacyRetentionWorkflowItem{
		Key:    "access_boundary",
		Label:  "Access boundary",
		State:  state,
		Detail: "The policy matches Janus role gates for posture, evidence export, audit review, and admin policy changes.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(PrivacyRetentionWorkflowItem{
		Key:    "payload_exclusions",
		Label:  "Payload exclusions",
		State:  state,
		Detail: "Secret values, request bodies, prompts, command output, env dumps, auth secrets, and raw evidence stay out.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(PrivacyRetentionWorkflowItem{
		Key:    "cleanup_review",
		Label:  "Cleanup review",
		State:  state,
		Detail: "Policy review covers local evidence cleanup and exported evidence custody outside Janus.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(PrivacyRetentionWorkflowItem{
		Key:    "policy_boundary",
		Label:  "Policy boundary",
		State:  "withheld",
		Detail: "Policy docs, URLs, notes, refs, request bodies, backend paths, raw metadata, and values stay outside Janus.",
		Next:   "Keep policy evidence in the external governance system.",
		Tone:   "ok",
	})
	return workflow
}

func (w *PrivacyRetentionWorkflow) add(item PrivacyRetentionWorkflowItem) {
	item.ValueReturned = false
	w.Checks = append(w.Checks, item)
}
