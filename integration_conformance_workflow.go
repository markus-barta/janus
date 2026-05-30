package main

import "strings"

const integrationConformanceControlKey = "integration_conformance"

type IntegrationConformanceWorkflow struct {
	Label                   string                               `json:"label"`
	Summary                 string                               `json:"summary"`
	Mode                    string                               `json:"mode"`
	Status                  string                               `json:"status"`
	ControlKey              string                               `json:"control_key"`
	OwnerRole               string                               `json:"owner_role"`
	Required                bool                                 `json:"required"`
	Attached                bool                                 `json:"attached"`
	Missing                 bool                                 `json:"missing"`
	CanAttach               bool                                 `json:"can_attach"`
	Attachment              string                               `json:"attachment"`
	EvidenceSignal          string                               `json:"evidence_signal"`
	ReviewCadence           string                               `json:"review_cadence"`
	Next                    string                               `json:"next"`
	Checks                  []IntegrationConformanceWorkflowItem `json:"checks"`
	ConnectorConfigReturned bool                                 `json:"connector_config_returned"`
	EndpointReturned        bool                                 `json:"endpoint_returned"`
	PayloadReturned         bool                                 `json:"payload_returned"`
	EvidenceRefReturned     bool                                 `json:"evidence_ref_returned"`
	ValueReturned           bool                                 `json:"value_returned"`
}

type IntegrationConformanceWorkflowItem struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	State         string `json:"state"`
	Detail        string `json:"detail"`
	Next          string `json:"next"`
	Tone          string `json:"tone"`
	ValueReturned bool   `json:"value_returned"`
}

func IntegrationConformanceWorkflowFor(enterprise EnterpriseValidation, records map[string]EvidenceAttachmentRecord, session Session) IntegrationConformanceWorkflow {
	control := enterpriseControlByKey(enterprise.Controls, integrationConformanceControlKey)
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
	attached := attachment == "attached_presence_only" || evidenceAttachmentPresent(records, integrationConformanceControlKey)

	workflow := IntegrationConformanceWorkflow{
		Label:                   "Integration conformance workflow",
		Summary:                 "Integration conformance workflow records only that reviewed identity, audit, ticketing, SIEM, and evidence-custody proof exists outside Janus.",
		Mode:                    mode,
		Status:                  "review",
		ControlKey:              integrationConformanceControlKey,
		OwnerRole:               ownerRole,
		Required:                control.Required,
		Attached:                attached,
		Missing:                 false,
		CanAttach:               HasRole(session, ownerRole),
		Attachment:              attachment,
		EvidenceSignal:          evidenceSignal,
		ReviewCadence:           "before enterprise claim and after identity, audit, ticketing, SIEM, or custody integration changes",
		Next:                    "Use an admin session after the external integration conformance record exists.",
		ConnectorConfigReturned: false,
		EndpointReturned:        false,
		PayloadReturned:         false,
		EvidenceRefReturned:     false,
		ValueReturned:           false,
	}
	if attached {
		workflow.Status = "attached"
		workflow.Attachment = "attached_presence_only"
		workflow.EvidenceSignal = "presence_only_workflow"
		workflow.Next = "Keep the conformance record reviewed outside Janus; refresh it after integration changes."
	} else if mode == "enterprise" {
		workflow.Status = "blocked"
		workflow.Missing = true
		workflow.Attachment = "missing"
		workflow.Next = "Attach integration conformance presence after the external record is reviewed outside Janus."
	} else {
		workflow.Next = "Mark presence only after the reviewed integration conformance record exists outside Janus."
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
	workflow.add(IntegrationConformanceWorkflowItem{
		Key:    "identity_mapping",
		Label:  "Identity mapping",
		State:  state,
		Detail: "External evidence proves identity subjects, groups, and Janus roles map as intended.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(IntegrationConformanceWorkflowItem{
		Key:    "audit_shipping",
		Label:  "Audit shipping",
		State:  state,
		Detail: "External evidence proves Janus audit metadata, request ids, severity, and chain state reach the audit system.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(IntegrationConformanceWorkflowItem{
		Key:    "ticketing_link",
		Label:  "Ticketing link",
		State:  state,
		Detail: "External evidence proves changes, exceptions, and approvals can be tied to the right ticket or review record.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(IntegrationConformanceWorkflowItem{
		Key:    "siem_custody",
		Label:  "SIEM custody",
		State:  state,
		Detail: "External evidence proves downstream custody and alert review for Janus security events.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(IntegrationConformanceWorkflowItem{
		Key:    "evidence_handoff",
		Label:  "Evidence handoff",
		State:  state,
		Detail: "External evidence proves export hashes and presence receipts can be reviewed outside Janus.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(IntegrationConformanceWorkflowItem{
		Key:    "connector_boundary",
		Label:  "Connector boundary",
		State:  "withheld",
		Detail: "Connector configs, tokens, webhook secrets, endpoints, URLs, payloads, request bodies, refs, and values stay outside Janus.",
		Next:   "Keep connector proof and downstream system details in the external integration record.",
		Tone:   "ok",
	})
	return workflow
}

func (w *IntegrationConformanceWorkflow) add(item IntegrationConformanceWorkflowItem) {
	item.ValueReturned = false
	w.Checks = append(w.Checks, item)
}
