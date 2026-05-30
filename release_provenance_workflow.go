package main

import "strings"

const releaseProvenanceControlKey = "release_provenance"

type ReleaseProvenanceWorkflow struct {
	Label               string                          `json:"label"`
	Summary             string                          `json:"summary"`
	Mode                string                          `json:"mode"`
	Status              string                          `json:"status"`
	ControlKey          string                          `json:"control_key"`
	OwnerRole           string                          `json:"owner_role"`
	Required            bool                            `json:"required"`
	Attached            bool                            `json:"attached"`
	Missing             bool                            `json:"missing"`
	CanAttach           bool                            `json:"can_attach"`
	Attachment          string                          `json:"attachment"`
	EvidenceSignal      string                          `json:"evidence_signal"`
	ReviewCadence       string                          `json:"review_cadence"`
	Next                string                          `json:"next"`
	Checks              []ReleaseProvenanceWorkflowItem `json:"checks"`
	ArtifactReturned    bool                            `json:"artifact_returned"`
	EvidenceRefReturned bool                            `json:"evidence_ref_returned"`
	ValueReturned       bool                            `json:"value_returned"`
}

type ReleaseProvenanceWorkflowItem struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	State         string `json:"state"`
	Detail        string `json:"detail"`
	Next          string `json:"next"`
	Tone          string `json:"tone"`
	ValueReturned bool   `json:"value_returned"`
}

func ReleaseProvenanceWorkflowFor(enterprise EnterpriseValidation, records map[string]EvidenceAttachmentRecord, session Session) ReleaseProvenanceWorkflow {
	control := enterpriseControlByKey(enterprise.Controls, releaseProvenanceControlKey)
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
	attached := attachment == "attached_presence_only" || evidenceAttachmentPresent(records, releaseProvenanceControlKey)

	workflow := ReleaseProvenanceWorkflow{
		Label:               "Release provenance workflow",
		Summary:             "Release provenance workflow records only that reviewed build and release evidence exists outside Janus.",
		Mode:                mode,
		Status:              "review",
		ControlKey:          releaseProvenanceControlKey,
		OwnerRole:           ownerRole,
		Required:            control.Required,
		Attached:            attached,
		Missing:             false,
		CanAttach:           HasRole(session, ownerRole),
		Attachment:          attachment,
		EvidenceSignal:      evidenceSignal,
		ReviewCadence:       "for every deployed image and before enterprise promotion",
		Next:                "Use an operator session after the external release evidence exists.",
		ArtifactReturned:    false,
		EvidenceRefReturned: false,
		ValueReturned:       false,
	}
	if attached {
		workflow.Status = "attached"
		workflow.Attachment = "attached_presence_only"
		workflow.EvidenceSignal = "presence_only_workflow"
		workflow.Next = "Keep the release evidence reviewed outside Janus; refresh it for each deployed image."
	} else if mode == "enterprise" {
		workflow.Status = "blocked"
		workflow.Missing = true
		workflow.Attachment = "missing"
		workflow.Next = "Attach release provenance presence after the release evidence is reviewed outside Janus."
	} else {
		workflow.Next = "Mark presence only after release provenance exists outside Janus."
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
	workflow.add(ReleaseProvenanceWorkflowItem{
		Key:    "build_identity",
		Label:  "Build identity",
		State:  state,
		Detail: "Commit, image digest, builder identity, and build inputs are matched in the external release evidence.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(ReleaseProvenanceWorkflowItem{
		Key:    "provenance_attestation",
		Label:  "Provenance attestation",
		State:  state,
		Detail: "Signed provenance or an approved equivalent is reviewed before trusting the release.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(ReleaseProvenanceWorkflowItem{
		Key:    "sbom_review",
		Label:  "SBOM review",
		State:  state,
		Detail: "Dependency and vulnerability evidence is reviewed outside Janus, including any accepted exceptions.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(ReleaseProvenanceWorkflowItem{
		Key:    "channel_trust",
		Label:  "Channel trust",
		State:  state,
		Detail: "Release channel, registry path, and deployment source are trusted before enterprise use.",
		Next:   next,
		Tone:   tone,
	})
	workflow.add(ReleaseProvenanceWorkflowItem{
		Key:    "artifact_boundary",
		Label:  "Artifact boundary",
		State:  "withheld",
		Detail: "Release artifacts, signatures, SBOM files, URLs, refs, request bodies, and values stay outside Janus.",
		Next:   "Keep artifact evidence in the external release system.",
		Tone:   "ok",
	})
	return workflow
}

func (w *ReleaseProvenanceWorkflow) add(item ReleaseProvenanceWorkflowItem) {
	item.ValueReturned = false
	w.Checks = append(w.Checks, item)
}
