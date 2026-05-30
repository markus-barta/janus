package main

const (
	supplyChainBuilderImage = "golang:1.26.3-alpine"
	supplyChainFixedAlerts  = 30
)

type SupplyChainPosture struct {
	Label                 string                   `json:"label"`
	Summary               string                   `json:"summary"`
	Status                string                   `json:"status"`
	Builder               string                   `json:"builder"`
	DependencyState       string                   `json:"dependency_state"`
	OpenAlerts            int                      `json:"open_alerts"`
	FixedAlerts           int                      `json:"fixed_alerts"`
	ModuleVerification    string                   `json:"module_verification"`
	ScannerBoundary       string                   `json:"scanner_boundary"`
	EvidenceSignal        string                   `json:"evidence_signal"`
	EvidenceGate          string                   `json:"evidence_gate"`
	ReviewCadence         string                   `json:"review_cadence"`
	Next                  string                   `json:"next"`
	Checks                []SupplyChainPostureItem `json:"checks"`
	ScannerOutputReturned bool                     `json:"scanner_output_returned"`
	PackageLockReturned   bool                     `json:"package_lock_returned"`
	BackendPathReturned   bool                     `json:"backend_path_returned"`
	EnvReturned           bool                     `json:"env_returned"`
	EvidenceRefReturned   bool                     `json:"evidence_ref_returned"`
	ValueReturned         bool                     `json:"value_returned"`
}

type SupplyChainPostureItem struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	State         string `json:"state"`
	Detail        string `json:"detail"`
	Next          string `json:"next"`
	Tone          string `json:"tone"`
	ValueReturned bool   `json:"value_returned"`
}

func SupplyChainPostureFor(boundary EvidenceBoundary) SupplyChainPosture {
	posture := SupplyChainPosture{
		Label:                 "Supply-chain posture",
		Summary:               "Release dependency checks are summarized for operators without returning scanner output, lockfile contents, backend paths, env values, refs, or secrets.",
		Status:                "clean",
		Builder:               supplyChainBuilderImage,
		DependencyState:       "no_open_alerts_at_release_review",
		OpenAlerts:            0,
		FixedAlerts:           supplyChainFixedAlerts,
		ModuleVerification:    "go_mod_verify_release_gate",
		ScannerBoundary:       "summary_only_no_raw_scanner_output",
		EvidenceSignal:        "release_verified_dependency_posture",
		EvidenceGate:          boundary.Gate,
		ReviewCadence:         "before each release and after dependency, builder, auth, or crypto changes",
		Next:                  "Keep dependency review in the release gate; attach external release evidence before stronger enterprise claims.",
		ScannerOutputReturned: false,
		PackageLockReturned:   false,
		BackendPathReturned:   false,
		EnvReturned:           false,
		EvidenceRefReturned:   false,
		ValueReturned:         false,
	}
	posture.add("dependency_alerts", "Dependency alerts", "clean", "Release review found zero open dependency alerts for this baseline.", "Recheck alerts before the next release.", "ok")
	posture.add("patched_builder", "Patched builder", "pinned", "Janus builds with the patched Go builder family used for the release gate.", "Refresh the builder pin when Go publishes a security patch.", "ok")
	posture.add("module_integrity", "Module integrity", "verified", "Module verification is part of the release gate before deploy.", "Keep module verification in every Janus release.", "ok")
	posture.add("vulnerability_scan", "Vulnerability scan", "clean", "The release gate records a clean vulnerability scan result without returning raw scanner output.", "Run the scan from the patched builder image after dependency changes.", "ok")
	posture.add("evidence_boundary", "Evidence boundary", "withheld", "Scanner output, lockfile contents, backend paths, env values, evidence refs, request bodies, and secret values stay outside Janus.", "Return only summary posture and value-free receipts.", "ok")
	return posture
}

func (p *SupplyChainPosture) add(key, label, state, detail, next, tone string) {
	p.Checks = append(p.Checks, SupplyChainPostureItem{
		Key:           key,
		Label:         label,
		State:         state,
		Detail:        detail,
		Next:          next,
		Tone:          tone,
		ValueReturned: false,
	})
}
