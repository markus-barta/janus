package main

import (
	"runtime"
	"runtime/debug"
	"strings"
)

const (
	supplyChainBuilderImage = "golang:1.26.3-alpine"
	supplyChainFixedAlerts  = 30
)

var (
	buildCommit = "unknown"
	buildTime   = "unknown"
)

type SupplyChainPosture struct {
	Label                 string                   `json:"label"`
	Summary               string                   `json:"summary"`
	Status                string                   `json:"status"`
	Builder               string                   `json:"builder"`
	BuildProvenance       BuildProvenanceReceipt   `json:"build_provenance"`
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

type BuildProvenanceReceipt struct {
	Label                 string                   `json:"label"`
	Summary               string                   `json:"summary"`
	Status                string                   `json:"status"`
	Builder               string                   `json:"builder"`
	ModulePath            string                   `json:"module_path"`
	GoVersion             string                   `json:"go_version"`
	Commit                string                   `json:"commit"`
	CommitShort           string                   `json:"commit_short"`
	BuildTime             string                   `json:"build_time"`
	CommitBound           bool                     `json:"commit_bound"`
	BuildTimeBound        bool                     `json:"build_time_bound"`
	EvidenceSignal        string                   `json:"evidence_signal"`
	Next                  string                   `json:"next"`
	Checks                []SupplyChainPostureItem `json:"checks"`
	ArtifactReturned      bool                     `json:"artifact_returned"`
	SBOMReturned          bool                     `json:"sbom_returned"`
	ScannerOutputReturned bool                     `json:"scanner_output_returned"`
	EnvReturned           bool                     `json:"env_returned"`
	BackendPathReturned   bool                     `json:"backend_path_returned"`
	SecretValueReturned   bool                     `json:"secret_value_returned"`
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
	build := BuildProvenanceFor()
	posture := SupplyChainPosture{
		Label:                 "Supply-chain posture",
		Summary:               "Release dependency and build checks are summarized for operators without returning artifacts, scanner output, lockfile contents, backend paths, env values, refs, or secrets.",
		Status:                "clean",
		Builder:               supplyChainBuilderImage,
		BuildProvenance:       build,
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
	posture.add("build_provenance_receipt", "Build provenance", build.Status, "The running binary exposes a copy-safe build receipt with commit and build time when bound by the image build.", build.Next, buildToneFor(build.Status))
	posture.add("module_integrity", "Module integrity", "verified", "Module verification is part of the release gate before deploy.", "Keep module verification in every Janus release.", "ok")
	posture.add("vulnerability_scan", "Vulnerability scan", "clean", "The release gate records a clean vulnerability scan result without returning raw scanner output.", "Run the scan from the patched builder image after dependency changes.", "ok")
	posture.add("evidence_boundary", "Evidence boundary", "withheld", "Scanner output, lockfile contents, backend paths, env values, evidence refs, request bodies, and secret values stay outside Janus.", "Return only summary posture and value-free receipts.", "ok")
	return posture
}

func BuildProvenanceFor() BuildProvenanceReceipt {
	modulePath := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok && strings.TrimSpace(info.Main.Path) != "" {
		modulePath = strings.TrimSpace(info.Main.Path)
	}
	return buildProvenanceFor(supplyChainBuilderImage, modulePath, runtime.Version(), buildCommit, buildTime)
}

func buildProvenanceFor(builder, modulePath, goVersion, commit, builtAt string) BuildProvenanceReceipt {
	builder = cleanBuildField(builder)
	modulePath = cleanBuildField(modulePath)
	goVersion = cleanBuildField(goVersion)
	commit = cleanBuildField(commit)
	builtAt = cleanBuildField(builtAt)
	if builder == "" {
		builder = "unknown"
	}
	if modulePath == "" {
		modulePath = "unknown"
	}
	if goVersion == "" {
		goVersion = "unknown"
	}
	if commit == "" {
		commit = "unknown"
	}
	if builtAt == "" {
		builtAt = "unknown"
	}

	commitBound := commit != "unknown"
	timeBound := builtAt != "unknown"
	status := "bound"
	next := "Keep binding commit and build time during every image build."
	summary := "The running binary is bound to a source commit and build timestamp without returning build artifacts."
	if !commitBound || !timeBound {
		status = "incomplete"
		next = "Bind JANUS_BUILD_COMMIT and JANUS_BUILD_TIME during the image build before claiming release provenance."
		summary = "The running binary exposes a build receipt, but commit or build time was not bound at build."
	}

	receipt := BuildProvenanceReceipt{
		Label:                 "Build provenance receipt",
		Summary:               summary,
		Status:                status,
		Builder:               builder,
		ModulePath:            modulePath,
		GoVersion:             goVersion,
		Commit:                commit,
		CommitShort:           shortCommit(commit),
		BuildTime:             builtAt,
		CommitBound:           commitBound,
		BuildTimeBound:        timeBound,
		EvidenceSignal:        "copy_safe_build_provenance_receipt",
		Next:                  next,
		ArtifactReturned:      false,
		SBOMReturned:          false,
		ScannerOutputReturned: false,
		EnvReturned:           false,
		BackendPathReturned:   false,
		SecretValueReturned:   false,
		ValueReturned:         false,
	}
	receipt.add("commit_binding", "Commit binding", boundState(commitBound), "The source commit is supplied by the image build.", "Pass JANUS_BUILD_COMMIT from git rev-parse during deploy.", toneForBool(commitBound))
	receipt.add("build_time_binding", "Build time binding", boundState(timeBound), "The UTC build timestamp is supplied by the image build.", "Pass JANUS_BUILD_TIME during deploy.", toneForBool(timeBound))
	receipt.add("builder_identity", "Builder identity", "pinned", "The receipt names the pinned builder family without returning build logs.", "Keep builder review in the release gate.", "ok")
	receipt.add("artifact_boundary", "Artifact boundary", "withheld", "Binary artifacts, SBOM files, scanner output, env values, backend paths, and secret values are not returned.", "Keep detailed release evidence outside Janus.", "ok")
	return receipt
}

func (r *BuildProvenanceReceipt) add(key, label, state, detail, next, tone string) {
	r.Checks = append(r.Checks, SupplyChainPostureItem{
		Key:           key,
		Label:         label,
		State:         state,
		Detail:        detail,
		Next:          next,
		Tone:          tone,
		ValueReturned: false,
	})
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

func cleanBuildField(value string) string {
	return strings.TrimSpace(strings.ReplaceAll(value, "\n", " "))
}

func shortCommit(commit string) string {
	if commit == "" || commit == "unknown" {
		return "unknown"
	}
	if len(commit) <= 12 {
		return commit
	}
	return commit[:12]
}

func boundState(ok bool) string {
	if ok {
		return "bound"
	}
	return "unknown"
}

func toneForBool(ok bool) string {
	if ok {
		return "ok"
	}
	return "warn"
}

func buildToneFor(status string) string {
	if status == "bound" {
		return "ok"
	}
	return "warn"
}
