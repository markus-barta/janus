package main

import (
	"strings"
	"time"
)

const (
	LifecycleDraft         = "draft"
	LifecycleActive        = "active"
	LifecycleRotating      = "rotating"
	LifecycleDeprecated    = "deprecated"
	LifecycleDisabled      = "disabled"
	LifecyclePendingDelete = "pending_delete"
	LifecycleDestroyed     = "destroyed"
)

type LifecycleGate struct {
	SecretRef string `json:"secret_ref"`
	Severity  string `json:"severity"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}

type LifecycleStateCount struct {
	State string `json:"state"`
	Count int    `json:"count"`
}

type LifecyclePosture struct {
	SupportedStates []string              `json:"supported_states"`
	Counts          map[string]int        `json:"counts"`
	StateCounts     []LifecycleStateCount `json:"state_counts"`
	ActiveCount     int                   `json:"active_count"`
	BlockedCount    int                   `json:"blocked_count"`
	StaleCount      int                   `json:"stale_count"`
	Gates           []LifecycleGate       `json:"gates"`
	GateCount       int                   `json:"gate_count"`
	ValueReturned   bool                  `json:"value_returned"`
}

func SupportedLifecycleStates() []string {
	return []string{
		LifecycleDraft,
		LifecycleActive,
		LifecycleRotating,
		LifecycleDeprecated,
		LifecycleDisabled,
		LifecyclePendingDelete,
		LifecycleDestroyed,
	}
}

func DescriptorLifecycle(desc SecretDescriptor) string {
	state := strings.ToLower(strings.TrimSpace(desc.Lifecycle))
	if state == "" {
		return LifecycleActive
	}
	for _, known := range SupportedLifecycleStates() {
		if state == known {
			return state
		}
	}
	return state
}

func LifecycleBlocksNormalUse(desc SecretDescriptor) (bool, string) {
	switch DescriptorLifecycle(desc) {
	case LifecycleActive, LifecycleRotating:
		return false, ""
	case LifecycleDraft:
		return true, "secret is draft and cannot be used yet"
	case LifecycleDeprecated:
		return true, "secret is deprecated; new use is blocked"
	case LifecycleDisabled:
		return true, "secret is disabled"
	case LifecyclePendingDelete:
		return true, "secret is pending deletion"
	case LifecycleDestroyed:
		return true, "secret is destroyed"
	default:
		return true, "secret lifecycle is unknown"
	}
}

func LifecyclePostureFor(descriptors []SecretDescriptor, now time.Time) LifecyclePosture {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	counts := map[string]int{}
	for _, state := range SupportedLifecycleStates() {
		counts[state] = 0
	}

	var gates []LifecycleGate
	activeCount := 0
	blockedCount := 0
	staleCount := 0

	for _, desc := range descriptors {
		state := DescriptorLifecycle(desc)
		counts[state]++
		if state == LifecycleActive {
			activeCount++
		}
		if blocked, reason := LifecycleBlocksNormalUse(desc); blocked {
			blockedCount++
			gates = append(gates, LifecycleGate{
				SecretRef: desc.ID,
				Severity:  "high",
				Code:      "normal_use_blocked",
				Message:   reason,
			})
		}
		if desc.LastCheckedAt.IsZero() {
			staleCount++
			gates = append(gates, LifecycleGate{
				SecretRef: desc.ID,
				Severity:  "medium",
				Code:      "freshness_unknown",
				Message:   "Descriptor has no checked timestamp.",
			})
			continue
		}
		maxAgeDays := desc.RotationDays
		if maxAgeDays <= 0 {
			maxAgeDays = 180
		}
		if desc.LastCheckedAt.Before(now.AddDate(0, 0, -maxAgeDays)) {
			staleCount++
			gates = append(gates, LifecycleGate{
				SecretRef: desc.ID,
				Severity:  "medium",
				Code:      "stale_descriptor",
				Message:   "Descriptor freshness is older than its rotation window.",
			})
		}
	}

	stateCounts := make([]LifecycleStateCount, 0, len(counts))
	for _, state := range SupportedLifecycleStates() {
		stateCounts = append(stateCounts, LifecycleStateCount{State: state, Count: counts[state]})
	}

	return LifecyclePosture{
		SupportedStates: SupportedLifecycleStates(),
		Counts:          counts,
		StateCounts:     stateCounts,
		ActiveCount:     activeCount,
		BlockedCount:    blockedCount,
		StaleCount:      staleCount,
		Gates:           gates,
		GateCount:       len(gates),
		ValueReturned:   false,
	}
}
