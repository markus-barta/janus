package main

import (
	"sort"
	"strings"
)

type ScopePolicy struct {
	AllowedScopes map[string]bool
	Strict        bool
}

type ScopeGate struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type ScopePosture struct {
	AllowedScopes   []string    `json:"allowed_scopes"`
	Strict          bool        `json:"strict"`
	DescriptorCount int         `json:"descriptor_count"`
	OutOfScopeCount int         `json:"out_of_scope_count"`
	Gates           []ScopeGate `json:"gates"`
	GateCount       int         `json:"gate_count"`
	ValueReturned   bool        `json:"value_returned"`
}

func LoadScopePolicyFromEnv() ScopePolicy {
	return ScopePolicy{
		AllowedScopes: splitSet(envDefault("JANUS_ALLOWED_SCOPES", "csb1")),
		Strict:        envBoolDefault("JANUS_SCOPE_STRICT", true),
	}
}

func (p ScopePolicy) Allows(scope string) bool {
	if !p.Strict {
		return true
	}
	if len(p.AllowedScopes) == 0 {
		return false
	}
	return p.AllowedScopes[normalizeScope(scope)]
}

func (p ScopePolicy) Filter(descriptors []SecretDescriptor) []SecretDescriptor {
	out := make([]SecretDescriptor, 0, len(descriptors))
	for _, desc := range descriptors {
		if p.Allows(desc.Scope) {
			out = append(out, desc)
		}
	}
	return out
}

func ScopePostureFor(policy ScopePolicy, descriptors []SecretDescriptor) ScopePosture {
	outOfScope := 0
	for _, desc := range descriptors {
		if !policy.Allows(desc.Scope) {
			outOfScope++
		}
	}

	gates := []ScopeGate{}
	if policy.Strict && len(policy.AllowedScopes) == 0 {
		gates = append(gates, ScopeGate{
			Severity: "high",
			Code:     "no_allowed_scopes",
			Message:  "Strict scope mode has no allowed scopes configured.",
		})
	}
	if outOfScope > 0 {
		gates = append(gates, ScopeGate{
			Severity: "high",
			Code:     "out_of_scope_descriptors",
			Message:  "One or more descriptors are outside the active Janus scope allowlist.",
		})
	}

	return ScopePosture{
		AllowedScopes:   policy.AllowedScopeList(),
		Strict:          policy.Strict,
		DescriptorCount: len(descriptors),
		OutOfScopeCount: outOfScope,
		Gates:           gates,
		GateCount:       len(gates),
		ValueReturned:   false,
	}
}

func (p ScopePolicy) AllowedScopeList() []string {
	out := make([]string, 0, len(p.AllowedScopes))
	for scope := range p.AllowedScopes {
		out = append(out, scope)
	}
	sort.Strings(out)
	return out
}

func normalizeScope(scope string) string {
	return strings.ToLower(strings.TrimSpace(scope))
}
