package main

import (
	"sort"
	"strings"
)

const (
	RoleAdmin    = "admin"
	RoleAuditor  = "auditor"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

type RolePolicy struct {
	AdminSubjects    map[string]bool
	AuditorSubjects  map[string]bool
	OperatorSubjects map[string]bool
	AdminGroups      map[string]bool
	AuditorGroups    map[string]bool
	OperatorGroups   map[string]bool
	BootstrapOwner   bool
}

type AccessGate struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type AccessPosture struct {
	ExplicitBindings bool              `json:"explicit_bindings"`
	BootstrapOwner   bool              `json:"bootstrap_owner"`
	KnownRoles       []string          `json:"known_roles"`
	RequiredRoles    map[string]string `json:"required_roles"`
	Gates            []AccessGate      `json:"gates"`
	GateCount        int               `json:"gate_count"`
	ValueReturned    bool              `json:"value_returned"`
}

func LoadRolePolicyFromEnv() RolePolicy {
	return RolePolicy{
		AdminSubjects:    splitSet(envDefault("JANUS_ADMIN_SUBJECTS", "")),
		AuditorSubjects:  splitSet(envDefault("JANUS_AUDITOR_SUBJECTS", "")),
		OperatorSubjects: splitSet(envDefault("JANUS_OPERATOR_SUBJECTS", "")),
		AdminGroups:      splitSet(envDefault("JANUS_ADMIN_GROUPS", "")),
		AuditorGroups:    splitSet(envDefault("JANUS_AUDITOR_GROUPS", "")),
		OperatorGroups:   splitSet(envDefault("JANUS_OPERATOR_GROUPS", "")),
		BootstrapOwner:   envBoolDefault("JANUS_BOOTSTRAP_OWNER", true),
	}
}

func (p RolePolicy) Configured() bool {
	return len(p.AdminSubjects)+len(p.AuditorSubjects)+len(p.OperatorSubjects)+
		len(p.AdminGroups)+len(p.AuditorGroups)+len(p.OperatorGroups) > 0
}

func DeriveRoles(subject, email string, claimValues []string, policy RolePolicy) []string {
	if strings.TrimSpace(subject) == "" {
		return nil
	}

	roles := map[string]bool{RoleViewer: true}
	subjectKey := normalizeRoleToken(subject)
	emailKey := normalizeRoleToken(email)

	if policy.AdminSubjects[subjectKey] || policy.AdminSubjects[emailKey] {
		roles[RoleAdmin] = true
	}
	if policy.AuditorSubjects[subjectKey] || policy.AuditorSubjects[emailKey] {
		roles[RoleAuditor] = true
	}
	if policy.OperatorSubjects[subjectKey] || policy.OperatorSubjects[emailKey] {
		roles[RoleOperator] = true
	}

	for _, value := range claimValues {
		key := normalizeRoleToken(value)
		switch {
		case policy.AdminGroups[key] || key == "janus:admin" || key == "janus_admin" || key == "janus-admin":
			roles[RoleAdmin] = true
		case policy.AuditorGroups[key] || key == "janus:auditor" || key == "janus_auditor" || key == "janus-auditor":
			roles[RoleAuditor] = true
		case policy.OperatorGroups[key] || key == "janus:operator" || key == "janus_operator" || key == "janus-operator":
			roles[RoleOperator] = true
		}
	}

	if !policy.Configured() && policy.BootstrapOwner {
		roles[RoleAdmin] = true
		roles[RoleAuditor] = true
		roles[RoleOperator] = true
	}

	return sortedRoles(roles)
}

func HasRole(session Session, role string) bool {
	for _, got := range session.Roles {
		if got == role {
			return true
		}
	}
	return false
}

func AllRoles() []string {
	return []string{RoleAdmin, RoleAuditor, RoleOperator, RoleViewer}
}

func AccessPostureFor(policy RolePolicy) AccessPosture {
	gates := []AccessGate{}
	if !policy.Configured() {
		message := "Explicit Janus role bindings are not configured; sensitive APIs deny without matching roles."
		if policy.BootstrapOwner {
			message = "Explicit Janus role bindings are not configured; self-hosted bootstrap grants authenticated users all V1 roles."
		}
		gates = append(gates, AccessGate{
			Severity: "medium",
			Code:     "bootstrap_role_policy",
			Message:  message,
		})
	}

	return AccessPosture{
		ExplicitBindings: policy.Configured(),
		BootstrapOwner:   !policy.Configured() && policy.BootstrapOwner,
		KnownRoles:       AllRoles(),
		RequiredRoles: map[string]string{
			"/api/audit/recent": RoleAuditor,
			"/api/evidence":     RoleAuditor,
		},
		Gates:         gates,
		GateCount:     len(gates),
		ValueReturned: false,
	}
}

func ClaimRoleInputs(groups, roles []string, projectRoles map[string]any) []string {
	values := make([]string, 0, len(groups)+len(roles)+len(projectRoles))
	values = append(values, groups...)
	values = append(values, roles...)
	for key, value := range projectRoles {
		values = append(values, key)
		values = appendClaimValue(values, value)
	}
	return values
}

func splitSet(raw string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		if key := normalizeRoleToken(part); key != "" {
			out[key] = true
		}
	}
	return out
}

func normalizeRoleToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func sortedRoles(roles map[string]bool) []string {
	out := make([]string, 0, len(roles))
	for role := range roles {
		out = append(out, role)
	}
	sort.Strings(out)
	return out
}

func appendClaimValue(values []string, value any) []string {
	switch typed := value.(type) {
	case string:
		return append(values, typed)
	case []any:
		for _, item := range typed {
			values = appendClaimValue(values, item)
		}
	case map[string]any:
		for key, item := range typed {
			values = append(values, key)
			values = appendClaimValue(values, item)
		}
	}
	return values
}
