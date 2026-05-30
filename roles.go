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
	RoleDutyMatrix   bool              `json:"role_duty_matrix"`
	DutyModel        string            `json:"duty_model"`
	Gates            []AccessGate      `json:"gates"`
	GateCount        int               `json:"gate_count"`
	ValueReturned    bool              `json:"value_returned"`
}

type RoleBoundary struct {
	Role    string
	Duty    string
	Allowed string
	Blocked string
	Active  bool
}

type RoleAvailability struct {
	Label  string
	State  string
	Detail string
	Tone   string
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
			"/api/audit/recent":          RoleAuditor,
			"/api/evidence":              RoleAuditor,
			"POST /api/warden/resolve":   RoleOperator,
			"POST /api/permits":          RoleOperator,
			"POST /api/permits/{id}/run": RoleOperator,
		},
		RoleDutyMatrix: true,
		DutyModel:      "separated_admin_auditor_operator_viewer",
		Gates:          gates,
		GateCount:      len(gates),
		ValueReturned:  false,
	}
}

func RoleBoundariesFor(session Session) []RoleBoundary {
	return []RoleBoundary{
		{
			Role:    RoleAdmin,
			Duty:    "Policy and ownership",
			Allowed: "Review role policy and future admin approvals.",
			Blocked: "Does not bypass audit, approval, or value-return rules.",
			Active:  HasRole(session, RoleAdmin),
		},
		{
			Role:    RoleAuditor,
			Duty:    "Evidence and audit",
			Allowed: "View audit events and export evidence.",
			Blocked: "No handle, permit, or access-broadening controls.",
			Active:  HasRole(session, RoleAuditor),
		},
		{
			Role:    RoleOperator,
			Duty:    "Approved use",
			Allowed: "Request metadata handles and permit safety checks.",
			Blocked: "No evidence export or role-policy changes.",
			Active:  HasRole(session, RoleOperator),
		},
		{
			Role:    RoleViewer,
			Duty:    "Posture only",
			Allowed: "Read safe posture and descriptor metadata.",
			Blocked: "No secret-use, audit export, or admin controls.",
			Active:  HasRole(session, RoleViewer),
		},
	}
}

func RoleAvailabilityFor(session Session) []RoleAvailability {
	operator := HasRole(session, RoleOperator)
	auditor := HasRole(session, RoleAuditor)
	admin := HasRole(session, RoleAdmin)
	return []RoleAvailability{
		{
			Label:  "Posture",
			State:  "available",
			Detail: "Safe posture and descriptor views are available.",
			Tone:   "ok",
		},
		{
			Label:  "Use actions",
			State:  availabilityState(operator),
			Detail: availabilityDetail(operator, "Handle and permit controls are available.", "Operator role required."),
			Tone:   availabilityTone(operator),
		},
		{
			Label:  "Audit export",
			State:  availabilityState(auditor),
			Detail: availabilityDetail(auditor, "Audit rows and evidence export are available.", "Auditor role required."),
			Tone:   availabilityTone(auditor),
		},
		{
			Label:  "Admin policy",
			State:  availabilityState(admin),
			Detail: availabilityDetail(admin, "Admin policy review is available.", "Admin role required."),
			Tone:   availabilityTone(admin),
		},
	}
}

func ActionReadinessFor(session Session, ready bool) ActionReadiness {
	matrix := ActionReadiness{
		Summary:       "Action readiness shows what this session can safely do, what is role-gated, and what waits for readiness.",
		ValueReturned: false,
	}
	matrix.add(ActionReadinessItem{
		Key:           "posture_view",
		Label:         "Posture view",
		State:         "available",
		RequiredRole:  RoleViewer,
		Reason:        "Safe metadata posture is available to every signed-in viewer.",
		Next:          "Use posture to understand health, gates, and value boundaries.",
		Safety:        "Read-only and value-free.",
		ValueReturned: false,
		Tone:          "ok",
	})
	matrix.add(actionReadinessItem(session, ready, "evidence_export", "Evidence export", RoleAuditor, true, "Auditor role can download value-free evidence JSON.", "Use an auditor session to export evidence.", "Role-gated, readiness-gated, and value-free."))
	matrix.add(actionReadinessItem(session, ready, "handle_issue", "Issue metadata handle", RoleOperator, true, "Operator role can issue metadata-only handles.", "Use an operator session after readiness is healthy.", "Never reveals a secret value."))
	matrix.add(actionReadinessItem(session, ready, "permit_create", "Create permit", RoleOperator, true, "Operator role can create metadata-only permits.", "Use an operator session after readiness is healthy.", "Permit records are durable and value-free."))
	matrix.add(actionReadinessItem(session, ready, "permit_run_check", "Run permit check", RoleOperator, true, "Operator role can run a no-connector safety check.", "Use an operator session after readiness is healthy.", "No connector executes and output is scrubbed."))
	matrix.add(actionReadinessItem(session, true, "admin_policy_review", "Admin policy review", RoleAdmin, false, "Admin role can review ownership and role policy posture.", "Use an admin session to review policy posture.", "Does not bypass audit, approval, or value-return rules."))
	return matrix
}

func actionReadinessItem(session Session, ready bool, key, label, role string, readinessGated bool, availableReason, roleNext, safety string) ActionReadinessItem {
	item := ActionReadinessItem{
		Key:           key,
		Label:         label,
		State:         "available",
		RequiredRole:  role,
		Reason:        availableReason,
		Next:          "Use the available dashboard or API action.",
		Safety:        safety,
		ValueReturned: false,
		Tone:          "ok",
	}
	if !HasRole(session, role) {
		item.State = "role_gated"
		item.Reason = role + " role required."
		item.Next = roleNext
		item.Tone = "warn"
		return item
	}
	if readinessGated && !ready {
		item.State = "readiness_blocked"
		item.Reason = "Readiness is degraded, so sensitive actions fail closed."
		item.Next = "Recover readiness before using this action."
		item.Tone = "warn"
		return item
	}
	return item
}

func (r *ActionReadiness) add(item ActionReadinessItem) {
	switch item.State {
	case "available":
		r.Available++
	case "readiness_blocked":
		r.Blocked++
	default:
		r.Gated++
	}
	r.Actions = append(r.Actions, item)
}

func availabilityState(allowed bool) string {
	if allowed {
		return "available"
	}
	return "blocked"
}

func availabilityTone(allowed bool) string {
	if allowed {
		return "ok"
	}
	return "warn"
}

func availabilityDetail(allowed bool, yes, no string) string {
	if allowed {
		return yes
	}
	return no
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
