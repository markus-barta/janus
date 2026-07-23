package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	RoleViewer          = "viewer"
	RoleOperator        = "operator"
	RoleOwner           = "owner"
	RoleApprover        = "approver"
	RoleAuditor         = "auditor"
	RoleSecurityAdmin   = "security_admin"
	RoleBreakGlassAdmin = "break_glass_admin"
	RoleServiceAdmin    = "service_admin"
	RoleWorkloadAdmin   = "workload_admin"

	zitadelProjectRolesClaim       = "urn:zitadel:iam:org:project:roles"
	zitadelProjectRolesClaimPrefix = "urn:zitadel:iam:org:project:"
	zitadelProjectRolesClaimSuffix = ":roles"
)

type RolePolicy struct {
	ViewerSubjects          map[string]bool
	OwnerSubjects           map[string]bool
	ApproverSubjects        map[string]bool
	AuditorSubjects         map[string]bool
	OperatorSubjects        map[string]bool
	SecurityAdminSubjects   map[string]bool
	BreakGlassAdminSubjects map[string]bool
	ServiceAdminSubjects    map[string]bool
	WorkloadAdminSubjects   map[string]bool
	ViewerGroups            map[string]bool
	OwnerGroups             map[string]bool
	ApproverGroups          map[string]bool
	AuditorGroups           map[string]bool
	OperatorGroups          map[string]bool
	SecurityAdminGroups     map[string]bool
	BreakGlassAdminGroups   map[string]bool
	ServiceAdminGroups      map[string]bool
	WorkloadAdminGroups     map[string]bool

	BootstrapOwner bool
}

type AccessGate struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

type AccessPosture struct {
	ExplicitBindings       bool                `json:"explicit_bindings"`
	BootstrapOwner         bool                `json:"bootstrap_owner"`
	KnownRoles             []string            `json:"known_roles"`
	RequiredRoles          map[string]string   `json:"required_roles"`
	RoleDutyMatrix         bool                `json:"role_duty_matrix"`
	DutyModel              string              `json:"duty_model"`
	ClaimPolicy            string              `json:"claim_policy"`
	ImplicitElevatedClaims bool                `json:"implicit_elevated_claims"`
	SubjectBindingCount    int                 `json:"subject_binding_count"`
	GroupBindingCount      int                 `json:"group_binding_count"`
	ElevatedBindingCount   int                 `json:"elevated_binding_count"`
	BindingSources         []RoleBindingSource `json:"binding_sources"`
	Gates                  []AccessGate        `json:"gates"`
	GateCount              int                 `json:"gate_count"`
	ValueReturned          bool                `json:"value_returned"`
}

type RoleBindingSource struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	State         string `json:"state"`
	Count         int    `json:"count"`
	Detail        string `json:"detail"`
	Tone          string `json:"tone"`
	ValueReturned bool   `json:"value_returned"`
}

type RoleBoundary struct {
	Role    string
	Duty    string
	Allowed string
	Blocked string
	Active  bool
}

type RouteGateView struct {
	Route          string
	RequiredRole   string
	SessionState   string
	SessionTone    string
	State          string
	Tone           string
	ReadinessGated bool
}

type accessRouteDefinition struct {
	Route          string
	RequiredRole   string
	ReadinessGated bool
}

var accessProtectedRoutes = []accessRouteDefinition{
	{Route: "POST /api/warden/resolve", RequiredRole: RoleOperator, ReadinessGated: true},
	{Route: "POST /api/permits", RequiredRole: RoleOperator, ReadinessGated: true},
	{Route: "POST /api/permits/{permitID}/run", RequiredRole: RoleOperator, ReadinessGated: true},
	{Route: "GET /vault/new/plan.sh", RequiredRole: RoleOperator, ReadinessGated: false},
	{Route: "GET /api/audit/recent", RequiredRole: RoleAuditor, ReadinessGated: false},
	{Route: "GET /api/evidence", RequiredRole: RoleAuditor, ReadinessGated: true},
}

type AccessSessionGateView struct {
	Label string
	State string
	Tone  string
}

type AccessRoleLaneView struct {
	Key           string
	Label         string
	SessionState  string
	SessionTone   string
	BindingLabel  string
	Scope         string
	SubjectLabel  string
	GroupLabel    string
	ServiceLabel  string
	GateLabel     string
	GateTone      string
	Readiness     string
	ReadinessTone string
	ValueReturned bool
}

type RoleAvailability struct {
	Label  string
	State  string
	Detail string
	Tone   string
}

type RoleWorkbench struct {
	Summary       string
	Available     []RoleWorkbenchItem
	Hidden        []RoleWorkbenchItem
	ValueReturned bool
}

type RoleWorkbenchItem struct {
	Key    string
	Label  string
	State  string
	Detail string
	Next   string
	Tone   string
}

type RolePolicyReadiness struct {
	Label                 string           `json:"label"`
	Summary               string           `json:"summary"`
	Status                string           `json:"status"`
	Ready                 bool             `json:"ready"`
	BootstrapOwnerState   string           `json:"bootstrap_owner_state"`
	BootstrapOwnerBlocked bool             `json:"bootstrap_owner_blocked"`
	ExplicitBindings      bool             `json:"explicit_bindings"`
	ReadyLanes            int              `json:"ready_lanes"`
	MissingLanes          int              `json:"missing_lanes"`
	TotalLanes            int              `json:"total_lanes"`
	EvidenceSignal        string           `json:"evidence_signal"`
	Next                  string           `json:"next"`
	Lanes                 []RolePolicyLane `json:"lanes"`
	Steps                 []RolePolicyStep `json:"steps"`
	SubjectValuesReturned bool             `json:"subject_values_returned"`
	GroupValuesReturned   bool             `json:"group_values_returned"`
	ClaimValuesReturned   bool             `json:"claim_values_returned"`
	EnvValuesReturned     bool             `json:"env_values_returned"`
	BackendPathReturned   bool             `json:"backend_path_returned"`
	TokenReturned         bool             `json:"token_returned"`
	ValueReturned         bool             `json:"value_returned"`
}

type RolePolicyLane struct {
	Key                      string `json:"key"`
	Label                    string `json:"label"`
	Role                     string `json:"role"`
	State                    string `json:"state"`
	Ready                    bool   `json:"ready"`
	Required                 bool   `json:"required"`
	SubjectBindingConfigured bool   `json:"subject_binding_configured"`
	GroupBindingConfigured   bool   `json:"group_binding_configured"`
	SubjectBindingCount      int    `json:"subject_binding_count"`
	GroupBindingCount        int    `json:"group_binding_count"`
	BindingCount             int    `json:"binding_count"`
	Detail                   string `json:"detail"`
	Next                     string `json:"next"`
	Tone                     string `json:"tone"`
	SubjectValuesReturned    bool   `json:"subject_values_returned"`
	GroupValuesReturned      bool   `json:"group_values_returned"`
	ClaimValuesReturned      bool   `json:"claim_values_returned"`
	ValueReturned            bool   `json:"value_returned"`
}

type RolePolicyStep struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	State         string `json:"state"`
	OwnerRole     string `json:"owner_role"`
	Detail        string `json:"detail"`
	Next          string `json:"next"`
	Tone          string `json:"tone"`
	ValueReturned bool   `json:"value_returned"`
}

type SessionRoleEvidence struct {
	Label                  string                  `json:"label"`
	Summary                string                  `json:"summary"`
	State                  string                  `json:"state"`
	AuthMode               string                  `json:"auth_mode"`
	IdentityProvider       string                  `json:"identity_provider"`
	IdentityLabel          string                  `json:"identity_label"`
	IdentityBoundary       string                  `json:"identity_boundary"`
	ActiveRoleCount        int                     `json:"active_role_count"`
	TotalRoleCount         int                     `json:"total_role_count"`
	EvidenceSignal         string                  `json:"evidence_signal"`
	Next                   string                  `json:"next"`
	Roles                  []SessionRoleSignal     `json:"roles"`
	Gates                  []SessionRoleGateSignal `json:"gates"`
	IdentityValuesReturned bool                    `json:"identity_values_returned"`
	SubjectReturned        bool                    `json:"subject_returned"`
	EmailReturned          bool                    `json:"email_returned"`
	NameReturned           bool                    `json:"name_returned"`
	ClaimValuesReturned    bool                    `json:"claim_values_returned"`
	GroupValuesReturned    bool                    `json:"group_values_returned"`
	TokenReturned          bool                    `json:"token_returned"`
	CookieValueReturned    bool                    `json:"cookie_value_returned"`
	RequestBodyReturned    bool                    `json:"request_body_returned"`
	EnvValuesReturned      bool                    `json:"env_values_returned"`
	BackendPathReturned    bool                    `json:"backend_path_returned"`
	ValueReturned          bool                    `json:"value_returned"`
}

type SessionRoleSignal struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	Role          string `json:"role"`
	State         string `json:"state"`
	Active        bool   `json:"active"`
	Detail        string `json:"detail"`
	Tone          string `json:"tone"`
	ValueReturned bool   `json:"value_returned"`
}

type SessionRoleGateSignal struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	State         string `json:"state"`
	RequiredRole  string `json:"required_role"`
	Detail        string `json:"detail"`
	Next          string `json:"next"`
	Tone          string `json:"tone"`
	ValueReturned bool   `json:"value_returned"`
}

func LoadRolePolicyFromEnv() RolePolicy {
	return RolePolicy{
		ViewerSubjects:          splitSet(envDefault("JANUS_VIEWER_SUBJECTS", "")),
		OwnerSubjects:           splitSet(envDefault("JANUS_OWNER_SUBJECTS", "")),
		ApproverSubjects:        splitSet(envDefault("JANUS_APPROVER_SUBJECTS", "")),
		AuditorSubjects:         splitSet(envDefault("JANUS_AUDITOR_SUBJECTS", "")),
		OperatorSubjects:        splitSet(envDefault("JANUS_OPERATOR_SUBJECTS", "")),
		SecurityAdminSubjects:   splitSet(envDefault("JANUS_SECURITY_ADMIN_SUBJECTS", "")),
		BreakGlassAdminSubjects: splitSet(envDefault("JANUS_BREAK_GLASS_ADMIN_SUBJECTS", "")),
		ServiceAdminSubjects:    splitSet(envDefault("JANUS_SERVICE_ADMIN_SUBJECTS", "")),
		WorkloadAdminSubjects:   splitSet(envDefault("JANUS_WORKLOAD_ADMIN_SUBJECTS", "")),
		ViewerGroups:            splitSet(envDefault("JANUS_VIEWER_GROUPS", "")),
		OwnerGroups:             splitSet(envDefault("JANUS_OWNER_GROUPS", "")),
		ApproverGroups:          splitSet(envDefault("JANUS_APPROVER_GROUPS", "")),
		AuditorGroups:           splitSet(envDefault("JANUS_AUDITOR_GROUPS", "")),
		OperatorGroups:          splitSet(envDefault("JANUS_OPERATOR_GROUPS", "")),
		SecurityAdminGroups:     splitSet(envDefault("JANUS_SECURITY_ADMIN_GROUPS", "")),
		BreakGlassAdminGroups:   splitSet(envDefault("JANUS_BREAK_GLASS_ADMIN_GROUPS", "")),
		ServiceAdminGroups:      splitSet(envDefault("JANUS_SERVICE_ADMIN_GROUPS", "")),
		WorkloadAdminGroups:     splitSet(envDefault("JANUS_WORKLOAD_ADMIN_GROUPS", "")),
		BootstrapOwner:          envBoolDefault("JANUS_UNSAFE_BOOTSTRAP_OWNER", false),
	}
}

func (p RolePolicy) Configured() bool {
	return roleSubjectBindingCount(p)+roleGroupBindingCount(p) > 0
}

func DeriveRoles(subject, email string, claimValues []string, policy RolePolicy) []string {
	roles, err := DeriveRolesChecked(subject, email, claimValues, policy)
	if err != nil {
		return nil
	}
	return roles
}

// DeriveRolesChecked projects only exact reviewed subject/email and group
// bindings. An identity with no binding receives no role. Any explicit role
// match carries the viewer baseline, while duplicate claims and a single
// identity value mapped to multiple elevated roles fail closed without
// returning the value.
func DeriveRolesChecked(subject, email string, claimValues []string, policy RolePolicy) ([]string, error) {
	if strings.TrimSpace(subject) == "" {
		return nil, nil
	}

	roles := map[string]bool{}
	identityKeys := []string{normalizeRoleToken(subject)}
	if emailKey := normalizeRoleToken(email); emailKey != "" && emailKey != identityKeys[0] {
		identityKeys = append(identityKeys, emailKey)
	}
	for _, key := range identityKeys {
		matches := matchingRoles(key, policy, false)
		if ambiguousRoleMatches(matches) {
			return nil, fmt.Errorf("ambiguous exact subject role binding")
		}
		for _, role := range matches {
			roles[role] = true
		}
	}

	seenClaims := map[string]bool{}
	for _, value := range claimValues {
		key := normalizeRoleToken(value)
		if key == "" {
			continue
		}
		if seenClaims[key] {
			return nil, fmt.Errorf("duplicate role claim")
		}
		seenClaims[key] = true
		matches := matchingRoles(key, policy, true)
		if ambiguousRoleMatches(matches) {
			return nil, fmt.Errorf("ambiguous exact group role binding")
		}
		for _, role := range matches {
			roles[role] = true
		}
	}
	if len(roles) > 0 {
		roles[RoleViewer] = true
	}
	return sortedRoles(roles), nil
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
	return []string{
		RoleViewer,
		RoleOperator,
		RoleOwner,
		RoleApprover,
		RoleAuditor,
		RoleSecurityAdmin,
		RoleBreakGlassAdmin,
		RoleServiceAdmin,
		RoleWorkloadAdmin,
	}
}

func matchingRoles(key string, policy RolePolicy, groups bool) []string {
	matches := []string{}
	for _, role := range AllRoles() {
		bindings := roleSubjects(policy, role)
		if groups {
			bindings = roleGroups(policy, role)
		}
		if bindings[key] {
			matches = append(matches, role)
		}
	}
	return matches
}

func ambiguousRoleMatches(matches []string) bool {
	elevated := 0
	for _, role := range matches {
		if role != RoleViewer {
			elevated++
		}
	}
	return elevated > 1
}

func roleSubjects(policy RolePolicy, role string) map[string]bool {
	switch role {
	case RoleViewer:
		return policy.ViewerSubjects
	case RoleOwner:
		return policy.OwnerSubjects
	case RoleApprover:
		return policy.ApproverSubjects
	case RoleAuditor:
		return policy.AuditorSubjects
	case RoleOperator:
		return policy.OperatorSubjects
	case RoleSecurityAdmin:
		return policy.SecurityAdminSubjects
	case RoleBreakGlassAdmin:
		return policy.BreakGlassAdminSubjects
	case RoleServiceAdmin:
		return policy.ServiceAdminSubjects
	case RoleWorkloadAdmin:
		return policy.WorkloadAdminSubjects
	default:
		return nil
	}
}

func roleGroups(policy RolePolicy, role string) map[string]bool {
	switch role {
	case RoleViewer:
		return policy.ViewerGroups
	case RoleOwner:
		return policy.OwnerGroups
	case RoleApprover:
		return policy.ApproverGroups
	case RoleAuditor:
		return policy.AuditorGroups
	case RoleOperator:
		return policy.OperatorGroups
	case RoleSecurityAdmin:
		return policy.SecurityAdminGroups
	case RoleBreakGlassAdmin:
		return policy.BreakGlassAdminGroups
	case RoleServiceAdmin:
		return policy.ServiceAdminGroups
	case RoleWorkloadAdmin:
		return policy.WorkloadAdminGroups
	default:
		return nil
	}
}

func AccessPostureFor(policy RolePolicy) AccessPosture {
	gates := []AccessGate{}
	explicit := policy.Configured()
	subjectCount := roleSubjectBindingCount(policy)
	groupCount := roleGroupBindingCount(policy)
	if !explicit {
		message := "Explicit Janus role bindings are not configured; sensitive APIs deny without matching roles."
		if policy.BootstrapOwner {
			message = "Legacy bootstrap owner is configured but grants no role; exact bindings are required."
		}
		gates = append(gates, AccessGate{
			Severity: "medium",
			Code:     "bootstrap_role_policy",
			Message:  message,
		})
	}

	requiredRoles := make(map[string]string, len(accessProtectedRoutes))
	for _, definition := range accessProtectedRoutes {
		requiredRoles[definition.Route] = definition.RequiredRole
	}

	return AccessPosture{
		ExplicitBindings:       explicit,
		BootstrapOwner:         policy.BootstrapOwner,
		KnownRoles:             AllRoles(),
		ClaimPolicy:            "explicit_only",
		ImplicitElevatedClaims: false,
		SubjectBindingCount:    subjectCount,
		GroupBindingCount:      groupCount,
		ElevatedBindingCount:   elevatedRoleSubjectBindingCount(policy) + elevatedRoleGroupBindingCount(policy),
		BindingSources:         RoleBindingSourcesFor(policy),
		RequiredRoles:          requiredRoles,
		RoleDutyMatrix:         true,
		DutyModel:              "shared_v1_roles_with_hard_separation",
		Gates:                  gates,
		GateCount:              len(gates),
		ValueReturned:          false,
	}
}

func RoleBindingSourcesFor(policy RolePolicy) []RoleBindingSource {
	subjectCount := roleSubjectBindingCount(policy)
	groupCount := roleGroupBindingCount(policy)
	sources := []RoleBindingSource{
		{
			Key:           "subject_bindings",
			Label:         "Subject bindings",
			State:         configuredState(subjectCount),
			Count:         subjectCount,
			Detail:        "Subject bindings may grant elevated roles; subject and email values are not returned.",
			Tone:          configuredTone(subjectCount),
			ValueReturned: false,
		},
		{
			Key:           "group_claim_bindings",
			Label:         "Group claim bindings",
			State:         configuredState(groupCount),
			Count:         groupCount,
			Detail:        "OIDC group and role claims grant elevated roles only when they match configured policy.",
			Tone:          configuredTone(groupCount),
			ValueReturned: false,
		},
		{
			Key:           "implicit_elevated_claims",
			Label:         "Implicit elevated claims",
			State:         "disabled",
			Count:         0,
			Detail:        "Claim names are not trusted by convention; every elevated claim needs an explicit binding.",
			Tone:          "ok",
			ValueReturned: false,
		},
	}
	bootstrap := RoleBindingSource{
		Key:           "bootstrap_owner",
		Label:         "Bootstrap owner",
		State:         "off",
		Count:         0,
		Detail:        "Bootstrap owner is off; elevated roles require explicit policy.",
		Tone:          "ok",
		ValueReturned: false,
	}
	if policy.BootstrapOwner {
		bootstrap.State = "blocked_legacy"
		bootstrap.Detail = "Legacy bootstrap owner is ignored; exact subject or group bindings are mandatory."
		bootstrap.Tone = "warn"
	}
	return append(sources, bootstrap)
}

func RolePolicyReadinessFor(policy RolePolicy, access AccessPosture) RolePolicyReadiness {
	lanes := []RolePolicyLane{
		rolePolicyLane(RoleOperator, "Operator lane", roleSubjects(policy, RoleOperator), roleGroups(policy, RoleOperator)),
		rolePolicyLane(RoleOwner, "Owner lane", roleSubjects(policy, RoleOwner), roleGroups(policy, RoleOwner)),
		rolePolicyLane(RoleApprover, "Approver lane", roleSubjects(policy, RoleApprover), roleGroups(policy, RoleApprover)),
		rolePolicyLane(RoleAuditor, "Auditor lane", roleSubjects(policy, RoleAuditor), roleGroups(policy, RoleAuditor)),
		rolePolicyLane(RoleSecurityAdmin, "Security admin lane", roleSubjects(policy, RoleSecurityAdmin), roleGroups(policy, RoleSecurityAdmin)),
		rolePolicyLane(RoleBreakGlassAdmin, "Break-glass eligibility lane", roleSubjects(policy, RoleBreakGlassAdmin), roleGroups(policy, RoleBreakGlassAdmin)),
		rolePolicyLane(RoleServiceAdmin, "Service admin lane", roleSubjects(policy, RoleServiceAdmin), roleGroups(policy, RoleServiceAdmin)),
		rolePolicyLane(RoleWorkloadAdmin, "Workload admin lane", roleSubjects(policy, RoleWorkloadAdmin), roleGroups(policy, RoleWorkloadAdmin)),
	}
	readyLanes := 0
	for _, lane := range lanes {
		if lane.Ready {
			readyLanes++
		}
	}
	missingLanes := len(lanes) - readyLanes

	bootstrapState := "off"
	bootstrapBlocked := false
	bootstrapDetail := "Bootstrap owner is off; elevated roles require explicit Zitadel policy."
	bootstrapNext := "Keep bootstrap owner off and maintain explicit role owner review."
	bootstrapTone := "ok"
	if policy.BootstrapOwner {
		bootstrapState = "blocked_legacy"
		bootstrapBlocked = true
		bootstrapDetail = "Legacy bootstrap owner is ignored and must be removed."
		bootstrapNext = "Remove JANUS_UNSAFE_BOOTSTRAP_OWNER and keep exact role bindings."
		bootstrapTone = "warn"
	}

	ready := missingLanes == 0 && !bootstrapBlocked && !access.ValueReturned
	status := "ready"
	summary := "Role policy has exact bindings for every shared elevated role; bootstrap owner is off."
	next := "Keep owner review current and leave evidence value-free."
	if !ready {
		status = "blocked"
		summary = "Role policy is not ready because a shared role lane is missing or legacy bootstrap is configured."
		next = "Bind each missing elevated role lane to a Zitadel subject or group, then close bootstrap."
	} else if policy.BootstrapOwner {
		summary = "Role policy lanes are explicit, but legacy bootstrap configuration is still forbidden."
		next = "Remove legacy bootstrap configuration."
	}

	readiness := RolePolicyReadiness{
		Label:                 "Role policy readiness",
		Summary:               summary,
		Status:                status,
		Ready:                 ready,
		BootstrapOwnerState:   bootstrapState,
		BootstrapOwnerBlocked: bootstrapBlocked,
		ExplicitBindings:      access.ExplicitBindings,
		ReadyLanes:            readyLanes,
		MissingLanes:          missingLanes,
		TotalLanes:            len(lanes),
		EvidenceSignal:        "bootstrap_to_explicit_zitadel_lanes",
		Next:                  next,
		Lanes:                 lanes,
		SubjectValuesReturned: false,
		GroupValuesReturned:   false,
		ClaimValuesReturned:   false,
		EnvValuesReturned:     false,
		BackendPathReturned:   false,
		TokenReturned:         false,
		ValueReturned:         false,
	}
	readiness.Steps = []RolePolicyStep{
		{
			Key:           "bootstrap_owner",
			Label:         "Bootstrap owner",
			State:         bootstrapState,
			OwnerRole:     RoleSecurityAdmin,
			Detail:        bootstrapDetail,
			Next:          bootstrapNext,
			Tone:          bootstrapTone,
			ValueReturned: false,
		},
		{
			Key:           "zitadel_lanes",
			Label:         "Zitadel role lanes",
			State:         laneSetupState(missingLanes),
			OwnerRole:     RoleSecurityAdmin,
			Detail:        "Every shared elevated role needs at least one exact subject or group binding.",
			Next:          laneSetupNext(missingLanes),
			Tone:          laneSetupTone(missingLanes),
			ValueReturned: false,
		},
		{
			Key:           "value_boundary",
			Label:         "Value boundary",
			State:         "enforced",
			OwnerRole:     RoleAuditor,
			Detail:        "Readiness returns counts and yes/no states only; no subject, group, claim, token, env, or backend values.",
			Next:          "Use posture and evidence for review without copying identity or secret values.",
			Tone:          "ok",
			ValueReturned: false,
		},
	}
	return readiness
}

func SessionRoleEvidenceFor(session Session, requireAuth, oidcConfigured, ready bool) SessionRoleEvidence {
	state := "signed_in"
	authMode := "zitadel_oidc"
	identityProvider := "zitadel_oidc"
	summary := "Signed-in session is recognized through Zitadel; Janus returns only role and gate state, not identity claim values."
	if !requireAuth {
		state = "local_auth_disabled"
		authMode = "local_dev"
		identityProvider = "local_dev"
		summary = "Local smoke session is active; Janus returns only role and gate state, not identity claim values."
	} else if !oidcConfigured {
		state = "setup_only"
		authMode = "setup_only"
		summary = "Auth is required but setup is incomplete; Janus keeps identity values outside the response."
	} else if strings.TrimSpace(session.Subject) == "" {
		state = "missing"
		summary = "No signed-in session is active."
	}

	evidence := SessionRoleEvidence{
		Label:                  "Signed-in role receipt",
		Summary:                summary,
		State:                  state,
		AuthMode:               authMode,
		IdentityProvider:       identityProvider,
		IdentityLabel:          "Signed in",
		IdentityBoundary:       "identity_claim_values_withheld",
		TotalRoleCount:         len(AllRoles()),
		EvidenceSignal:         "signed_in_role_receipt_no_identity_values",
		Next:                   "Use the role gates below; keep identity, group, claim, token, cookie, env, backend path, and request-body values outside Janus evidence.",
		IdentityValuesReturned: false,
		SubjectReturned:        false,
		EmailReturned:          false,
		NameReturned:           false,
		ClaimValuesReturned:    false,
		GroupValuesReturned:    false,
		TokenReturned:          false,
		CookieValueReturned:    false,
		RequestBodyReturned:    false,
		EnvValuesReturned:      false,
		BackendPathReturned:    false,
		ValueReturned:          false,
	}
	for _, role := range AllRoles() {
		signal := sessionRoleSignal(session, role)
		if signal.Active {
			evidence.ActiveRoleCount++
		}
		evidence.Roles = append(evidence.Roles, signal)
	}
	evidence.Gates = []SessionRoleGateSignal{
		sessionRoleGate(session, ready, "posture_view", "Posture view", RoleViewer, false, "Safe posture and descriptor metadata are visible to signed-in viewers.", "Use posture before any sensitive action."),
		sessionRoleGate(session, ready, "evidence_export", "Evidence export", RoleAuditor, true, "Evidence JSON is available only to auditor sessions while readiness is healthy.", "Use an auditor session to download evidence JSON."),
		sessionRoleGate(session, ready, "use_actions", "Use actions", RoleOperator, true, "Handle and permit controls are available only to operator sessions while readiness is healthy.", "Use an operator session for metadata handles and permits."),
		sessionRoleGate(session, true, "security_policy", "Security policy", RoleSecurityAdmin, false, "Authorization policy review is available only to security-admin sessions.", "Use a security-admin session to review role policy."),
		{
			Key:           "identity_boundary",
			Label:         "Identity boundary",
			State:         "withheld",
			RequiredRole:  RoleViewer,
			Detail:        "Subject, email, display name, group, and claim values stay out of dashboard, posture, and evidence responses.",
			Next:          "Use role names and gates for review, not raw identity claims.",
			Tone:          "ok",
			ValueReturned: false,
		},
	}
	return evidence
}

func sessionRoleSignal(session Session, role string) SessionRoleSignal {
	active := HasRole(session, role)
	state := "inactive"
	detail := "This role is not active for the current session."
	tone := "info"
	if active {
		state = "active"
		detail = "This role is active for the current session."
		tone = "ok"
	}
	return SessionRoleSignal{
		Key:           role,
		Label:         roleTitle(role),
		Role:          role,
		State:         state,
		Active:        active,
		Detail:        detail,
		Tone:          tone,
		ValueReturned: false,
	}
}

func sessionRoleGate(session Session, ready bool, key, label, role string, readinessGated bool, detail, next string) SessionRoleGateSignal {
	state := "available"
	tone := "ok"
	if !HasRole(session, role) {
		state = "role_required"
		tone = "warn"
	} else if readinessGated && !ready {
		state = "readiness_blocked"
		tone = "warn"
		next = "Recover readiness before using this gate."
	}
	return SessionRoleGateSignal{
		Key:           key,
		Label:         label,
		State:         state,
		RequiredRole:  role,
		Detail:        detail,
		Next:          next,
		Tone:          tone,
		ValueReturned: false,
	}
}

func roleTitle(role string) string {
	switch role {
	case RoleOwner:
		return "Owner"
	case RoleApprover:
		return "Approver"
	case RoleSecurityAdmin:
		return "Security admin"
	case RoleBreakGlassAdmin:
		return "Break-glass admin"
	case RoleServiceAdmin:
		return "Service admin"
	case RoleWorkloadAdmin:
		return "Workload admin"
	case RoleAuditor:
		return "Auditor"
	case RoleOperator:
		return "Operator"
	case RoleViewer:
		return "Viewer"
	default:
		return role
	}
}

func rolePolicyLane(role, label string, subjects, groups map[string]bool) RolePolicyLane {
	subjectCount := len(subjects)
	groupCount := len(groups)
	bindingCount := subjectCount + groupCount
	ready := bindingCount > 0
	state := "ready"
	detail := "This role lane has explicit policy; only binding counts are returned."
	next := "Keep the binding owner review current."
	tone := "ok"
	if !ready {
		state = "missing"
		detail = "This role lane has no explicit subject or group binding."
		next = "Add a Zitadel subject or group binding for this role before enterprise release."
		tone = "warn"
	}
	return RolePolicyLane{
		Key:                      role,
		Label:                    label,
		Role:                     role,
		State:                    state,
		Ready:                    ready,
		Required:                 true,
		SubjectBindingConfigured: subjectCount > 0,
		GroupBindingConfigured:   groupCount > 0,
		SubjectBindingCount:      subjectCount,
		GroupBindingCount:        groupCount,
		BindingCount:             bindingCount,
		Detail:                   detail,
		Next:                     next,
		Tone:                     tone,
		SubjectValuesReturned:    false,
		GroupValuesReturned:      false,
		ClaimValuesReturned:      false,
		ValueReturned:            false,
	}
}

func laneSetupState(missing int) string {
	if missing == 0 {
		return "ready"
	}
	return "missing_lanes"
}

func laneSetupNext(missing int) string {
	if missing == 0 {
		return "Keep Zitadel role bindings reviewed before release promotion."
	}
	return "Add explicit Zitadel bindings for every missing elevated role lane."
}

func laneSetupTone(missing int) string {
	if missing == 0 {
		return "ok"
	}
	return "warn"
}

func roleSubjectBindingCount(policy RolePolicy) int {
	count := 0
	for _, role := range AllRoles() {
		count += len(roleSubjects(policy, role))
	}
	return count
}

func roleGroupBindingCount(policy RolePolicy) int {
	count := 0
	for _, role := range AllRoles() {
		count += len(roleGroups(policy, role))
	}
	return count
}

func elevatedRoleSubjectBindingCount(policy RolePolicy) int {
	count := 0
	for _, role := range AllRoles()[1:] {
		count += len(roleSubjects(policy, role))
	}
	return count
}

func elevatedRoleGroupBindingCount(policy RolePolicy) int {
	count := 0
	for _, role := range AllRoles()[1:] {
		count += len(roleGroups(policy, role))
	}
	return count
}

func configuredState(count int) string {
	if count > 0 {
		return "configured"
	}
	return "empty"
}

func configuredTone(count int) string {
	if count > 0 {
		return "ok"
	}
	return "info"
}

func RoleBoundariesFor(session Session) []RoleBoundary {
	return []RoleBoundary{
		{
			Role:    RoleViewer,
			Duty:    "Posture only",
			Allowed: "Read safe posture and descriptor metadata.",
			Blocked: "No secret use or mutation.",
			Active:  HasRole(session, RoleViewer),
		},
		{
			Role:    RoleOperator,
			Duty:    "Approved use",
			Allowed: "Request metadata handles and permit safety checks.",
			Blocked: "No approval, evidence export, or policy changes.",
			Active:  HasRole(session, RoleOperator),
		},
		{
			Role:    RoleOwner,
			Duty:    "Lifecycle ownership",
			Allowed: "Review lifecycle, recovery, and retention posture.",
			Blocked: "No normal secret use or self-approval.",
			Active:  HasRole(session, RoleOwner),
		},
		{
			Role:    RoleApprover,
			Duty:    "Exact approvals",
			Allowed: "Review approval posture.",
			Blocked: "No execution or policy administration.",
			Active:  HasRole(session, RoleApprover),
		},
		{
			Role:    RoleAuditor,
			Duty:    "Evidence and audit",
			Allowed: "View audit events and export evidence.",
			Blocked: "No handle, permit, or access-broadening controls.",
			Active:  HasRole(session, RoleAuditor),
		},
		{
			Role:    RoleSecurityAdmin,
			Duty:    "Authorization policy",
			Allowed: "Review authorization and exact binding posture.",
			Blocked: "No secret use, self-grant, or backend custody.",
			Active:  HasRole(session, RoleSecurityAdmin),
		},
		{
			Role:    RoleBreakGlassAdmin,
			Duty:    "Emergency eligibility",
			Allowed: "Show eligibility metadata only.",
			Blocked: "Inert without a separate exact activation.",
			Active:  HasRole(session, RoleBreakGlassAdmin),
		},
		{
			Role:    RoleServiceAdmin,
			Duty:    "Exact service administration",
			Allowed: "Show service-admin posture.",
			Blocked: "No untargeted or cross-service authority.",
			Active:  HasRole(session, RoleServiceAdmin),
		},
		{
			Role:    RoleWorkloadAdmin,
			Duty:    "Exact workload administration",
			Allowed: "Show workload-admin posture.",
			Blocked: "No untargeted or cross-workload authority.",
			Active:  HasRole(session, RoleWorkloadAdmin),
		},
	}
}

func SessionRoleBadge(session Session) string {
	elevated := make([]string, 0, len(AllRoles())-1)
	for _, role := range AllRoles()[1:] {
		if HasRole(session, role) {
			elevated = append(elevated, role)
		}
	}
	if len(elevated) == 0 {
		return "Viewer session"
	}
	if len(elevated) == 1 {
		return roleTitle(elevated[0]) + " session"
	}
	return fmt.Sprintf("%d elevated roles", len(elevated))
}

func AccessSessionGateViewsFor(session Session, witness AuthenticatedBrowserWitness, posture SessionPosture, access AccessPosture, readiness RolePolicyReadiness, requireAuth, oidcConfigured bool) []AccessSessionGateView {
	witnessLabel := "Local session"
	witnessPresent := strings.TrimSpace(session.Subject) != ""
	if requireAuth && oidcConfigured {
		witnessLabel = "Browser proof"
		witnessPresent = witness.Authenticated && witness.EvidenceSignal != ""
	}
	gates := []AccessSessionGateView{
		accessSessionGate("Authenticated", witness.Authenticated, "Allowed", "Missing"),
		accessSessionGate("Session valid", posture.SecondsRemaining > 0, "Allowed", "Expired"),
		accessSessionGate(witnessLabel, witnessPresent, "Present", "Missing"),
		accessSessionGate("Role session", len(session.Roles) > 0, "Allowed", "Missing"),
	}
	policyGate := AccessSessionGateView{Label: "Role policy", State: "Missing", Tone: "bad"}
	if readiness.Ready {
		policyGate.State = "Explicit"
		policyGate.Tone = "ok"
	} else if access.ExplicitBindings || access.BootstrapOwner {
		policyGate.State = "Review"
		policyGate.Tone = "warn"
	}
	return append(gates, policyGate)
}

func accessSessionGate(label string, allowed bool, allowedState, deniedState string) AccessSessionGateView {
	if allowed {
		return AccessSessionGateView{Label: label, State: allowedState, Tone: "ok"}
	}
	return AccessSessionGateView{Label: label, State: deniedState, Tone: "bad"}
}

func AccessRoleLaneViewsFor(session Session, readiness RolePolicyReadiness, globallyReady bool) []AccessRoleLaneView {
	policyLanes := make(map[string]RolePolicyLane, len(readiness.Lanes))
	for _, lane := range readiness.Lanes {
		policyLanes[lane.Role] = lane
	}

	views := make([]AccessRoleLaneView, 0, len(AllRoles()))
	for _, role := range AllRoles() {
		active := HasRole(session, role)
		lane := policyLanes[role]
		bindingReady := role == RoleViewer || lane.Ready
		hasSurface := role != RoleBreakGlassAdmin
		checks := []bool{session.Subject != "", active, bindingReady, hasSurface, globallyReady || role == RoleViewer || role == RoleSecurityAdmin}
		score := 0
		for _, check := range checks {
			if check {
				score++
			}
		}

		view := AccessRoleLaneView{
			Key:           role,
			Label:         roleTitle(role),
			SessionState:  "Not active",
			SessionTone:   "info",
			BindingLabel:  fmt.Sprintf("%d", lane.BindingCount),
			Scope:         accessRoleScope(role),
			SubjectLabel:  fmt.Sprintf("%d", lane.SubjectBindingCount),
			GroupLabel:    fmt.Sprintf("%d", lane.GroupBindingCount),
			ServiceLabel:  "—",
			GateLabel:     fmt.Sprintf("%d / %d", score, len(checks)),
			GateTone:      accessLaneTone(score, len(checks)),
			Readiness:     "Not ready",
			ReadinessTone: "bad",
			ValueReturned: false,
		}
		if role == RoleViewer {
			view.BindingLabel = "Baseline"
			view.SubjectLabel = "—"
			view.GroupLabel = "—"
		}
		if active {
			view.SessionState = "Active"
			view.SessionTone = "ok"
		}
		if active && !globallyReady && (role == RoleOperator || role == RoleAuditor) {
			view.Readiness = "Blocked"
			view.ReadinessTone = "bad"
		} else if score == len(checks) {
			view.Readiness = "Ready"
			view.ReadinessTone = "ok"
		} else if score >= 3 {
			view.Readiness = "Limited"
			view.ReadinessTone = "warn"
		}
		views = append(views, view)
	}
	return views
}

func accessRoleScope(role string) string {
	switch role {
	case RoleViewer:
		return "Read only"
	case RoleOperator:
		return "Operate"
	case RoleAuditor:
		return "Audit & export"
	case RoleOwner:
		return "Lifecycle"
	case RoleApprover:
		return "Approve"
	case RoleSecurityAdmin:
		return "Policy"
	case RoleBreakGlassAdmin:
		return "Eligibility only"
	case RoleServiceAdmin:
		return "Exact service"
	case RoleWorkloadAdmin:
		return "Exact workload"
	default:
		return "—"
	}
}

func accessLaneTone(score, total int) string {
	if score == total {
		return "ok"
	}
	if score >= 3 {
		return "warn"
	}
	return "bad"
}

func RouteGateViewsFor(session Session, access AccessPosture, ready bool) []RouteGateView {
	views := make([]RouteGateView, 0, len(accessProtectedRoutes))
	for _, definition := range accessProtectedRoutes {
		requiredRole := access.RequiredRoles[definition.Route]
		view := RouteGateView{
			Route:          definition.Route,
			RequiredRole:   requiredRole,
			SessionState:   "Active",
			SessionTone:    "ok",
			State:          "Allowed",
			Tone:           "ok",
			ReadinessGated: definition.ReadinessGated,
		}
		if requiredRole == "" {
			view.RequiredRole = "Unmapped"
			view.SessionState = "Missing"
			view.SessionTone = "bad"
			view.State = "Blocked"
			view.Tone = "bad"
		} else if !HasRole(session, requiredRole) {
			view.SessionState = "Missing"
			view.SessionTone = "warn"
			view.State = "Role-gated"
			view.Tone = "warn"
		} else if definition.ReadinessGated && !ready {
			view.State = "Blocked"
			view.Tone = "warn"
		}
		views = append(views, view)
	}
	return views
}

func RoleAvailabilityFor(session Session) []RoleAvailability {
	operator := HasRole(session, RoleOperator)
	auditor := HasRole(session, RoleAuditor)
	securityAdmin := HasRole(session, RoleSecurityAdmin)
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
			Label:  "Security policy",
			State:  availabilityState(securityAdmin),
			Detail: availabilityDetail(securityAdmin, "Authorization policy review is available.", "Security-admin role required."),
			Tone:   availabilityTone(securityAdmin),
		},
	}
}

func RoleWorkbenchFor(session Session, ready bool) RoleWorkbench {
	workbench := RoleWorkbench{
		Summary:       "Role workbench shows the controls rendered for this session and hides controls outside its role boundary.",
		ValueReturned: false,
	}
	workbench.Available = append(workbench.Available, RoleWorkbenchItem{
		Key:    "posture_view",
		Label:  "Posture view",
		State:  "rendered",
		Detail: "Safe posture, descriptor focus, and value boundaries are visible.",
		Next:   "Use posture to decide the next safe action.",
		Tone:   "ok",
	})

	if HasRole(session, RoleAuditor) {
		workbench.addAvailable("audit_evidence", "Audit and evidence", ready, "Audit rows and evidence download are rendered for this auditor session.", "Download evidence or inspect audit posture.")
	} else {
		workbench.addHidden("audit_evidence", "Audit and evidence", "Auditor controls are not rendered for this session.", "Use an auditor session to inspect audit rows or download evidence.")
	}

	if HasRole(session, RoleOperator) {
		workbench.addAvailable("operator_use", "Handle and permit", ready, "Handle, permit, and permit safety controls are rendered for this operator session.", "Issue a metadata handle or create a value-free permit.")
	} else {
		workbench.addHidden("operator_use", "Handle and permit", "Operator mutation controls are not rendered for this session.", "Use an operator session for metadata handles or permits.")
	}

	if HasRole(session, RoleSecurityAdmin) {
		workbench.Available = append(workbench.Available, RoleWorkbenchItem{
			Key:    "security_policy",
			Label:  "Security policy",
			State:  "rendered",
			Detail: "Role policy, ownership, and enterprise control review are visible.",
			Next:   "Review role bindings and external evidence status.",
			Tone:   "ok",
		})
	} else {
		workbench.addHidden("security_policy", "Security policy", "Authorization policy controls are not rendered for this session.", "Use a security-admin session to review role policy.")
	}

	return workbench
}

func (w *RoleWorkbench) addAvailable(key, label string, ready bool, detail, next string) {
	state := "rendered"
	tone := "ok"
	if !ready {
		state = "readiness blocked"
		tone = "warn"
		next = "Recover readiness before using this control."
	}
	w.Available = append(w.Available, RoleWorkbenchItem{
		Key:    key,
		Label:  label,
		State:  state,
		Detail: detail,
		Next:   next,
		Tone:   tone,
	})
}

func (w *RoleWorkbench) addHidden(key, label, detail, next string) {
	w.Hidden = append(w.Hidden, RoleWorkbenchItem{
		Key:    key,
		Label:  label,
		State:  "hidden",
		Detail: detail,
		Next:   next,
		Tone:   "warn",
	})
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
	matrix.add(actionReadinessItem(session, ready, "handle_issue", "Issue metadata handle", RoleOperator, true, "Operator role can issue metadata-only handles.", "Use an operator session after readiness is healthy.", "Never reveals a secret value."))
	matrix.add(actionReadinessItem(session, ready, "permit_create", "Create permit", RoleOperator, true, "Operator role can create metadata-only permits.", "Use an operator session after readiness is healthy.", "Permit records are durable and value-free."))
	matrix.add(actionReadinessItem(session, ready, "permit_run_check", "Run permit check", RoleOperator, true, "Operator role can run a no-connector safety check.", "Use an operator session after readiness is healthy.", "No connector executes and output is scrubbed."))
	matrix.add(actionReadinessItem(session, true, "service_setup_download", "Download service setup", RoleOperator, false, "Operator role can download a value-free machine configuration script.", "Use an operator session to apply reviewed service configuration.", "Configuration only; the secret value is never included."))
	matrix.add(actionReadinessItem(session, ready, "evidence_export", "Evidence export", RoleAuditor, true, "Auditor role can download value-free evidence JSON.", "Use an auditor session to export evidence.", "Role-gated, readiness-gated, and value-free."))
	matrix.add(actionReadinessItem(session, true, "policy_posture", "Review policy posture", RoleViewer, false, "Every signed-in viewer can review value-free role and ownership posture.", "Use a signed-in viewer session to review policy posture.", "Read-only and value-free."))
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
	for key := range projectRoles {
		values = append(values, key)
	}
	return values
}

// ZitadelProjectRoles selects the project-specific roles claim for the
// configured Janus project. ZITADEL also emits a legacy unscoped alias, which
// remains a fallback for compatibility. Claim values are decoded but never
// returned in errors.
func ZitadelProjectRoles(rawClaims map[string]json.RawMessage, projectID string) (map[string]any, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID != "" {
		for _, char := range projectID {
			if char < '0' || char > '9' {
				return nil, fmt.Errorf("invalid Zitadel project id")
			}
		}
		exact := zitadelProjectRolesClaimPrefix + projectID + zitadelProjectRolesClaimSuffix
		if raw, ok := rawClaims[exact]; ok {
			return decodeZitadelProjectRoles(raw)
		}
		return nil, nil
	}

	var selected json.RawMessage
	for key, raw := range rawClaims {
		if !strings.HasPrefix(key, zitadelProjectRolesClaimPrefix) ||
			!strings.HasSuffix(key, zitadelProjectRolesClaimSuffix) ||
			key == zitadelProjectRolesClaim {
			continue
		}
		project := strings.TrimSuffix(strings.TrimPrefix(key, zitadelProjectRolesClaimPrefix), zitadelProjectRolesClaimSuffix)
		if project == "" {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("ambiguous Zitadel project role claims")
		}
		selected = raw
	}
	if selected != nil {
		return decodeZitadelProjectRoles(selected)
	}
	return decodeZitadelProjectRoles(rawClaims[zitadelProjectRolesClaim])
}

func decodeZitadelProjectRoles(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var roles map[string]any
	if err := json.Unmarshal(raw, &roles); err != nil {
		return nil, fmt.Errorf("invalid Zitadel project role claim")
	}
	return roles, nil
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
