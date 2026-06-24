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
		case policy.AdminGroups[key]:
			roles[RoleAdmin] = true
		case policy.AuditorGroups[key]:
			roles[RoleAuditor] = true
		case policy.OperatorGroups[key]:
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
	explicit := policy.Configured()
	subjectCount := roleSubjectBindingCount(policy)
	groupCount := roleGroupBindingCount(policy)
	if !explicit {
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
		ExplicitBindings:       explicit,
		BootstrapOwner:         !explicit && policy.BootstrapOwner,
		KnownRoles:             AllRoles(),
		ClaimPolicy:            "explicit_only",
		ImplicitElevatedClaims: false,
		SubjectBindingCount:    subjectCount,
		GroupBindingCount:      groupCount,
		ElevatedBindingCount:   subjectCount + groupCount,
		BindingSources:         RoleBindingSourcesFor(policy),
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

func RoleBindingSourcesFor(policy RolePolicy) []RoleBindingSource {
	explicit := policy.Configured()
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
		bootstrap.State = "inactive"
		bootstrap.Detail = "Bootstrap owner is ignored because explicit role policy is configured."
		if !explicit {
			bootstrap.State = "active"
			bootstrap.Count = 1
			bootstrap.Detail = "Bootstrap owner grants all V1 roles until explicit role policy is configured."
			bootstrap.Tone = "warn"
		}
	}
	return append(sources, bootstrap)
}

func RolePolicyReadinessFor(policy RolePolicy, access AccessPosture) RolePolicyReadiness {
	lanes := []RolePolicyLane{
		rolePolicyLane(RoleAdmin, "Admin lane", policy.AdminSubjects, policy.AdminGroups),
		rolePolicyLane(RoleAuditor, "Auditor lane", policy.AuditorSubjects, policy.AuditorGroups),
		rolePolicyLane(RoleOperator, "Operator lane", policy.OperatorSubjects, policy.OperatorGroups),
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
		bootstrapState = "inactive"
		bootstrapDetail = "Bootstrap owner is ignored because explicit role policy exists."
		bootstrapNext = "Turn bootstrap owner off after explicit role lanes are reviewed."
		bootstrapTone = "info"
		if access.BootstrapOwner {
			bootstrapState = "active"
			bootstrapBlocked = true
			bootstrapDetail = "Bootstrap owner is granting all V1 elevated roles because explicit policy is not ready."
			bootstrapNext = "Add explicit Zitadel subject or group bindings for every elevated role lane."
			bootstrapTone = "warn"
		}
	}

	ready := missingLanes == 0 && !bootstrapBlocked && !access.ValueReturned
	status := "ready"
	summary := "Role policy has explicit Zitadel admin, auditor, and operator lanes; bootstrap owner is not active."
	next := "Keep owner review current and leave evidence value-free."
	if !ready {
		status = "blocked"
		summary = "Role policy is not ready for enterprise release because bootstrap is active or a role lane is missing."
		next = "Bind each missing elevated role lane to a Zitadel subject or group, then close bootstrap."
	} else if policy.BootstrapOwner {
		summary = "Role policy lanes are explicit; bootstrap owner is inactive and should be turned off after review."
		next = "Turn bootstrap owner off to make the explicit policy visible in configuration too."
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
			OwnerRole:     RoleAdmin,
			Detail:        bootstrapDetail,
			Next:          bootstrapNext,
			Tone:          bootstrapTone,
			ValueReturned: false,
		},
		{
			Key:           "zitadel_lanes",
			Label:         "Zitadel role lanes",
			State:         laneSetupState(missingLanes),
			OwnerRole:     RoleAdmin,
			Detail:        "Admin, auditor, and operator each need at least one configured subject or group binding.",
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
		sessionRoleGate(session, true, "admin_policy", "Admin policy", RoleAdmin, false, "Admin policy review is available only to admin sessions.", "Use an admin session to review ownership and role policy."),
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
	case RoleAdmin:
		return "Admin"
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
	return len(policy.AdminSubjects) + len(policy.AuditorSubjects) + len(policy.OperatorSubjects)
}

func roleGroupBindingCount(policy RolePolicy) int {
	return len(policy.AdminGroups) + len(policy.AuditorGroups) + len(policy.OperatorGroups)
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

	if HasRole(session, RoleAdmin) {
		workbench.Available = append(workbench.Available, RoleWorkbenchItem{
			Key:    "admin_policy",
			Label:  "Admin policy",
			State:  "rendered",
			Detail: "Role policy, ownership, and enterprise control review are visible.",
			Next:   "Review role bindings and external evidence status.",
			Tone:   "ok",
		})
	} else {
		workbench.addHidden("admin_policy", "Admin policy", "Admin policy controls are not rendered for this session.", "Use an admin session to review role and ownership policy.")
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
