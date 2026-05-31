package main

type AuthenticatedBrowserWitness struct {
	Label                   string                     `json:"label"`
	Summary                 string                     `json:"summary"`
	State                   string                     `json:"state"`
	Flow                    string                     `json:"flow"`
	Page                    string                     `json:"page"`
	AuthMode                string                     `json:"auth_mode"`
	IdentityProvider        string                     `json:"identity_provider"`
	SessionCookiePolicy     string                     `json:"session_cookie_policy"`
	CSRFBoundary            string                     `json:"csrf_boundary"`
	CSPBoundary             string                     `json:"csp_boundary"`
	EvidenceSignal          string                     `json:"evidence_signal"`
	Next                    string                     `json:"next"`
	Authenticated           bool                       `json:"authenticated"`
	Ready                   bool                       `json:"ready"`
	ActiveRoleCount         int                        `json:"active_role_count"`
	TotalRoleCount          int                        `json:"total_role_count"`
	Gates                   []AuthenticatedBrowserGate `json:"gates"`
	IdentityValuesReturned  bool                       `json:"identity_values_returned"`
	SubjectReturned         bool                       `json:"subject_returned"`
	EmailReturned           bool                       `json:"email_returned"`
	NameReturned            bool                       `json:"name_returned"`
	ClaimValuesReturned     bool                       `json:"claim_values_returned"`
	GroupValuesReturned     bool                       `json:"group_values_returned"`
	TokenReturned           bool                       `json:"token_returned"`
	CookieValueReturned     bool                       `json:"cookie_value_returned"`
	RequestBodyReturned     bool                       `json:"request_body_returned"`
	EnvValuesReturned       bool                       `json:"env_values_returned"`
	BackendPathReturned     bool                       `json:"backend_path_returned"`
	ConnectorOutputReturned bool                       `json:"connector_output_returned"`
	PermitPayloadReturned   bool                       `json:"permit_payload_returned"`
	SecretValueReturned     bool                       `json:"secret_value_returned"`
	ValueReturned           bool                       `json:"value_returned"`
}

type AuthenticatedBrowserCapture struct {
	Schema                 string   `json:"schema"`
	BodyField              string   `json:"body_field"`
	Headers                []string `json:"headers"`
	Proof                  string   `json:"proof"`
	ReplaySafe             bool     `json:"replay_safe"`
	CopySafe               bool     `json:"copy_safe"`
	IdentityValuesReturned bool     `json:"identity_values_returned"`
	CookieValueReturned    bool     `json:"cookie_value_returned"`
	TokenReturned          bool     `json:"token_returned"`
	ValueReturned          bool     `json:"value_returned"`
}

type AuthenticatedBrowserCaptureHeader struct {
	Name          string `json:"name"`
	Value         string `json:"value"`
	ValueReturned bool   `json:"value_returned"`
}

type AuthenticatedBrowserGate struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	State         string `json:"state"`
	Detail        string `json:"detail"`
	Tone          string `json:"tone"`
	ValueReturned bool   `json:"value_returned"`
}

func AuthenticatedBrowserWitnessFor(session Session, roleEvidence SessionRoleEvidence, sessionPosture SessionPosture, requireAuth, oidcConfigured, ready bool) AuthenticatedBrowserWitness {
	authenticated := session.Subject != ""
	state := "authenticated"
	flow := "zitadel_oidc_pkce_to_signed_session"
	summary := "Browser login is complete: Zitadel handed Janus a signed session, role gates are visible, and identity values stay withheld."
	if !requireAuth {
		state = "local_smoke"
		flow = "local_dev_signed_session"
		summary = "Local smoke session is active; the same browser witness stays value-free."
	} else if !oidcConfigured {
		state = "setup_only"
		flow = "oidc_setup_required"
		summary = "Auth is required but setup is incomplete; Janus keeps identity values outside the response."
	} else if !authenticated {
		state = "missing"
		flow = "login_required"
		summary = "No authenticated browser session is active."
	}

	cookiePolicy := "review"
	if sessionPosture.CookieSigned && sessionPosture.CookieSameSite == "Strict" && sessionPosture.CookieHostPrefixed {
		cookiePolicy = "host_prefixed_strict_signed"
	} else if sessionPosture.CookieSigned && sessionPosture.CookieSameSite == "Strict" {
		cookiePolicy = "strict_signed"
	}
	csrfBoundary := "review"
	if sessionPosture.CSRFBound {
		csrfBoundary = "bound_to_signed_session"
	}

	witness := AuthenticatedBrowserWitness{
		Label:                   "Authenticated browser witness",
		Summary:                 summary,
		State:                   state,
		Flow:                    flow,
		Page:                    "dashboard_authenticated",
		AuthMode:                roleEvidence.AuthMode,
		IdentityProvider:        roleEvidence.IdentityProvider,
		SessionCookiePolicy:     cookiePolicy,
		CSRFBoundary:            csrfBoundary,
		CSPBoundary:             "script_src_none",
		EvidenceSignal:          "signed_session_browser_proof_no_identity_values",
		Next:                    "Use this panel or /api/auth/session-witness as copy-safe proof of browser login and role gates.",
		Authenticated:           authenticated,
		Ready:                   ready,
		ActiveRoleCount:         roleEvidence.ActiveRoleCount,
		TotalRoleCount:          roleEvidence.TotalRoleCount,
		IdentityValuesReturned:  false,
		SubjectReturned:         false,
		EmailReturned:           false,
		NameReturned:            false,
		ClaimValuesReturned:     false,
		GroupValuesReturned:     false,
		TokenReturned:           false,
		CookieValueReturned:     false,
		RequestBodyReturned:     false,
		EnvValuesReturned:       false,
		BackendPathReturned:     false,
		ConnectorOutputReturned: false,
		PermitPayloadReturned:   false,
		SecretValueReturned:     false,
		ValueReturned:           false,
	}
	witness.Gates = []AuthenticatedBrowserGate{
		authenticatedBrowserGate("login_completed", "Login proof", state, "The browser has a Janus session and the page renders only safe role state.", authenticated || !requireAuth),
		authenticatedBrowserGate("cookie_boundary", "Cookie boundary", cookiePolicy, "Session cookie posture is strict, signed, HttpOnly, secure, and host-prefixed on HTTPS.", cookiePolicy == "host_prefixed_strict_signed"),
		authenticatedBrowserGate("csrf_boundary", "CSRF boundary", csrfBoundary, "Browser mutations require a token bound to the signed session.", csrfBoundary == "bound_to_signed_session"),
		authenticatedBrowserGate("page_boundary", "No-script page", "script_src_none", "Dashboard HTML runs without browser script and keeps forms same-origin.", true),
		authenticatedBrowserGate("role_gates", "Role gates", "roles_visible", "Janus shows role names and gate states, not identity claim values.", roleEvidence.ActiveRoleCount > 0),
		authenticatedBrowserGate("value_boundary", "Value boundary", "values_withheld", "Subject, email, name, groups, claims, tokens, cookies, request bodies, env, backend paths, connector output, permit payloads, and secret values are not returned.", true),
	}
	return witness
}

func AuthenticatedBrowserCaptureFor() AuthenticatedBrowserCapture {
	return AuthenticatedBrowserCapture{
		Schema:    "janus-auth-session-witness-v1",
		BodyField: "witness",
		Headers: []string{
			"X-Request-Id",
			"X-Janus-Witness-Schema",
			"X-Janus-Witness-State",
			"X-Janus-Witness-Flow",
			"X-Janus-Witness-Signal",
			"X-Janus-Witness-Body-Field",
			"X-Janus-Value-Returned",
		},
		Proof:                  "signed_session_browser_proof_no_identity_values",
		ReplaySafe:             true,
		CopySafe:               true,
		IdentityValuesReturned: false,
		CookieValueReturned:    false,
		TokenReturned:          false,
		ValueReturned:          false,
	}
}

func AuthenticatedBrowserCaptureHeadersFor(witness AuthenticatedBrowserWitness, capture AuthenticatedBrowserCapture, requestID string) []AuthenticatedBrowserCaptureHeader {
	return []AuthenticatedBrowserCaptureHeader{
		authenticatedBrowserCaptureHeader("X-Request-Id", requestID),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-Schema", capture.Schema),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-State", witness.State),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-Flow", witness.Flow),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-Signal", witness.EvidenceSignal),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-Body-Field", capture.BodyField),
		authenticatedBrowserCaptureHeader("X-Janus-Value-Returned", "false"),
	}
}

func AuthenticatedBrowserCaptureLineFor(witness AuthenticatedBrowserWitness, capture AuthenticatedBrowserCapture, requestID string) string {
	return "schema=" + capture.Schema +
		" state=" + witness.State +
		" flow=" + witness.Flow +
		" signal=" + witness.EvidenceSignal +
		" body_field=" + capture.BodyField +
		" request_id=" + requestID +
		" value_returned=false"
}

func authenticatedBrowserCaptureHeader(name, value string) AuthenticatedBrowserCaptureHeader {
	return AuthenticatedBrowserCaptureHeader{
		Name:          name,
		Value:         value,
		ValueReturned: false,
	}
}

func authenticatedBrowserGate(key, label, state, detail string, ok bool) AuthenticatedBrowserGate {
	tone := "ok"
	if !ok {
		tone = "warn"
	}
	return AuthenticatedBrowserGate{
		Key:           key,
		Label:         label,
		State:         state,
		Detail:        detail,
		Tone:          tone,
		ValueReturned: false,
	}
}
