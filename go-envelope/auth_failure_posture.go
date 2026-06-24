package main

type AuthFailurePosture struct {
	Label                    string              `json:"label"`
	State                    string              `json:"state"`
	Summary                  string              `json:"summary"`
	IdentityProvider         string              `json:"identity_provider"`
	AuthRequired             bool                `json:"auth_required"`
	OIDCConfigured           bool                `json:"oidc_configured"`
	EvidenceSignal           string              `json:"evidence_signal"`
	LoopGuard                AuthLoopGuard       `json:"loop_guard"`
	Reasons                  []AuthFailureReason `json:"reasons"`
	Actions                  []AuthFailureAction `json:"actions"`
	RawCallbackQueryReturned bool                `json:"raw_callback_query_returned"`
	ProviderErrorReturned    bool                `json:"provider_error_returned"`
	RedirectURLReturned      bool                `json:"redirect_url_returned"`
	TokenReturned            bool                `json:"token_returned"`
	CookieValueReturned      bool                `json:"cookie_value_returned"`
	RequestBodyReturned      bool                `json:"request_body_returned"`
	EnvReturned              bool                `json:"env_returned"`
	BackendPathReturned      bool                `json:"backend_path_returned"`
	ValueReturned            bool                `json:"value_returned"`
}

type AuthLoopGuard struct {
	State               string `json:"state"`
	MaxAttempts         int    `json:"max_attempts"`
	WindowSeconds       int    `json:"window_seconds"`
	CookieSameSite      string `json:"cookie_same_site"`
	ResetAction         string `json:"reset_action"`
	CookieValueReturned bool   `json:"cookie_value_returned"`
	ValueReturned       bool   `json:"value_returned"`
}

type AuthFailureReason struct {
	Key                    string `json:"key"`
	Label                  string `json:"label"`
	State                  string `json:"state"`
	Detail                 string `json:"detail"`
	Next                   string `json:"next"`
	Tone                   string `json:"tone"`
	RawQueryReturned       bool   `json:"raw_query_returned"`
	ProviderDetailReturned bool   `json:"provider_detail_returned"`
	TokenReturned          bool   `json:"token_returned"`
	ValueReturned          bool   `json:"value_returned"`
}

type AuthFailureAction struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	Safety        string `json:"safety"`
	Next          string `json:"next"`
	ValueReturned bool   `json:"value_returned"`
}

func AuthFailurePostureFor(cfg Config) AuthFailurePosture {
	state := "ready"
	summary := "OIDC failure handling is bounded, value-free, and ready to guide the user back to a clean Janus login."
	switch {
	case !cfg.RequireAuth:
		state = "local_auth_disabled"
		summary = "Auth is disabled for local smoke; production failure handling stays documented and value-free."
	case !cfg.OIDCConfigured():
		state = "setup_required"
		summary = "OIDC is not fully configured, so Janus stays locked to setup guidance."
	}
	return AuthFailurePosture{
		Label:            "Auth failure posture",
		State:            state,
		Summary:          summary,
		IdentityProvider: "zitadel_oidc",
		AuthRequired:     cfg.RequireAuth,
		OIDCConfigured:   cfg.OIDCConfigured(),
		EvidenceSignal:   "presence_only_auth_failure_posture",
		LoopGuard: AuthLoopGuard{
			State:               "enabled",
			MaxAttempts:         maxLoginAttempts,
			WindowSeconds:       int(loginAttemptTTL.Seconds()),
			CookieSameSite:      "Lax",
			ResetAction:         "clear_temporary_login_cookies",
			CookieValueReturned: false,
			ValueReturned:       false,
		},
		Reasons: []AuthFailureReason{
			authFailureReason("login_restart_required", "Fresh login required", "recoverable", "State was missing or stale, so Janus stopped before creating a session.", "Reset the login session and start again.", "warn"),
			authFailureReason("login_integrity_check_failed", "Integrity check failed", "blocked", "Nonce, PKCE, or logout checks did not match the protected browser flow.", "Reload Janus and retry from a fresh page.", "warn"),
			authFailureReason("identity_login_denied", "Identity login denied", "recoverable", "The identity provider did not complete login; Janus keeps provider details outside the response.", "Retry login or reset the browser session.", "warn"),
			authFailureReason("authorization_code_missing", "Completion code missing", "blocked", "The callback reached Janus without a usable authorization code.", "Start a fresh login and keep the request id if it repeats.", "warn"),
			authFailureReason("identity_response_failed", "Identity response failed", "blocked", "The identity response could not be verified or read safely.", "Keep the request id and review identity provider health outside Janus.", "warn"),
			authFailureReason("login_loop_paused", "Redirect loop paused", "protected", "Janus pauses repeated login starts before sending the browser back to identity again.", "Reset temporary login cookies, then try once from a clean tab.", "info"),
		},
		Actions: []AuthFailureAction{
			{Key: "retry_login", Label: "Retry login", Safety: "starts a fresh OIDC flow without reusing stale callback data", Next: "Use after a normal stale-state failure.", ValueReturned: false},
			{Key: "reset_login_cookies", Label: "Reset login session", Safety: "clears only Janus temporary login cookies", Next: "Use when login keeps bouncing between Janus and identity.", ValueReturned: false},
			{Key: "keep_request_id", Label: "Keep request id", Safety: "support handle contains no token, query string, or secret value", Next: "Use the request id for server-side audit lookup.", ValueReturned: false},
		},
		RawCallbackQueryReturned: false,
		ProviderErrorReturned:    false,
		RedirectURLReturned:      false,
		TokenReturned:            false,
		CookieValueReturned:      false,
		RequestBodyReturned:      false,
		EnvReturned:              false,
		BackendPathReturned:      false,
		ValueReturned:            false,
	}
}

func authFailureReason(key, label, state, detail, next, tone string) AuthFailureReason {
	return AuthFailureReason{
		Key:                    key,
		Label:                  label,
		State:                  state,
		Detail:                 detail,
		Next:                   next,
		Tone:                   tone,
		RawQueryReturned:       false,
		ProviderDetailReturned: false,
		TokenReturned:          false,
		ValueReturned:          false,
	}
}
