package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

const authenticatedBrowserCaptureFreshness = 5 * time.Minute

const (
	authenticatedBrowserCaptureSchema = "janus-auth-session-witness-v1"
	authenticatedBrowserCaptureSignal = "signed_session_browser_proof_no_identity_values"
	witnessVerificationReceiptSchema  = "janus-witness-verification-v1"
)

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

type AuthenticatedBrowserCaptureReceipt struct {
	Algorithm        string `json:"algorithm"`
	Hash             string `json:"hash"`
	HashHeader       string `json:"hash_header"`
	BodyField        string `json:"body_field"`
	Input            string `json:"input"`
	CapturedAt       string `json:"captured_at"`
	FreshUntil       string `json:"fresh_until"`
	FreshnessSeconds int    `json:"freshness_seconds"`
	ValueReturned    bool   `json:"value_returned"`
}

type WitnessReceiptVerificationRequest struct {
	ProofLine string `json:"proof_line"`
	ProofHash string `json:"proof_hash"`
	Hash      string `json:"hash"`
}

type WitnessProofPackVerificationRequest struct {
	ProofPack string `json:"proof_pack"`
}

type WitnessReceiptVerification struct {
	Label               string                            `json:"label"`
	Status              string                            `json:"status"`
	Summary             string                            `json:"summary"`
	Receipt             *WitnessVerificationReceipt       `json:"receipt,omitempty"`
	Schema              string                            `json:"schema,omitempty"`
	State               string                            `json:"state,omitempty"`
	Flow                string                            `json:"flow,omitempty"`
	Signal              string                            `json:"signal,omitempty"`
	BodyField           string                            `json:"body_field,omitempty"`
	RequestID           string                            `json:"request_id,omitempty"`
	CapturedAt          string                            `json:"captured_at,omitempty"`
	FreshUntil          string                            `json:"fresh_until,omitempty"`
	FreshnessSeconds    int                               `json:"freshness_seconds,omitempty"`
	ProvidedHash        string                            `json:"provided_hash,omitempty"`
	ExpectedHash        string                            `json:"expected_hash,omitempty"`
	HashMatch           bool                              `json:"hash_match"`
	Fresh               bool                              `json:"fresh"`
	Verified            bool                              `json:"verified"`
	Checks              []WitnessReceiptVerificationCheck `json:"checks"`
	InputReturned       bool                              `json:"input_returned"`
	RequestBodyReturned bool                              `json:"request_body_returned"`
	ValueReturned       bool                              `json:"value_returned"`
}

type WitnessVerificationReceipt struct {
	Schema              string `json:"schema"`
	Algorithm           string `json:"algorithm"`
	Hash                string `json:"hash"`
	HashHeader          string `json:"hash_header"`
	BodyField           string `json:"body_field"`
	Input               string `json:"input"`
	RequestID           string `json:"request_id"`
	Status              string `json:"status"`
	HashMatch           bool   `json:"hash_match"`
	Fresh               bool   `json:"fresh"`
	Verified            bool   `json:"verified"`
	InputReturned       bool   `json:"input_returned"`
	RequestBodyReturned bool   `json:"request_body_returned"`
	ValueReturned       bool   `json:"value_returned"`
}

type WitnessReceiptVerificationCheck struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	State  string `json:"state"`
	Detail string `json:"detail"`
	Tone   string `json:"tone"`
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
		Schema:    authenticatedBrowserCaptureSchema,
		BodyField: "witness",
		Headers: []string{
			"X-Request-Id",
			"X-Janus-Witness-Schema",
			"X-Janus-Witness-State",
			"X-Janus-Witness-Flow",
			"X-Janus-Witness-Signal",
			"X-Janus-Witness-Body-Field",
			"X-Janus-Witness-Algorithm",
			"X-Janus-Witness-Hash",
			"X-Janus-Witness-Hash-Body-Field",
			"X-Janus-Witness-Captured-At",
			"X-Janus-Witness-Fresh-Until",
			"X-Janus-Witness-Freshness-Seconds",
			"X-Janus-Value-Returned",
		},
		Proof:                  authenticatedBrowserCaptureSignal,
		ReplaySafe:             true,
		CopySafe:               true,
		IdentityValuesReturned: false,
		CookieValueReturned:    false,
		TokenReturned:          false,
		ValueReturned:          false,
	}
}

func (req WitnessReceiptVerificationRequest) NormalizedHash() string {
	if strings.TrimSpace(req.ProofHash) != "" {
		return strings.ToLower(strings.TrimSpace(req.ProofHash))
	}
	return strings.ToLower(strings.TrimSpace(req.Hash))
}

func VerifyAuthenticatedBrowserCaptureReceipt(req WitnessReceiptVerificationRequest, now time.Time) WitnessReceiptVerification {
	now = now.UTC()
	proofLine := strings.TrimSpace(req.ProofLine)
	providedHash := req.NormalizedHash()
	verification := WitnessReceiptVerification{
		Label:               "Session witness receipt verification",
		Status:              "blocked",
		Summary:             "The witness receipt could not be verified.",
		InputReturned:       false,
		RequestBodyReturned: false,
		ValueReturned:       false,
	}

	fields, parseChecks, parseOK := parseWitnessProofLine(proofLine)
	verification.Checks = append(verification.Checks, parseChecks...)
	if proofLine == "" {
		verification.Checks = append(verification.Checks, witnessVerificationCheck("receipt_input", "Receipt input", "missing", "Paste the witness proof line from the text or page.", false))
		parseOK = false
	}
	if providedHash == "" {
		verification.Checks = append(verification.Checks, witnessVerificationCheck("hash_format", "Proof hash", "missing", "Paste the proof_hash value or X-Janus-Witness-Hash header.", false))
	} else if !isLowerHexString(providedHash, 64) {
		verification.Checks = append(verification.Checks, witnessVerificationCheck("hash_format", "Proof hash", "invalid", "The proof hash must be 64 lowercase hexadecimal characters.", false))
	} else {
		verification.ProvidedHash = providedHash
		verification.Checks = append(verification.Checks, witnessVerificationCheck("hash_format", "Proof hash", "valid", "The provided hash has the expected SHA-256 shape.", true))
	}

	schemaOK := fields["schema"] == authenticatedBrowserCaptureSchema
	verification.Checks = append(verification.Checks, witnessVerificationCheck("schema", "Schema", fields["schema"], "Expected "+authenticatedBrowserCaptureSchema+".", schemaOK))
	if schemaOK {
		verification.Schema = fields["schema"]
	}

	state, flow := fields["state"], fields["flow"]
	flowOK := authenticatedBrowserFlowAllowed(state, flow)
	verification.Checks = append(verification.Checks, witnessVerificationCheck("flow", "Flow", flow, "State and flow must match a Janus browser witness mode.", flowOK))
	if flowOK {
		verification.State = state
		verification.Flow = flow
	}

	signalOK := fields["signal"] == authenticatedBrowserCaptureSignal
	verification.Checks = append(verification.Checks, witnessVerificationCheck("signal", "Signal", fields["signal"], "Expected the signed-session value-free proof signal.", signalOK))
	if signalOK {
		verification.Signal = fields["signal"]
	}

	bodyFieldOK := fields["body_field"] == "witness"
	verification.Checks = append(verification.Checks, witnessVerificationCheck("body_field", "Body field", fields["body_field"], "Expected body_field=witness.", bodyFieldOK))
	if bodyFieldOK {
		verification.BodyField = fields["body_field"]
	}

	requestID := sanitizeRequestID(fields["request_id"])
	requestIDOK := requestID != ""
	verification.Checks = append(verification.Checks, witnessVerificationCheck("request_id", "Request id", safeDisplayState(requestID), "Request id must use Janus-safe request id characters.", requestIDOK))
	if requestIDOK {
		verification.RequestID = requestID
	}

	capturedAt, capturedOK := parseWitnessTime(fields["captured_at"])
	freshUntil, freshUntilOK := parseWitnessTime(fields["fresh_until"])
	freshnessSeconds, freshnessOK := parseWitnessFreshnessSeconds(fields["freshness_seconds"])
	verification.Checks = append(verification.Checks, witnessVerificationCheck("captured_at", "Captured at", fields["captured_at"], "captured_at must be RFC3339 UTC time.", capturedOK))
	verification.Checks = append(verification.Checks, witnessVerificationCheck("fresh_until", "Fresh until", fields["fresh_until"], "fresh_until must be RFC3339 UTC time.", freshUntilOK))
	verification.Checks = append(verification.Checks, witnessVerificationCheck("freshness_seconds", "Freshness window", fields["freshness_seconds"], "Expected freshness_seconds=300.", freshnessOK))
	if capturedOK {
		verification.CapturedAt = capturedAt.Format(time.RFC3339)
	}
	if freshUntilOK {
		verification.FreshUntil = freshUntil.Format(time.RFC3339)
	}
	if freshnessOK {
		verification.FreshnessSeconds = freshnessSeconds
	}

	windowOK := capturedOK && freshUntilOK && freshnessOK && freshUntil.Equal(capturedAt.Add(time.Duration(freshnessSeconds)*time.Second))
	verification.Checks = append(verification.Checks, witnessVerificationCheck("freshness_window", "Freshness math", safeDisplayState(fields["fresh_until"]), "fresh_until must equal captured_at plus the declared window.", windowOK))
	verification.Fresh = freshUntilOK && !now.After(freshUntil)
	verification.Checks = append(verification.Checks, witnessVerificationCheck("fresh_now", "Fresh now", verification.FreshUntil, "The proof must still be inside its freshness window.", verification.Fresh))

	valueBoundaryOK := fields["value_returned"] == "false"
	verification.Checks = append(verification.Checks, witnessVerificationCheck("value_boundary", "Value boundary", fields["value_returned"], "Expected value_returned=false.", valueBoundaryOK))

	structureOK := parseOK && schemaOK && flowOK && signalOK && bodyFieldOK && requestIDOK && capturedOK && freshUntilOK && freshnessOK && windowOK && valueBoundaryOK
	if structureOK {
		sum := sha256.Sum256([]byte(proofLine))
		expectedHash := hex.EncodeToString(sum[:])
		verification.ExpectedHash = expectedHash
		verification.HashMatch = providedHash != "" && providedHash == expectedHash
		verification.Checks = append(verification.Checks, witnessVerificationCheck("hash_match", "Hash match", safeDisplayState(providedHash), "The provided hash must match the SHA-256 of the proof line.", verification.HashMatch))
	} else {
		verification.Checks = append(verification.Checks, witnessVerificationCheck("hash_match", "Hash match", "not_checked", "Hash is checked only after the proof line has the expected Janus shape.", false))
	}

	verification.Verified = structureOK && verification.HashMatch && verification.Fresh
	if verification.Verified {
		verification.Status = "verified"
		verification.Summary = "The witness receipt hash matches and the proof is fresh."
	} else if structureOK && verification.HashMatch {
		verification.Status = "stale"
		verification.Summary = "The witness receipt hash matches, but the freshness window has expired."
	} else if structureOK {
		verification.Status = "mismatch"
		verification.Summary = "The witness receipt has the right shape, but the hash does not match."
	}
	return verification
}

func VerifyAuthenticatedBrowserProofPack(proofPack string, now time.Time) WitnessReceiptVerification {
	req, packChecks, packOK := WitnessReceiptVerificationRequestFromProofPack(proofPack)
	verification := VerifyAuthenticatedBrowserCaptureReceipt(req, now)
	verification.Checks = append(packChecks, verification.Checks...)
	if !packOK {
		verification.Status = "blocked"
		verification.Summary = "The proof pack could not be verified."
		verification.Verified = false
	}
	return verification
}

func WitnessReceiptVerificationRequestFromProofPack(proofPack string) (WitnessReceiptVerificationRequest, []WitnessReceiptVerificationCheck, bool) {
	fields := map[string]string{}
	checks := []WitnessReceiptVerificationCheck{}
	ok := true
	proofPack = strings.ReplaceAll(proofPack, "\r\n", "\n")
	proofPack = strings.TrimSpace(proofPack)
	if proofPack == "" {
		return WitnessReceiptVerificationRequest{}, []WitnessReceiptVerificationCheck{
			witnessVerificationCheck("proof_pack_input", "Proof pack", "missing", "Paste a Janus current-session proof pack.", false),
		}, false
	}
	if len(proofPack) > 8192 {
		return WitnessReceiptVerificationRequest{}, []WitnessReceiptVerificationCheck{
			witnessVerificationCheck("proof_pack_size", "Proof pack size", "invalid", "Proof pack input is larger than the Janus verifier accepts.", false),
		}, false
	}

	allowed := map[string]bool{
		"handoff":                          true,
		"signed_browser_capture":           true,
		"proof_pack_contains_verification": true,
		"current_session_verified":         true,
		"schema":                           true,
		"state":                            true,
		"flow":                             true,
		"signal":                           true,
		"body_field":                       true,
		"request_id":                       true,
		"captured_at":                      true,
		"fresh_until":                      true,
		"freshness_seconds":                true,
		"witness_proof_line":               true,
		"witness_algorithm":                true,
		"witness_hash":                     true,
		"witness_hash_header":              true,
		"witness_hash_body_field":          true,
		"verification_status":              true,
		"verification_verified":            true,
		"verification_hash_match":          true,
		"verification_fresh":               true,
		"verification_algorithm":           true,
		"verification_hash":                true,
		"verification_hash_header":         true,
		"verification_hash_body_field":     true,
		"verification_receipt_line":        true,
		"copy_safe":                        true,
		"input_returned":                   true,
		"request_body_returned":            true,
		"identity_values_returned":         true,
		"subject_returned":                 true,
		"email_returned":                   true,
		"name_returned":                    true,
		"claim_values_returned":            true,
		"group_values_returned":            true,
		"token_returned":                   true,
		"cookie_value_returned":            true,
		"env_values_returned":              true,
		"backend_path_returned":            true,
		"connector_output_returned":        true,
		"permit_payload_returned":          true,
		"secret_value_returned":            true,
		"value_returned":                   true,
	}
	lines := strings.Split(proofPack, "\n")
	headerSeen := false
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if !headerSeen {
			headerSeen = true
			if line != "janus_current_session_witness_proof" {
				checks = append(checks, witnessVerificationCheck("proof_pack_header", "Proof pack", "invalid", "Expected a Janus current-session proof pack.", false))
				ok = false
			}
			continue
		}
		key, value, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !found || key == "" {
			checks = append(checks, witnessVerificationCheck("proof_pack_shape", "Proof pack shape", "invalid", "Every proof-pack line must use key=value.", false))
			ok = false
			continue
		}
		if !allowed[key] {
			checks = append(checks, witnessVerificationCheck("proof_pack_unexpected_field", "Proof pack field", safeDisplayState(key), "Only Janus proof-pack fields are accepted.", false))
			ok = false
			continue
		}
		if _, exists := fields[key]; exists {
			checks = append(checks, witnessVerificationCheck("proof_pack_duplicate_field", "Proof pack duplicate", safeDisplayState(key), "Each proof-pack field may appear once.", false))
			ok = false
			continue
		}
		fields[key] = value
	}
	if !headerSeen {
		checks = append(checks, witnessVerificationCheck("proof_pack_header", "Proof pack", "missing", "Expected a Janus current-session proof pack.", false))
		ok = false
	}

	required := []string{
		"handoff",
		"signed_browser_capture",
		"proof_pack_contains_verification",
		"current_session_verified",
		"witness_proof_line",
		"witness_algorithm",
		"witness_hash",
		"witness_hash_header",
		"witness_hash_body_field",
		"verification_status",
		"verification_verified",
		"verification_hash_match",
		"verification_fresh",
		"verification_algorithm",
		"verification_hash",
		"verification_hash_header",
		"verification_hash_body_field",
		"verification_receipt_line",
		"copy_safe",
		"input_returned",
		"request_body_returned",
		"value_returned",
	}
	for _, key := range required {
		if fields[key] == "" {
			checks = append(checks, witnessVerificationCheck("proof_pack_missing_"+key, "Proof pack field", key, "The proof pack is missing a required copy-safe field.", false))
			ok = false
		}
	}
	for key, want := range map[string]string{
		"handoff":                          "reviewer_ready",
		"signed_browser_capture":           "true",
		"proof_pack_contains_verification": "true",
		"current_session_verified":         "true",
		"witness_algorithm":                "sha256-witness-v1",
		"witness_hash_header":              "X-Janus-Witness-Hash",
		"witness_hash_body_field":          "receipt.hash",
		"verification_status":              "verified",
		"verification_verified":            "true",
		"verification_hash_match":          "true",
		"verification_fresh":               "true",
		"verification_algorithm":           "sha256-witness-verification-v1",
		"verification_hash_header":         "X-Janus-Witness-Verification-Hash",
		"verification_hash_body_field":     "verification.receipt.hash",
		"copy_safe":                        "true",
		"input_returned":                   "false",
		"request_body_returned":            "false",
		"value_returned":                   "false",
	} {
		if fields[key] == "" {
			continue
		}
		match := fields[key] == want
		displayKey := strings.TrimPrefix(key, "proof_pack_")
		checkKey := "proof_pack_" + displayKey
		checks = append(checks, witnessVerificationCheck(checkKey, "Proof pack "+strings.ReplaceAll(displayKey, "_", " "), fields[key], "Expected "+key+"="+want+".", match))
		ok = ok && match
	}
	if fields["witness_hash"] != "" {
		hashOK := isLowerHexString(fields["witness_hash"], 64)
		checks = append(checks, witnessVerificationCheck("proof_pack_witness_hash", "Proof pack hash", fields["witness_hash"], "Expected a 64-character lowercase witness hash.", hashOK))
		ok = ok && hashOK
	}
	witnessFields := map[string]string{}
	if fields["witness_proof_line"] != "" {
		var proofLineOK bool
		witnessFields, _, proofLineOK = parseWitnessProofLine(fields["witness_proof_line"])
		checks = append(checks, witnessVerificationCheck("proof_pack_witness_line_shape", "Proof pack witness line", proofPackMatchState(proofLineOK), "The embedded witness line must have the expected Janus shape.", proofLineOK))
		ok = ok && proofLineOK
		if proofLineOK {
			witnessMatchOK := true
			for _, key := range []string{"schema", "state", "flow", "signal", "body_field", "request_id", "captured_at", "fresh_until", "freshness_seconds", "value_returned"} {
				if fields[key] == "" {
					continue
				}
				match := fields[key] == witnessFields[key]
				witnessMatchOK = witnessMatchOK && match
			}
			checks = append(checks, witnessVerificationCheck("proof_pack_witness_line_matches", "Proof pack witness fields", proofPackMatchState(witnessMatchOK), "Top-level proof-pack fields must match the embedded witness line.", witnessMatchOK))
			ok = ok && witnessMatchOK
		}
	}
	if fields["verification_hash"] != "" {
		hashOK := isLowerHexString(fields["verification_hash"], 64)
		checks = append(checks, witnessVerificationCheck("proof_pack_verification_hash", "Proof pack verification hash", fields["verification_hash"], "Expected a 64-character lowercase verification hash.", hashOK))
		ok = ok && hashOK
	}
	if fields["verification_receipt_line"] != "" {
		receiptFields, receiptLineOK := parseWitnessVerificationLine(fields["verification_receipt_line"])
		checks = append(checks, witnessVerificationCheck("proof_pack_verification_receipt_shape", "Proof pack verification receipt", proofPackMatchState(receiptLineOK), "The embedded verification receipt must have the expected Janus shape.", receiptLineOK))
		ok = ok && receiptLineOK
		if receiptLineOK {
			sum := sha256.Sum256([]byte(fields["verification_receipt_line"]))
			receiptHash := hex.EncodeToString(sum[:])
			hashMatch := fields["verification_hash"] != "" && fields["verification_hash"] == receiptHash
			checks = append(checks, witnessVerificationCheck("proof_pack_verification_hash_match", "Proof pack verification hash match", proofPackMatchState(hashMatch), "The verification hash must match the embedded verification receipt line.", hashMatch))
			receiptMatches := receiptFields["schema"] == witnessVerificationReceiptSchema &&
				receiptFields["status"] == fields["verification_status"] &&
				receiptFields["hash_match"] == fields["verification_hash_match"] &&
				receiptFields["fresh"] == fields["verification_fresh"] &&
				receiptFields["verified"] == fields["verification_verified"] &&
				receiptFields["expected_hash"] == fields["witness_hash"] &&
				receiptFields["source_schema"] == fields["schema"] &&
				receiptFields["source_state"] == fields["state"] &&
				receiptFields["source_flow"] == fields["flow"] &&
				receiptFields["source_request_id"] == fields["request_id"] &&
				receiptFields["captured_at"] == fields["captured_at"] &&
				receiptFields["fresh_until"] == fields["fresh_until"] &&
				receiptFields["freshness_seconds"] == fields["freshness_seconds"] &&
				receiptFields["input_returned"] == "false" &&
				receiptFields["request_body_returned"] == "false" &&
				receiptFields["value_returned"] == "false"
			if len(witnessFields) > 0 {
				receiptMatches = receiptMatches && receiptFields["source_request_id"] == witnessFields["request_id"]
			}
			checks = append(checks, witnessVerificationCheck("proof_pack_verification_receipt_matches", "Proof pack verification receipt fields", proofPackMatchState(receiptMatches), "Verification receipt fields must match the proof-pack witness fields.", receiptMatches))
			ok = ok && hashMatch && receiptMatches
		}
	}
	if ok {
		checks = append(checks, witnessVerificationCheck("proof_pack_shape", "Proof pack shape", "valid", "The proof pack contains the expected Janus field set.", true))
	}
	return WitnessReceiptVerificationRequest{
		ProofLine: fields["witness_proof_line"],
		ProofHash: fields["witness_hash"],
	}, checks, ok
}

func parseWitnessVerificationLine(line string) (map[string]string, bool) {
	fields := map[string]string{}
	ok := true
	allowed := map[string]bool{
		"schema":                true,
		"verifier_request_id":   true,
		"status":                true,
		"source_schema":         true,
		"source_state":          true,
		"source_flow":           true,
		"source_request_id":     true,
		"captured_at":           true,
		"fresh_until":           true,
		"freshness_seconds":     true,
		"expected_hash":         true,
		"hash_match":            true,
		"fresh":                 true,
		"verified":              true,
		"input_returned":        true,
		"request_body_returned": true,
		"value_returned":        true,
	}
	required := []string{
		"schema",
		"verifier_request_id",
		"status",
		"source_schema",
		"source_state",
		"source_flow",
		"source_request_id",
		"captured_at",
		"fresh_until",
		"freshness_seconds",
		"expected_hash",
		"hash_match",
		"fresh",
		"verified",
		"input_returned",
		"request_body_returned",
		"value_returned",
	}
	for _, part := range strings.Fields(strings.TrimSpace(line)) {
		key, value, found := strings.Cut(part, "=")
		if !found || strings.TrimSpace(key) == "" || !allowed[key] {
			ok = false
			continue
		}
		if _, exists := fields[key]; exists {
			ok = false
			continue
		}
		fields[key] = value
	}
	for _, key := range required {
		if fields[key] == "" {
			ok = false
		}
	}
	return fields, ok
}

func proofPackMatchState(ok bool) string {
	if ok {
		return "match"
	}
	return "mismatch"
}

func WitnessReceiptVerificationReceiptFor(verification WitnessReceiptVerification, requestID string) WitnessVerificationReceipt {
	requestID = sanitizeRequestID(requestID)
	input := WitnessReceiptVerificationLineFor(verification, requestID)
	sum := sha256.Sum256([]byte(input))
	return WitnessVerificationReceipt{
		Schema:              witnessVerificationReceiptSchema,
		Algorithm:           "sha256-witness-verification-v1",
		Hash:                hex.EncodeToString(sum[:]),
		HashHeader:          "X-Janus-Witness-Verification-Hash",
		BodyField:           "verification.receipt.hash",
		Input:               input,
		RequestID:           requestID,
		Status:              safeDisplayState(verification.Status),
		HashMatch:           verification.HashMatch,
		Fresh:               verification.Fresh,
		Verified:            verification.Verified,
		InputReturned:       false,
		RequestBodyReturned: false,
		ValueReturned:       false,
	}
}

func WitnessReceiptVerificationLineFor(verification WitnessReceiptVerification, requestID string) string {
	return "schema=" + witnessVerificationReceiptSchema +
		" verifier_request_id=" + safeDisplayState(requestID) +
		" status=" + safeDisplayState(verification.Status) +
		" source_schema=" + safeDisplayState(verification.Schema) +
		" source_state=" + safeDisplayState(verification.State) +
		" source_flow=" + safeDisplayState(verification.Flow) +
		" source_request_id=" + safeDisplayState(verification.RequestID) +
		" captured_at=" + safeDisplayState(verification.CapturedAt) +
		" fresh_until=" + safeDisplayState(verification.FreshUntil) +
		" freshness_seconds=" + strconv.Itoa(verification.FreshnessSeconds) +
		" expected_hash=" + safeDisplayState(verification.ExpectedHash) +
		" hash_match=" + strconv.FormatBool(verification.HashMatch) +
		" fresh=" + strconv.FormatBool(verification.Fresh) +
		" verified=" + strconv.FormatBool(verification.Verified) +
		" input_returned=false" +
		" request_body_returned=false" +
		" value_returned=false"
}

func parseWitnessProofLine(proofLine string) (map[string]string, []WitnessReceiptVerificationCheck, bool) {
	fields := map[string]string{}
	checks := []WitnessReceiptVerificationCheck{}
	ok := true
	allowed := map[string]bool{
		"schema":            true,
		"state":             true,
		"flow":              true,
		"signal":            true,
		"body_field":        true,
		"request_id":        true,
		"captured_at":       true,
		"fresh_until":       true,
		"freshness_seconds": true,
		"value_returned":    true,
	}
	required := []string{"schema", "state", "flow", "signal", "body_field", "request_id", "captured_at", "fresh_until", "freshness_seconds", "value_returned"}
	for _, part := range strings.Fields(proofLine) {
		key, value, found := strings.Cut(part, "=")
		if !found || strings.TrimSpace(key) == "" {
			checks = append(checks, witnessVerificationCheck("receipt_shape", "Receipt shape", "invalid", "Every proof token must use key=value.", false))
			ok = false
			continue
		}
		if !allowed[key] {
			checks = append(checks, witnessVerificationCheck("unexpected_field", "Unexpected field", safeDisplayState(key), "Only Janus witness receipt fields are accepted.", false))
			ok = false
			continue
		}
		if _, exists := fields[key]; exists {
			checks = append(checks, witnessVerificationCheck("duplicate_field", "Duplicate field", safeDisplayState(key), "Each proof field may appear once.", false))
			ok = false
			continue
		}
		fields[key] = value
	}
	for _, key := range required {
		if fields[key] == "" {
			checks = append(checks, witnessVerificationCheck("missing_"+key, "Missing field", key, "The proof line is missing "+key+".", false))
			ok = false
		}
	}
	if ok {
		checks = append(checks, witnessVerificationCheck("receipt_shape", "Receipt shape", "valid", "The receipt contains the expected Janus field set.", true))
	}
	return fields, checks, ok
}

func authenticatedBrowserFlowAllowed(state, flow string) bool {
	allowed := map[string]string{
		"authenticated": "zitadel_oidc_pkce_to_signed_session",
		"local_smoke":   "local_dev_signed_session",
		"setup_only":    "oidc_setup_required",
		"missing":       "login_required",
	}
	return allowed[state] == flow
}

func parseWitnessTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func parseWitnessFreshnessSeconds(value string) (int, bool) {
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds != int(authenticatedBrowserCaptureFreshness.Seconds()) {
		return 0, false
	}
	return seconds, true
}

func isLowerHexString(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, ch := range value {
		if ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f' {
			continue
		}
		return false
	}
	return true
}

func safeDisplayState(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "missing"
	}
	if len(value) > 96 {
		return "invalid"
	}
	for _, ch := range value {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
			continue
		}
		switch ch {
		case '-', '_', '.', ':':
			continue
		default:
			return "invalid"
		}
	}
	return value
}

func witnessVerificationCheck(key, label, state, detail string, ok bool) WitnessReceiptVerificationCheck {
	tone := "ok"
	if !ok {
		tone = "warn"
	}
	if state == "" {
		state = "missing"
	}
	return WitnessReceiptVerificationCheck{
		Key:    key,
		Label:  label,
		State:  safeDisplayState(state),
		Detail: detail,
		Tone:   tone,
	}
}

func AuthenticatedBrowserCaptureHeadersFor(witness AuthenticatedBrowserWitness, capture AuthenticatedBrowserCapture, requestID string, receipt AuthenticatedBrowserCaptureReceipt) []AuthenticatedBrowserCaptureHeader {
	return []AuthenticatedBrowserCaptureHeader{
		authenticatedBrowserCaptureHeader("X-Request-Id", requestID),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-Schema", capture.Schema),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-State", witness.State),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-Flow", witness.Flow),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-Signal", witness.EvidenceSignal),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-Body-Field", capture.BodyField),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-Algorithm", receipt.Algorithm),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-Hash", receipt.Hash),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-Hash-Body-Field", receipt.BodyField),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-Captured-At", receipt.CapturedAt),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-Fresh-Until", receipt.FreshUntil),
		authenticatedBrowserCaptureHeader("X-Janus-Witness-Freshness-Seconds", strconv.Itoa(receipt.FreshnessSeconds)),
		authenticatedBrowserCaptureHeader("X-Janus-Value-Returned", "false"),
	}
}

func AuthenticatedBrowserCaptureLineFor(witness AuthenticatedBrowserWitness, capture AuthenticatedBrowserCapture, requestID string, capturedAt time.Time) string {
	capturedAt = capturedAt.UTC().Truncate(time.Second)
	freshUntil := capturedAt.Add(authenticatedBrowserCaptureFreshness)
	return "schema=" + capture.Schema +
		" state=" + witness.State +
		" flow=" + witness.Flow +
		" signal=" + witness.EvidenceSignal +
		" body_field=" + capture.BodyField +
		" request_id=" + requestID +
		" captured_at=" + capturedAt.Format(time.RFC3339) +
		" fresh_until=" + freshUntil.Format(time.RFC3339) +
		" freshness_seconds=" + strconv.Itoa(int(authenticatedBrowserCaptureFreshness.Seconds())) +
		" value_returned=false"
}

func AuthenticatedBrowserCaptureReceiptFor(witness AuthenticatedBrowserWitness, capture AuthenticatedBrowserCapture, requestID string, capturedAt time.Time) AuthenticatedBrowserCaptureReceipt {
	capturedAt = capturedAt.UTC().Truncate(time.Second)
	freshUntil := capturedAt.Add(authenticatedBrowserCaptureFreshness)
	input := AuthenticatedBrowserCaptureLineFor(witness, capture, requestID, capturedAt)
	sum := sha256.Sum256([]byte(input))
	return AuthenticatedBrowserCaptureReceipt{
		Algorithm:        "sha256-witness-v1",
		Hash:             hex.EncodeToString(sum[:]),
		HashHeader:       "X-Janus-Witness-Hash",
		BodyField:        "receipt.hash",
		Input:            input,
		CapturedAt:       capturedAt.Format(time.RFC3339),
		FreshUntil:       freshUntil.Format(time.RFC3339),
		FreshnessSeconds: int(authenticatedBrowserCaptureFreshness.Seconds()),
		ValueReturned:    false,
	}
}

func AuthenticatedBrowserCaptureTextFor(witness AuthenticatedBrowserWitness, capture AuthenticatedBrowserCapture, requestID string, receipt AuthenticatedBrowserCaptureReceipt) string {
	return "janus_session_witness\n" +
		"schema=" + capture.Schema + "\n" +
		"state=" + witness.State + "\n" +
		"flow=" + witness.Flow + "\n" +
		"signal=" + witness.EvidenceSignal + "\n" +
		"body_field=" + capture.BodyField + "\n" +
		"request_id=" + requestID + "\n" +
		"captured_at=" + receipt.CapturedAt + "\n" +
		"fresh_until=" + receipt.FreshUntil + "\n" +
		"freshness_seconds=" + strconv.Itoa(receipt.FreshnessSeconds) + "\n" +
		"proof_line=" + receipt.Input + "\n" +
		"proof_algorithm=" + receipt.Algorithm + "\n" +
		"proof_hash=" + receipt.Hash + "\n" +
		"proof_hash_header=" + receipt.HashHeader + "\n" +
		"proof_hash_body_field=" + receipt.BodyField + "\n" +
		"copy_safe=true\n" +
		"replay_safe=true\n" +
		"identity_values_returned=false\n" +
		"subject_returned=false\n" +
		"email_returned=false\n" +
		"name_returned=false\n" +
		"claim_values_returned=false\n" +
		"group_values_returned=false\n" +
		"token_returned=false\n" +
		"cookie_value_returned=false\n" +
		"request_body_returned=false\n" +
		"env_values_returned=false\n" +
		"backend_path_returned=false\n" +
		"connector_output_returned=false\n" +
		"permit_payload_returned=false\n" +
		"secret_value_returned=false\n" +
		"value_returned=false\n"
}

func CurrentSessionWitnessProofTextFor(witness AuthenticatedBrowserWitness, capture AuthenticatedBrowserCapture, requestID string, witnessReceipt AuthenticatedBrowserCaptureReceipt, verification WitnessReceiptVerification) string {
	verificationReceiptHash := ""
	verificationReceiptAlgorithm := ""
	verificationReceiptHashHeader := ""
	verificationReceiptBodyField := ""
	verificationReceiptInput := ""
	if verification.Receipt != nil {
		verificationReceiptHash = verification.Receipt.Hash
		verificationReceiptAlgorithm = verification.Receipt.Algorithm
		verificationReceiptHashHeader = verification.Receipt.HashHeader
		verificationReceiptBodyField = verification.Receipt.BodyField
		verificationReceiptInput = verification.Receipt.Input
	}
	return "janus_current_session_witness_proof\n" +
		"handoff=reviewer_ready\n" +
		"signed_browser_capture=true\n" +
		"proof_pack_contains_verification=true\n" +
		"current_session_verified=" + strconv.FormatBool(verification.Verified) + "\n" +
		"schema=" + capture.Schema + "\n" +
		"state=" + witness.State + "\n" +
		"flow=" + witness.Flow + "\n" +
		"signal=" + witness.EvidenceSignal + "\n" +
		"body_field=" + capture.BodyField + "\n" +
		"request_id=" + requestID + "\n" +
		"captured_at=" + witnessReceipt.CapturedAt + "\n" +
		"fresh_until=" + witnessReceipt.FreshUntil + "\n" +
		"freshness_seconds=" + strconv.Itoa(witnessReceipt.FreshnessSeconds) + "\n" +
		"witness_proof_line=" + witnessReceipt.Input + "\n" +
		"witness_algorithm=" + witnessReceipt.Algorithm + "\n" +
		"witness_hash=" + witnessReceipt.Hash + "\n" +
		"witness_hash_header=" + witnessReceipt.HashHeader + "\n" +
		"witness_hash_body_field=" + witnessReceipt.BodyField + "\n" +
		"verification_status=" + verification.Status + "\n" +
		"verification_verified=" + strconv.FormatBool(verification.Verified) + "\n" +
		"verification_hash_match=" + strconv.FormatBool(verification.HashMatch) + "\n" +
		"verification_fresh=" + strconv.FormatBool(verification.Fresh) + "\n" +
		"verification_algorithm=" + verificationReceiptAlgorithm + "\n" +
		"verification_hash=" + verificationReceiptHash + "\n" +
		"verification_hash_header=" + verificationReceiptHashHeader + "\n" +
		"verification_hash_body_field=" + verificationReceiptBodyField + "\n" +
		"verification_receipt_line=" + verificationReceiptInput + "\n" +
		"copy_safe=true\n" +
		"input_returned=false\n" +
		"request_body_returned=false\n" +
		"identity_values_returned=false\n" +
		"subject_returned=false\n" +
		"email_returned=false\n" +
		"name_returned=false\n" +
		"claim_values_returned=false\n" +
		"group_values_returned=false\n" +
		"token_returned=false\n" +
		"cookie_value_returned=false\n" +
		"env_values_returned=false\n" +
		"backend_path_returned=false\n" +
		"connector_output_returned=false\n" +
		"permit_payload_returned=false\n" +
		"secret_value_returned=false\n" +
		"value_returned=false\n"
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
