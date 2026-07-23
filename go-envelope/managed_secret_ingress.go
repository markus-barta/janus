package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	managedStepUpFlowTTL       = 5 * time.Minute
	managedStepUpProofTTL      = 2 * time.Minute
	managedStepUpClockSkew     = 30 * time.Second
	managedFormPrefixMaxBytes  = 384
	managedStepUpFlowDomain    = "inspr.janus.managed-step-up-flow.v1"
	managedStepUpProofDomain   = "inspr.janus.managed-step-up-proof.v1"
	managedLoginIntentDomain   = "inspr.janus.managed-login-intent.v1"
	managedSecretFormMediaType = "application/x-www-form-urlencoded"
)

type managedStepUpFlow struct {
	Schema          string `json:"schema"`
	IntentRef       string `json:"intent_ref"`
	Source          string `json:"source"`
	HumanSessionRef string `json:"human_session_ref"`
	StateHash       string `json:"state_hash"`
	IssuedAt        int64  `json:"issued_at"`
	ExpiresAt       int64  `json:"expires_at"`
}

type managedStepUpProof struct {
	Schema          string `json:"schema"`
	IntentRef       string `json:"intent_ref"`
	Source          string `json:"source"`
	HumanSessionRef string `json:"human_session_ref"`
	AuthenticatedAt int64  `json:"authenticated_at"`
	ExpiresAt       int64  `json:"expires_at"`
}

type managedLoginIntent struct {
	Schema    string `json:"schema"`
	IntentRef string `json:"intent_ref"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

type managedSetupPageData struct {
	Title            string
	ActivePage       string
	CSPNonce         string
	Mode             string
	Session          Session
	SessionRoleBadge string
	CSRF             string
	IntentRef        string
	OperationKind    string
	SelectedSource   string
	AllowGenerated   bool
	AllowImport      bool
	HostRef          string
	ServiceRef       string
	SlotRef          string
	ServiceLabel     string
	SlotLabel        string
	ConsumerLabel    string
	DeliveryLabel    string
	StepUpReady      bool
	RequestID        string
}

func (app *App) handleManagedSetup(w http.ResponseWriter, r *http.Request) {
	managedSecretResponseBoundary(w)
	session := currentSession(r.Context())
	intentRef, ok := exactManagedIntentQuery(r.URL)
	if !ok {
		app.audit(r, "managed_secret.setup.view", "denied", session.Subject, "invalid intent reference")
		app.renderSafeFailure(w, r, http.StatusBadRequest, "setup_link_invalid", "This setup link is not valid. Start again from Pharos.", nil)
		return
	}
	inspection, err := app.inspectManagedSetupIntent(r.Context(), session, intentRef)
	if err != nil {
		app.audit(r, "managed_secret.setup.view", "denied", session.Subject, "intent unavailable")
		app.renderSafeFailure(w, r, managedIntentHTTPStatus(err), "setup_link_unavailable", "This setup request is unavailable or expired. Start again from Pharos.", nil)
		return
	}
	proof, proofOK := app.readManagedStepUpProof(r)
	stepUpReady := proofOK &&
		proof.IntentRef == intentRef &&
		proof.HumanSessionRef == managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject) &&
		containsManagedSource(inspection.Intent.AllowedSources, proof.Source)
	selectedSource := proof.Source
	if !stepUpReady {
		selectedSource = preferredManagedSource(inspection.Intent.AllowedSources)
	}
	app.audit(r, "managed_secret.setup.view", "allowed", session.Subject, "value-free setup context")
	renderTemplateStatus(w, app.templates, "managed_secret_setup", http.StatusOK, managedSetupPageData{
		Title:            "Janus — Service secret",
		ActivePage:       "vault",
		CSPNonce:         cspNonceFromContext(r.Context()),
		Mode:             app.cfg.ProductMode,
		Session:          session,
		SessionRoleBadge: SessionRoleBadge(session),
		CSRF:             app.csrfToken(session),
		IntentRef:        inspection.Intent.IntentRef,
		OperationKind:    inspection.Intent.OperationKind,
		SelectedSource:   selectedSource,
		AllowGenerated:   containsManagedSource(inspection.Intent.AllowedSources, "generated"),
		AllowImport:      containsManagedSource(inspection.Intent.AllowedSources, "import"),
		HostRef:          inspection.Intent.HostRef,
		ServiceRef:       inspection.Intent.ServiceRef,
		SlotRef:          inspection.Intent.SlotRef,
		ServiceLabel:     inspection.Context.ServiceLabel,
		SlotLabel:        inspection.Context.SlotLabel,
		ConsumerLabel:    managedConsumerLabel(inspection.Context.ConsumerKind),
		DeliveryLabel:    managedDeliveryLabel(inspection.Context.DeliveryKind),
		StepUpReady:      stepUpReady,
		RequestID:        requestID(r),
	})
}

func (app *App) handleManagedSetupStepUp(w http.ResponseWriter, r *http.Request) {
	managedSecretResponseBoundary(w)
	session := currentSession(r.Context())
	if !app.managedSetupEnabled() || !app.cfg.RequireAuth || !app.cfg.OIDCConfigured() || app.oauth == nil {
		app.audit(r, "managed_secret.step_up.start", "denied", session.Subject, "managed setup unavailable")
		app.renderSafeFailure(w, r, http.StatusServiceUnavailable, "managed_setup_unavailable", "Managed secret setup is not ready.", nil)
		return
	}
	if !app.exactSameOriginBrowserMutation(r) ||
		!strictFormRequest(r, false) ||
		r.URL.RawQuery != "" ||
		r.ParseForm() != nil ||
		!exactFormKeys(r.PostForm, "csrf_token", "intent_ref", "source") ||
		!hmac.Equal([]byte(app.csrfToken(session)), []byte(r.PostForm.Get("csrf_token"))) {
		app.audit(r, "managed_secret.step_up.start", "denied", session.Subject, "request integrity failed")
		app.renderSafeFailure(w, r, http.StatusForbidden, "request_integrity_failed", "Reload the setup page and try again.", nil)
		return
	}
	intentRef := r.PostForm.Get("intent_ref")
	source := r.PostForm.Get("source")
	inspection, err := app.inspectManagedSetupIntent(r.Context(), session, intentRef)
	if err != nil {
		app.audit(r, "managed_secret.step_up.start", "denied", session.Subject, "intent unavailable")
		app.renderSafeFailure(w, r, managedIntentHTTPStatus(err), "setup_link_unavailable", "This setup request is unavailable or expired. Start again from Pharos.", nil)
		return
	}
	if !containsManagedSource(inspection.Intent.AllowedSources, source) {
		app.audit(r, "managed_secret.step_up.start", "denied", session.Subject, "source unavailable")
		app.renderSafeFailure(w, r, http.StatusForbidden, "source_not_allowed", "That setup choice is not allowed for this service. Start again from Pharos.", nil)
		return
	}

	state := randomToken(32)
	nonce := randomToken(32)
	verifier := oauth2.GenerateVerifier()
	now := time.Now().UTC()
	flow := managedStepUpFlow{
		Schema:          managedStepUpFlowDomain,
		IntentRef:       intentRef,
		Source:          source,
		HumanSessionRef: managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject),
		StateHash:       managedStateHash(state),
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.Add(managedStepUpFlowTTL).Unix(),
	}
	app.clearManagedStepUpProofCookies(w)
	app.writeManagedStepUpFlow(w, flow)
	app.writeOIDCEphemeralCookie(w, app.cfg.StateCookieName(), state)
	app.writeOIDCEphemeralCookie(w, app.cfg.NonceCookieName(), nonce)
	app.writeOIDCEphemeralCookie(w, app.cfg.PKCECookieName(), verifier)
	app.audit(r, "managed_secret.step_up.start", "allowed", session.Subject, "fresh passwordless assertion requested")
	http.Redirect(
		w,
		r,
		app.oauth.AuthCodeURL(
			state,
			oauth2.SetAuthURLParam("nonce", nonce),
			oauth2.SetAuthURLParam("prompt", "login"),
			oauth2.SetAuthURLParam("max_age", "0"),
			oauth2.S256ChallengeOption(verifier),
		),
		http.StatusFound,
	)
}

func (app *App) handleManagedSetupExecute(w http.ResponseWriter, r *http.Request) {
	managedSecretResponseBoundary(w)
	session := currentSession(r.Context())
	if !app.managedSetupEnabled() || !app.cfg.RequireAuth {
		app.audit(r, "managed_secret.execute", "denied", session.Subject, "managed setup unavailable")
		app.renderSafeFailure(w, r, http.StatusServiceUnavailable, "managed_setup_unavailable", "Managed secret setup is not ready.", nil)
		return
	}
	if !app.exactSameOriginBrowserMutation(r) || !strictFormRequest(r, true) || r.URL.RawQuery != "" {
		app.audit(r, "managed_secret.execute", "denied", session.Subject, "request integrity failed")
		app.renderSafeFailure(w, r, http.StatusForbidden, "request_integrity_failed", "Reload the setup page and try again.", nil)
		return
	}
	proof, ok := app.readManagedStepUpProof(r)
	humanSessionRef := managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject)
	if !ok || proof.HumanSessionRef != humanSessionRef {
		app.audit(r, "managed_secret.execute", "denied", session.Subject, "fresh passwordless assertion required")
		app.renderSafeFailure(w, r, http.StatusForbidden, "passwordless_step_up_required", "Confirm with your passkey again before changing this secret.", nil)
		return
	}

	prefix, err := readManagedSecretFormPrefix(r.Body)
	if err != nil {
		app.audit(r, "managed_secret.execute", "denied", session.Subject, "request form invalid")
		app.renderSafeFailure(w, r, http.StatusBadRequest, "request_form_invalid", "Reload the setup page and submit once.", nil)
		return
	}
	defer zeroizeBytes(prefix)
	if !validateManagedSecretFormPrefix(prefix, app.csrfToken(session), proof.IntentRef, proof.Source) {
		app.audit(r, "managed_secret.execute", "denied", session.Subject, "request integrity failed")
		app.renderSafeFailure(w, r, http.StatusForbidden, "request_integrity_failed", "Reload the setup page and try again.", nil)
		return
	}

	// The signed intent is consumed before any value bytes are read. This is an
	// intentional security-over-availability choice: an incomplete upload burns
	// the intent and must restart in Pharos, but no retry can replay a pasted
	// value after Janus has admitted it into memory.
	accepted, err := app.managedSetup.Consume(r.Context(), proof.IntentRef, humanSessionRef, proof.Source)
	if err != nil {
		app.clearManagedStepUpProofCookies(w)
		app.audit(r, "managed_secret.execute", "denied", session.Subject, "intent rejected")
		app.renderSafeFailure(w, r, managedIntentHTTPStatus(err), "setup_request_rejected", "This setup request was already used, expired, or changed. Start again from Pharos.", nil)
		return
	}

	remaining := r.ContentLength - int64(len(prefix))
	if remaining < 0 || remaining > maxRequestBody {
		app.clearManagedStepUpProofCookies(w)
		app.audit(r, "managed_secret.execute", "denied", session.Subject, "request body invalid")
		app.renderSafeFailure(w, r, http.StatusBadRequest, "request_body_invalid", "The value could not be accepted. Start again from Pharos.", nil)
		return
	}
	rawValue := make([]byte, int(remaining))
	defer zeroizeBytes(rawValue)
	if _, err := io.ReadFull(r.Body, rawValue); err != nil || !requestBodyAtEOF(r.Body) {
		app.clearManagedStepUpProofCookies(w)
		app.audit(r, "managed_secret.execute", "denied", session.Subject, "request body incomplete")
		app.renderSafeFailure(w, r, http.StatusBadRequest, "request_body_invalid", "The value could not be accepted. Start again from Pharos.", nil)
		return
	}
	importedValue, err := decodeManagedFormValueInPlace(rawValue)
	if err != nil ||
		accepted.Source == "import" && len(importedValue) == 0 ||
		accepted.Source == "generated" && len(importedValue) != 0 {
		app.clearManagedStepUpProofCookies(w)
		app.audit(r, "managed_secret.execute", "denied", session.Subject, "value shape rejected")
		app.renderSafeFailure(w, r, http.StatusBadRequest, "value_not_accepted", "The value could not be accepted. Start again from Pharos.", nil)
		return
	}

	result, err := app.managedTxn.Execute(r.Context(), accepted, importedValue)
	app.clearManagedStepUpProofCookies(w)
	w.Header().Set("Clear-Site-Data", `"cache", "storage"`)
	if err != nil || result.ValueReturned || result.Phase != "completed" ||
		result.OperationRef != accepted.OperationRef {
		app.audit(r, "managed_secret.execute", "denied", session.Subject, "transaction incomplete")
		app.renderSafeFailure(w, r, http.StatusServiceUnavailable, "secret_change_incomplete", "Janus could not confirm completion. Use the operation status in Pharos before trying again.", nil)
		return
	}
	returnURL, err := managedReturnURL(app.cfg.ManagedSetup.PharosReturnOrigin, result.OperationRef)
	if err != nil {
		app.audit(r, "managed_secret.execute", "denied", session.Subject, "return target unavailable")
		app.renderSafeFailure(w, r, http.StatusServiceUnavailable, "return_target_unavailable", "The secret change completed, but Janus could not open its operation status.", nil)
		return
	}
	app.auditWithRef(r, "managed_secret.execute", "allowed", session.Subject, result.SecretRef, "transaction completed without value return")
	http.Redirect(w, r, returnURL, http.StatusSeeOther)
}

func (app *App) inspectManagedSetupIntent(ctx context.Context, session Session, intentRef string) (managedSetupInspection, error) {
	if !app.managedSetupEnabled() || !validManagedRef("intent_", intentRef) {
		return managedSetupInspection{}, managedIntentError("managed_intent_invalid_request")
	}
	return app.managedSetup.Inspect(ctx, intentRef, managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject))
}

func (app *App) managedSetupEnabled() bool {
	return app.cfg.ManagedSetup != nil && app.managedSetup != nil && app.managedTxn != nil
}

func managedSecretResponseBoundary(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-transform")
	w.Header().Set("Content-Encoding", "identity")
}

func exactManagedIntentQuery(raw *url.URL) (string, bool) {
	if raw == nil || raw.Fragment != "" {
		return "", false
	}
	values := raw.Query()
	if len(values) != 1 || len(values["intent"]) != 1 {
		return "", false
	}
	intentRef := values.Get("intent")
	return intentRef, validManagedRef("intent_", intentRef)
}

func strictFormRequest(r *http.Request, requireBody bool) bool {
	if r == nil || r.Body == nil || len(r.TransferEncoding) != 0 ||
		r.Header.Get("Content-Encoding") != "" ||
		r.ContentLength < 0 || r.ContentLength > maxRequestBody ||
		requireBody && r.ContentLength == 0 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == managedSecretFormMediaType && len(parameters) == 0
}

func exactFormKeys(values url.Values, expected ...string) bool {
	if len(values) != len(expected) {
		return false
	}
	for _, key := range expected {
		items, ok := values[key]
		if !ok || len(items) != 1 {
			return false
		}
	}
	return true
}

func (app *App) exactSameOriginBrowserMutation(r *http.Request) bool {
	if r == nil || r.Method != http.MethodPost {
		return false
	}
	if site := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")); site != "" && site != "same-origin" {
		return false
	}
	expected, err := url.Parse(app.cfg.PublicURL)
	if err != nil || expected.Scheme == "" || expected.Host == "" {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" || strings.Contains(origin, ",") {
		return false
	}
	got, err := url.Parse(origin)
	return err == nil &&
		got.Scheme != "" &&
		got.Host != "" &&
		got.User == nil &&
		got.Path == "" &&
		got.RawQuery == "" &&
		got.Fragment == "" &&
		strings.EqualFold(got.Scheme, expected.Scheme) &&
		strings.EqualFold(got.Host, expected.Host)
}

func readManagedSecretFormPrefix(reader io.Reader) ([]byte, error) {
	const suffix = "&secret_value="
	prefix := make([]byte, 0, managedFormPrefixMaxBytes)
	one := []byte{0}
	for len(prefix) < managedFormPrefixMaxBytes {
		n, err := reader.Read(one)
		if n == 1 {
			prefix = append(prefix, one[0])
			if bytes.HasSuffix(prefix, []byte(suffix)) {
				return prefix, nil
			}
		}
		if err != nil {
			zeroizeBytes(prefix)
			return nil, errors.New("managed secret form prefix unavailable")
		}
		if n == 0 {
			zeroizeBytes(prefix)
			return nil, errors.New("managed secret form prefix stalled")
		}
	}
	zeroizeBytes(prefix)
	return nil, errors.New("managed secret form prefix oversized")
}

func validateManagedSecretFormPrefix(prefix []byte, csrfToken, intentRef, source string) bool {
	const csrfPrefix = "csrf_token="
	const intentSeparator = "&intent_ref="
	const sourceSeparator = "&source="
	const secretSuffix = "&secret_value="
	if !bytes.HasPrefix(prefix, []byte(csrfPrefix)) || !bytes.HasSuffix(prefix, []byte(secretSuffix)) {
		return false
	}
	body := prefix[len(csrfPrefix) : len(prefix)-len(secretSuffix)]
	csrf, rest, ok := bytes.Cut(body, []byte(intentSeparator))
	if !ok {
		return false
	}
	encodedIntent, encodedSource, ok := bytes.Cut(rest, []byte(sourceSeparator))
	if !ok || bytes.Contains(encodedIntent, []byte{'&'}) || bytes.Contains(encodedSource, []byte{'&'}) {
		return false
	}
	return hmac.Equal(csrf, []byte(csrfToken)) &&
		hmac.Equal(encodedIntent, []byte(intentRef)) &&
		hmac.Equal(encodedSource, []byte(source))
}

func decodeManagedFormValueInPlace(raw []byte) ([]byte, error) {
	write := 0
	for read := 0; read < len(raw); read++ {
		switch raw[read] {
		case '&':
			return nil, errors.New("managed secret form has extra fields")
		case '+':
			raw[write] = ' '
			write++
		case '%':
			if read+2 >= len(raw) {
				return nil, errors.New("managed secret form escape is truncated")
			}
			high, okHigh := fromHex(raw[read+1])
			low, okLow := fromHex(raw[read+2])
			if !okHigh || !okLow {
				return nil, errors.New("managed secret form escape is invalid")
			}
			raw[write] = high<<4 | low
			write++
			read += 2
		default:
			raw[write] = raw[read]
			write++
		}
	}
	return raw[:write], nil
}

func fromHex(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func requestBodyAtEOF(reader io.Reader) bool {
	var extra [1]byte
	n, err := reader.Read(extra[:])
	return n == 0 && errors.Is(err, io.EOF)
}

func zeroizeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

func preferredManagedSource(sources []string) string {
	if containsManagedSource(sources, "generated") {
		return "generated"
	}
	if containsManagedSource(sources, "import") {
		return "import"
	}
	return ""
}

func managedConsumerLabel(kind string) string {
	if kind == "managed_service" {
		return "Managed service"
	}
	return "Declared consumer"
}

func managedDeliveryLabel(kind string) string {
	if kind == "private_env_file" {
		return "Private environment file"
	}
	return "Managed delivery"
}

func managedIntentHTTPStatus(err error) int {
	var managed managedIntentError
	if errors.As(err, &managed) {
		switch managed {
		case "managed_intent_unknown":
			return http.StatusNotFound
		case "managed_intent_expired", "managed_intent_replayed", "managed_intent_cancelled", "managed_intent_declaration_drift":
			return http.StatusConflict
		case "managed_intent_pharos_unavailable", "managed_intent_declaration_unavailable", "managed_intent_replay_store_unavailable":
			return http.StatusServiceUnavailable
		}
	}
	return http.StatusForbidden
}

func (app *App) writeOIDCEphemeralCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   app.cfg.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
}

func (app *App) writeManagedStepUpFlow(w http.ResponseWriter, flow managedStepUpFlow) {
	app.writeManagedSignedCookie(w, app.cfg.StepUpFlowCookieName(), managedStepUpFlowDomain, flow, http.SameSiteLaxMode, managedStepUpFlowTTL)
}

func (app *App) writeManagedStepUpProof(w http.ResponseWriter, proof managedStepUpProof) {
	app.writeManagedSignedCookie(w, app.cfg.StepUpProofCookieName(), managedStepUpProofDomain, proof, http.SameSiteStrictMode, managedStepUpProofTTL)
}

func (app *App) writeManagedLoginIntent(w http.ResponseWriter, intentRef string) {
	if !validManagedRef("intent_", intentRef) {
		return
	}
	now := time.Now().UTC()
	app.writeManagedSignedCookie(
		w,
		app.cfg.ManagedLoginCookieName(),
		managedLoginIntentDomain,
		managedLoginIntent{
			Schema:    managedLoginIntentDomain,
			IntentRef: intentRef,
			IssuedAt:  now.Unix(),
			ExpiresAt: now.Add(managedStepUpFlowTTL).Unix(),
		},
		http.SameSiteLaxMode,
		managedStepUpFlowTTL,
	)
}

func (app *App) writeManagedSignedCookie(w http.ResponseWriter, name, domain string, value any, sameSite http.SameSite, ttl time.Duration) {
	raw, err := json.Marshal(value)
	if err != nil {
		return
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    payload + "." + sign(app.cfg.CookieKey, domain+"|"+payload),
		Path:     "/",
		HttpOnly: true,
		Secure:   app.cfg.SecureCookies(),
		SameSite: sameSite,
		MaxAge:   int(ttl.Seconds()),
	})
}

func (app *App) readManagedStepUpFlow(r *http.Request) (managedStepUpFlow, bool, error) {
	cookie, err := firstCookie(r, app.cfg.StepUpFlowCookieName(), stepUpFlowCookie)
	if err != nil {
		return managedStepUpFlow{}, false, nil
	}
	var flow managedStepUpFlow
	if !app.decodeManagedSignedCookie(cookie.Value, managedStepUpFlowDomain, &flow) ||
		flow.Schema != managedStepUpFlowDomain ||
		!validManagedRef("intent_", flow.IntentRef) ||
		!validManagedSource(flow.Source) ||
		!validManagedRef("hsn_", flow.HumanSessionRef) ||
		!isLowerHexString(flow.StateHash, sha256.Size*2) ||
		!validManagedStepUpTimes(flow.IssuedAt, flow.ExpiresAt, managedStepUpFlowTTL, time.Now().UTC()) {
		return managedStepUpFlow{}, true, errors.New("managed step-up flow cookie invalid")
	}
	return flow, true, nil
}

func (app *App) readManagedStepUpProof(r *http.Request) (managedStepUpProof, bool) {
	cookie, err := firstCookie(r, app.cfg.StepUpProofCookieName(), stepUpProofCookie)
	if err != nil {
		return managedStepUpProof{}, false
	}
	var proof managedStepUpProof
	if !app.decodeManagedSignedCookie(cookie.Value, managedStepUpProofDomain, &proof) ||
		proof.Schema != managedStepUpProofDomain ||
		!validManagedRef("intent_", proof.IntentRef) ||
		!validManagedSource(proof.Source) ||
		!validManagedRef("hsn_", proof.HumanSessionRef) ||
		!validManagedStepUpTimes(proof.AuthenticatedAt, proof.ExpiresAt, managedStepUpProofTTL, time.Now().UTC()) {
		return managedStepUpProof{}, false
	}
	return proof, true
}

func (app *App) readManagedLoginIntent(r *http.Request) (string, bool) {
	cookie, err := firstCookie(r, app.cfg.ManagedLoginCookieName(), managedLoginCookie)
	if err != nil {
		return "", false
	}
	var intent managedLoginIntent
	if !app.decodeManagedSignedCookie(cookie.Value, managedLoginIntentDomain, &intent) ||
		intent.Schema != managedLoginIntentDomain ||
		!validManagedRef("intent_", intent.IntentRef) ||
		!validManagedStepUpTimes(intent.IssuedAt, intent.ExpiresAt, managedStepUpFlowTTL, time.Now().UTC()) {
		return "", false
	}
	return intent.IntentRef, true
}

func (app *App) decodeManagedSignedCookie(value, domain string, target any) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 2 ||
		!verify(app.cfg.CookieKey, domain+"|"+parts[0], parts[1]) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	return err == nil && len(raw) <= 1024 && decodeStrictJSON(raw, target) == nil
}

func validManagedStepUpTimes(issuedAt, expiresAt int64, maximum time.Duration, now time.Time) bool {
	if issuedAt <= 0 || expiresAt <= issuedAt ||
		expiresAt-issuedAt > int64(maximum/time.Second) ||
		issuedAt > now.Add(managedStepUpClockSkew).Unix() ||
		now.Unix() >= expiresAt {
		return false
	}
	return true
}

func managedStateHash(state string) string {
	digest := sha256.Sum256([]byte(state))
	return hex.EncodeToString(digest[:])
}

func validManagedPasswordlessAssertion(authTime int64, amr []string, now time.Time) bool {
	if authTime <= 0 ||
		authTime > now.Add(managedStepUpClockSkew).Unix() ||
		now.Unix()-authTime > int64(managedStepUpProofTTL/time.Second) ||
		len(amr) != 2 {
		return false
	}
	// ZITADEL maps a passwordless passkey to exactly `user` + `mfa`.
	// A password with U2F additionally includes `pwd`, so exact matching
	// prevents that weaker flow from satisfying this passwordless gate.
	seen := map[string]bool{}
	for _, method := range amr {
		if seen[method] || method != "user" && method != "mfa" {
			return false
		}
		seen[method] = true
	}
	return seen["user"] && seen["mfa"]
}

func (app *App) completeManagedStepUpCallback(
	w http.ResponseWriter,
	r *http.Request,
	session Session,
	flow managedStepUpFlow,
	state string,
	authTime int64,
	amr []string,
) bool {
	now := time.Now().UTC()
	humanSessionRef := managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject)
	if flow.HumanSessionRef != humanSessionRef ||
		flow.StateHash != managedStateHash(state) ||
		!validManagedPasswordlessAssertion(authTime, amr, now) ||
		!SessionHasPermission(session, PermissionLifecycleEntry) {
		app.clearOIDCLoginCookies(w)
		app.clearManagedStepUpProofCookies(w)
		app.audit(r, "managed_secret.step_up.complete", "denied", session.Subject, "passwordless assertion denied")
		app.renderAuthError(w, r, http.StatusForbidden, "passwordless_step_up_failed", "A fresh passwordless passkey confirmation is required for this secret change.")
		return false
	}
	proof := managedStepUpProof{
		Schema:          managedStepUpProofDomain,
		IntentRef:       flow.IntentRef,
		Source:          flow.Source,
		HumanSessionRef: humanSessionRef,
		AuthenticatedAt: authTime,
		ExpiresAt:       time.Unix(authTime, 0).UTC().Add(managedStepUpProofTTL).Unix(),
	}
	app.writeSession(w, session)
	app.writeManagedStepUpProof(w, proof)
	app.clearOIDCLoginCookies(w)
	app.clearOIDCLoginAttemptCookie(w)
	app.clearManagedLoginIntentCookies(w)
	app.audit(r, "managed_secret.step_up.complete", "allowed", session.Subject, "fresh passwordless assertion accepted")
	http.Redirect(w, r, "/managed-service/setup?intent="+url.QueryEscape(flow.IntentRef), http.StatusFound)
	return true
}

func (app *App) clearManagedStepUpFlowCookies(w http.ResponseWriter) {
	app.clearCookie(w, app.cfg.StepUpFlowCookieName())
	if app.cfg.StepUpFlowCookieName() != stepUpFlowCookie {
		app.clearCookie(w, stepUpFlowCookie)
	}
}

func (app *App) clearManagedStepUpProofCookies(w http.ResponseWriter) {
	app.clearCookie(w, app.cfg.StepUpProofCookieName())
	if app.cfg.StepUpProofCookieName() != stepUpProofCookie {
		app.clearCookie(w, stepUpProofCookie)
	}
}

func (app *App) clearManagedStepUpCookies(w http.ResponseWriter) {
	app.clearManagedStepUpFlowCookies(w)
	app.clearManagedStepUpProofCookies(w)
}

func (app *App) clearManagedLoginIntentCookies(w http.ResponseWriter) {
	app.clearCookie(w, app.cfg.ManagedLoginCookieName())
	if app.cfg.ManagedLoginCookieName() != managedLoginCookie {
		app.clearCookie(w, managedLoginCookie)
	}
}
