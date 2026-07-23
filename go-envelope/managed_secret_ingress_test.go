package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	managedTestSubject   = "managed-user-357"
	managedTestIntentRef = "intent_0123456789abcdef"
	managedTestOpRef     = "op_0123456789abcdef"
	managedTestSecretRef = "sec_0000000000000000"
)

type fakeManagedIntentAuthority struct {
	intent         managedSetupIntent
	inspectCount   int
	consumeCount   int
	inspectErr     error
	consumeErr     error
	replayAfterOne bool
}

func (fake *fakeManagedIntentAuthority) Inspect(_ context.Context, intentRef, humanSessionRef string) (managedSetupIntent, error) {
	fake.inspectCount++
	if fake.inspectErr != nil {
		return managedSetupIntent{}, fake.inspectErr
	}
	if intentRef != fake.intent.IntentRef || humanSessionRef != fake.intent.HumanSessionRef {
		return managedSetupIntent{}, managedIntentError("managed_intent_wrong_user")
	}
	return fake.intent, nil
}

func (fake *fakeManagedIntentAuthority) Consume(_ context.Context, intentRef, humanSessionRef string) (managedAcceptedIntent, error) {
	fake.consumeCount++
	if fake.consumeErr != nil {
		return managedAcceptedIntent{}, fake.consumeErr
	}
	if fake.replayAfterOne && fake.consumeCount > 1 {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_replayed")
	}
	if intentRef != fake.intent.IntentRef || humanSessionRef != fake.intent.HumanSessionRef {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_wrong_user")
	}
	return managedAcceptedIntent{Intent: fake.intent, OperationRef: managedTestOpRef}, nil
}

type fakeManagedTransactionExecutor struct {
	count          int
	expectedValue  []byte
	valueObserved  bool
	retainedBuffer []byte
	err            error
	result         managedTransactionResult
}

func (fake *fakeManagedTransactionExecutor) Execute(_ context.Context, accepted managedAcceptedIntent, importedValue []byte) (managedTransactionResult, error) {
	fake.count++
	fake.valueObserved = bytes.Equal(importedValue, fake.expectedValue)
	fake.retainedBuffer = importedValue
	if accepted.OperationRef != managedTestOpRef {
		return managedTransactionResult{}, errors.New("unexpected operation")
	}
	if fake.err != nil {
		return managedTransactionResult{}, fake.err
	}
	return fake.result, nil
}

type managedReadOrderSpy struct {
	body           []byte
	offset         int
	secretOffset   int
	intentConsumed *bool
	earlyRead      bool
}

func (spy *managedReadOrderSpy) Read(target []byte) (int, error) {
	if spy.offset >= len(spy.body) {
		return 0, io.EOF
	}
	if spy.offset >= spy.secretOffset && !*spy.intentConsumed {
		spy.earlyRead = true
	}
	count := copy(target, spy.body[spy.offset:])
	spy.offset += count
	return count, nil
}

func managedIngressFixture(t *testing.T, source string) (*App, *fakeManagedIntentAuthority, *fakeManagedTransactionExecutor, Session, *http.Cookie, *http.Cookie) {
	t.Helper()
	app := newTestApp(t)
	app.oauth = testOAuthConfig()
	app.cfg.ManagedSetup = &managedSetupRuntimeConfig{
		PharosReturnOrigin: "https://pharos.barta.cm",
	}
	session := Session{
		Subject: managedTestSubject,
		Roles:   []string{RoleViewer, RoleOwner},
		Expiry:  time.Now().UTC().Add(time.Hour),
	}
	intent := managedSetupIntent{
		Schema:                 managedSetupIntentSchema,
		SchemaVersion:          managedIntentContractVersion,
		IntentRef:              managedTestIntentRef,
		OperationKind:          "create",
		Source:                 source,
		HostRef:                "host_0123456789abcdef",
		ServiceRef:             "svc_0123456789abcdef",
		SlotRef:                "slot_0123456789abcdef",
		HumanSessionRef:        managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject),
		IssuerRef:              managedSetupExpectedIssuerRef,
		AudienceRef:            managedSetupExpectedAudienceRef,
		NonceRef:               "nonce_0123456789abcdef",
		DeclarationFingerprint: "decl_0123456789abcdef",
		IssuedAtUnixSeconds:    time.Now().UTC().Add(-time.Minute).Unix(),
		ExpiresAtUnixSeconds:   time.Now().UTC().Add(time.Minute).Unix(),
		ReturnTarget:           "pharos_service",
	}
	authority := &fakeManagedIntentAuthority{intent: intent}
	executor := &fakeManagedTransactionExecutor{result: managedTransactionResult{
		OperationRef:  managedTestOpRef,
		SecretRef:     managedTestSecretRef,
		Mode:          source,
		Phase:         "completed",
		ReasonCode:    "entry_activation_ok",
		ValueReturned: false,
	}}
	app.managedSetup = authority
	app.managedTxn = executor

	sessionWriter := httptest.NewRecorder()
	app.writeSession(sessionWriter, session)
	sessionCookie := cookieByName(t, sessionWriter.Result().Cookies(), hostSessionCookie)
	now := time.Now().UTC()
	proofWriter := httptest.NewRecorder()
	app.writeManagedStepUpProof(proofWriter, managedStepUpProof{
		Schema:          managedStepUpProofDomain,
		IntentRef:       managedTestIntentRef,
		HumanSessionRef: intent.HumanSessionRef,
		AuthenticatedAt: now.Unix(),
		ExpiresAt:       now.Add(managedStepUpProofTTL).Unix(),
	})
	proofCookie := cookieByName(t, proofWriter.Result().Cookies(), hostStepUpProofCookie)
	return app, authority, executor, session, sessionCookie, proofCookie
}

func managedRequest(t *testing.T, app *App, session Session, sessionCookie, proofCookie *http.Cookie, body io.Reader, bodyLength int64) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/managed-service/setup/execute", body)
	request.ContentLength = bodyLength
	request.Header.Set("Content-Type", managedSecretFormMediaType)
	request.Header.Set("Origin", app.cfg.PublicURL)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(sessionCookie)
	request.AddCookie(proofCookie)
	if app.csrfToken(session) == "" {
		t.Fatal("test session should have a CSRF token")
	}
	return request
}

func TestManagedSetupPageRequiresPasskeyBeforeRenderingValueInput(t *testing.T) {
	app, authority, _, _, sessionCookie, proofCookie := managedIngressFixture(t, "import")

	request := httptest.NewRequest(http.MethodGet, "/managed-service/setup?intent="+managedTestIntentRef, nil)
	request.AddCookie(sessionCookie)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected setup page, got %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "Continue with passkey") ||
		strings.Contains(body, `name="secret_value"`) ||
		strings.Contains(body, `type="password"`) {
		t.Fatalf("value input must remain absent before step-up: %s", body)
	}

	request = httptest.NewRequest(http.MethodGet, "/managed-service/setup?intent="+managedTestIntentRef, nil)
	request.AddCookie(sessionCookie)
	request.AddCookie(proofCookie)
	response = httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	body = response.Body.String()
	for _, expected := range []string{
		`type="password"`,
		`name="secret_value"`,
		`autocomplete="off"`,
		`data-1p-ignore`,
		`data-bwignore`,
		"never renders them back",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("stepped-up page should contain %q: %s", expected, body)
		}
	}
	if authority.inspectCount != 2 || strings.Contains(body, "JANUS_IMPORT_CANARY_357") {
		t.Fatalf("setup page should inspect twice and remain value-free: count=%d body=%s", authority.inspectCount, body)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store, no-transform" {
		t.Fatalf("managed setup must not be cached or transformed, got %q", got)
	}
	if got := response.Header().Get("Content-Encoding"); got != "identity" {
		t.Fatalf("managed setup must not be compressed, got %q", got)
	}
	for header, expected := range map[string]string{
		"Content-Security-Policy":      "script-src 'none'",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Resource-Policy": "same-origin",
	} {
		if got := response.Header().Get(header); !strings.Contains(got, expected) {
			t.Fatalf("managed setup %s should contain %q, got %q", header, expected, got)
		}
	}
}

func TestUnauthenticatedManagedSetupPreservesOnlySignedIntentAcrossLogin(t *testing.T) {
	app, _, _, _, _, _ := managedIngressFixture(t, "generated")
	request := httptest.NewRequest(http.MethodGet, "/managed-service/setup?intent="+managedTestIntentRef, nil)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `href="/login?managed=1"`) {
		t.Fatalf("managed setup should render a login choice without losing the intent: status=%d body=%s", response.Code, response.Body.String())
	}
	loginIntentCookie := cookieByName(t, response.Result().Cookies(), hostManagedLoginCookie)
	if !loginIntentCookie.HttpOnly ||
		!loginIntentCookie.Secure ||
		loginIntentCookie.SameSite != http.SameSiteLaxMode ||
		strings.Contains(loginIntentCookie.Value, managedTestIntentRef) {
		t.Fatalf("managed login intent cookie must be opaque, signed, secure, and lax: %#v", loginIntentCookie)
	}
	cookieRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	cookieRequest.AddCookie(loginIntentCookie)
	if intentRef, ok := app.readManagedLoginIntent(cookieRequest); !ok || intentRef != managedTestIntentRef {
		t.Fatalf("managed login cookie did not recover the exact intent: ref=%q ok=%v", intentRef, ok)
	}

	login := httptest.NewRequest(http.MethodGet, "/login?managed=1", nil)
	login.AddCookie(loginIntentCookie)
	loginResponse := httptest.NewRecorder()
	app.handleLogin(loginResponse, login)
	if loginResponse.Code != http.StatusFound {
		t.Fatalf("managed login should start OIDC, got %d body=%s", loginResponse.Code, loginResponse.Body.String())
	}
	for _, cookie := range loginResponse.Result().Cookies() {
		if cookie.Name == hostManagedLoginCookie && cookie.MaxAge < 0 {
			t.Fatalf("managed login start unexpectedly cleared its signed intent: %#v", cookie)
		}
	}

	ordinaryLogin := httptest.NewRequest(http.MethodGet, "/login", nil)
	ordinaryLogin.AddCookie(loginIntentCookie)
	ordinaryResponse := httptest.NewRecorder()
	app.handleLogin(ordinaryResponse, ordinaryLogin)
	cleared := false
	for _, cookie := range ordinaryResponse.Result().Cookies() {
		if cookie.Name == hostManagedLoginCookie && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("ordinary login should clear a stale managed setup intent")
	}
}

func TestManagedStepUpStartsFreshPasswordlessOIDCFlow(t *testing.T) {
	app, authority, _, session, sessionCookie, _ := managedIngressFixture(t, "generated")
	form := url.Values{
		"csrf_token": {app.csrfToken(session)},
		"intent_ref": {managedTestIntentRef},
	}.Encode()
	request := httptest.NewRequest(http.MethodPost, "/managed-service/setup/step-up", strings.NewReader(form))
	request.Header.Set("Content-Type", managedSecretFormMediaType)
	request.Header.Set("Origin", app.cfg.PublicURL)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(sessionCookie)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("expected OIDC redirect, got %d body=%s", response.Code, response.Body.String())
	}
	target, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if target.Query().Get("prompt") != "login" ||
		target.Query().Get("max_age") != "0" ||
		target.Query().Get("nonce") == "" ||
		target.Query().Get("code_challenge") == "" ||
		target.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("step-up redirect is not fresh passwordless PKCE: %s", target.String())
	}
	cookies := response.Result().Cookies()
	flowCookie := cookieByName(t, cookies, hostStepUpFlowCookie)
	stateCookie := cookieByName(t, cookies, hostStateCookie)
	if !flowCookie.HttpOnly || !flowCookie.Secure || flowCookie.SameSite != http.SameSiteLaxMode ||
		stateCookie.Value == "" || authority.inspectCount != 1 {
		t.Fatalf("step-up cookies or intent inspection are invalid: cookies=%#v inspect=%d", cookies, authority.inspectCount)
	}
	callback := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
	callback.AddCookie(flowCookie)
	flow, present, err := app.readManagedStepUpFlow(callback)
	if err != nil || !present ||
		flow.IntentRef != managedTestIntentRef ||
		flow.StateHash != managedStateHash(stateCookie.Value) ||
		flow.HumanSessionRef != authority.intent.HumanSessionRef {
		t.Fatalf("signed step-up flow is not bound: flow=%#v present=%v err=%v", flow, present, err)
	}
}

func TestPasswordlessAssertionRequiresExactZitadelPasskeyAMR(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name     string
		authTime int64
		amr      []string
		want     bool
	}{
		{name: "passwordless", authTime: now.Unix(), amr: []string{"user", "mfa"}, want: true},
		{name: "order independent", authTime: now.Unix(), amr: []string{"mfa", "user"}, want: true},
		{name: "password plus u2f", authTime: now.Unix(), amr: []string{"pwd", "user", "mfa"}},
		{name: "password", authTime: now.Unix(), amr: []string{"pwd"}},
		{name: "otp", authTime: now.Unix(), amr: []string{"otp", "mfa"}},
		{name: "duplicate", authTime: now.Unix(), amr: []string{"user", "user"}},
		{name: "missing mfa", authTime: now.Unix(), amr: []string{"user"}},
		{name: "stale", authTime: now.Add(-managedStepUpProofTTL - time.Second).Unix(), amr: []string{"user", "mfa"}},
		{name: "future", authTime: now.Add(managedStepUpClockSkew + time.Second).Unix(), amr: []string{"user", "mfa"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := validManagedPasswordlessAssertion(test.authTime, test.amr, now); got != test.want {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestManagedStepUpCompletionBindsSubjectStateRoleAndFreshAssertion(t *testing.T) {
	app, _, _, session, _, _ := managedIngressFixture(t, "generated")
	state := "state-0123456789abcdef"
	now := time.Now().UTC()
	flow := managedStepUpFlow{
		Schema:          managedStepUpFlowDomain,
		IntentRef:       managedTestIntentRef,
		HumanSessionRef: managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject),
		StateHash:       managedStateHash(state),
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.Add(managedStepUpFlowTTL).Unix(),
	}
	request := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
	response := httptest.NewRecorder()
	if !app.completeManagedStepUpCallback(response, request, session, flow, state, now.Unix(), []string{"user", "mfa"}) {
		t.Fatalf("expected step-up completion, got %d body=%s", response.Code, response.Body.String())
	}
	if response.Code != http.StatusFound ||
		response.Header().Get("Location") != "/managed-service/setup?intent="+managedTestIntentRef {
		t.Fatalf("unexpected completion redirect: status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	proofCookie := cookieByName(t, response.Result().Cookies(), hostStepUpProofCookie)
	if !proofCookie.HttpOnly || !proofCookie.Secure || proofCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("step-up proof cookie must be host-prefixed, secure, httponly, strict: %#v", proofCookie)
	}

	response = httptest.NewRecorder()
	if app.completeManagedStepUpCallback(response, request, session, flow, state, now.Unix(), []string{"pwd", "user", "mfa"}) {
		t.Fatal("password plus U2F must not satisfy passwordless step-up")
	}
	if response.Code != http.StatusForbidden {
		t.Fatalf("invalid assertion should fail closed, got %d", response.Code)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == hostStepUpProofCookie && cookie.Value != "" {
			t.Fatalf("denied step-up must not mint proof: %#v", cookie)
		}
	}

	deniedSession := session
	deniedSession.Roles = []string{RoleViewer}
	response = httptest.NewRecorder()
	if app.completeManagedStepUpCallback(response, request, deniedSession, flow, state, now.Unix(), []string{"user", "mfa"}) {
		t.Fatal("fresh passkey must not bypass lifecycle.entry authorization")
	}
	if response.Code != http.StatusForbidden {
		t.Fatalf("unauthorized step-up should fail closed, got %d", response.Code)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == hostStepUpProofCookie && cookie.Value != "" {
			t.Fatalf("unauthorized step-up must not mint proof: %#v", cookie)
		}
	}
}

func TestOIDCCallbackCompletesOnlyBoundPasswordlessStepUp(t *testing.T) {
	app, _, _, _, _, _ := managedIngressFixture(t, "generated")
	app.cfg.RolePolicy = RolePolicy{
		OwnerSubjects: map[string]bool{managedTestSubject: true},
	}
	state := "state-0123456789abcdef"
	nonce := "nonce-0123456789abcdef"
	pkce := "pkce-0123456789abcdef0123456789abcdef"
	now := time.Now().UTC()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rawIDToken := signedManagedTestIDToken(t, privateKey, map[string]any{
		"iss":       app.cfg.OIDCIssuer,
		"sub":       managedTestSubject,
		"aud":       app.cfg.OIDCClientID,
		"exp":       now.Add(5 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"auth_time": now.Unix(),
		"nonce":     nonce,
		"amr":       []string{"user", "mfa"},
	})
	tokenServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.ParseForm() != nil ||
			request.Form.Get("code") != "step-up-code" ||
			request.Form.Get("code_verifier") != pkce {
			t.Errorf("unexpected token exchange: method=%s form=%#v", request.Method, request.Form)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"access_token": "synthetic-access-token",
			"token_type":   "Bearer",
			"expires_in":   300,
			"id_token":     rawIDToken,
		})
	}))
	defer tokenServer.Close()
	app.oauth = testOAuthConfig()
	app.oauth.Endpoint.TokenURL = tokenServer.URL
	app.verifier = oidc.NewVerifier(
		app.cfg.OIDCIssuer,
		&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&privateKey.PublicKey}},
		&oidc.Config{ClientID: app.cfg.OIDCClientID},
	)

	flowWriter := httptest.NewRecorder()
	app.writeManagedStepUpFlow(flowWriter, managedStepUpFlow{
		Schema:          managedStepUpFlowDomain,
		IntentRef:       managedTestIntentRef,
		HumanSessionRef: managedHumanSessionRef(app.cfg.OIDCIssuer, managedTestSubject),
		StateHash:       managedStateHash(state),
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.Add(managedStepUpFlowTTL).Unix(),
	})
	request := httptest.NewRequest(http.MethodGet, "/oidc/callback?state="+state+"&code=step-up-code", nil)
	request.AddCookie(cookieByName(t, flowWriter.Result().Cookies(), hostStepUpFlowCookie))
	request.AddCookie(&http.Cookie{Name: hostStateCookie, Value: state})
	request.AddCookie(&http.Cookie{Name: hostNonceCookie, Value: nonce})
	request.AddCookie(&http.Cookie{Name: hostPKCECookie, Value: pkce})
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusFound ||
		response.Header().Get("Location") != "/managed-service/setup?intent="+managedTestIntentRef {
		t.Fatalf("bound passwordless callback did not complete: status=%d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	proofCookie := cookieByName(t, response.Result().Cookies(), hostStepUpProofCookie)
	proofRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	proofRequest.AddCookie(proofCookie)
	proof, ok := app.readManagedStepUpProof(proofRequest)
	if !ok ||
		proof.IntentRef != managedTestIntentRef ||
		proof.HumanSessionRef != managedHumanSessionRef(app.cfg.OIDCIssuer, managedTestSubject) ||
		proof.AuthenticatedAt != now.Unix() {
		t.Fatalf("callback proof is not bound to the assertion: proof=%#v ok=%v", proof, ok)
	}
	sessionCookie := cookieByName(t, response.Result().Cookies(), hostSessionCookie)
	sessionRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	sessionRequest.AddCookie(sessionCookie)
	if session, ok := app.readSession(sessionRequest); !ok ||
		session.Subject != managedTestSubject ||
		!SessionHasPermission(session, PermissionLifecycleEntry) {
		t.Fatalf("callback did not refresh an authorized same-subject session: session=%#v ok=%v", session, ok)
	}
}

func signedManagedTestIDToken(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestManagedImportConsumesIntentBeforeReadingAndZeroizesValue(t *testing.T) {
	app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "import")
	canary := []byte("JANUS_IMPORT_CANARY_357+value")
	executor.expectedValue = canary
	formPrefix := "csrf_token=" + app.csrfToken(session) + "&intent_ref=" + managedTestIntentRef + "&secret_value="
	body := []byte(formPrefix + "JANUS_IMPORT_CANARY_357%2Bvalue")
	consumed := false
	spy := &managedReadOrderSpy{
		body:           body,
		secretOffset:   len(formPrefix),
		intentConsumed: &consumed,
	}
	request := managedRequest(t, app, session, sessionCookie, proofCookie, spy, int64(len(body)))
	response := httptest.NewRecorder()

	// Flip the read-order witness from the authority call itself.
	wrapped := &consumeWitnessAuthority{delegate: authority, consumed: &consumed}
	app.managedSetup = wrapped
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "https://pharos.barta.cm/managed-service/operations/"+managedTestOpRef {
		t.Fatalf("expected safe Pharos redirect, got %d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	if spy.earlyRead || authority.consumeCount != 1 || executor.count != 1 || !executor.valueObserved {
		t.Fatalf("value boundary order failed: early=%v consume=%d execute=%d observed=%v", spy.earlyRead, authority.consumeCount, executor.count, executor.valueObserved)
	}
	if !allZero(executor.retainedBuffer) {
		t.Fatalf("handler-owned imported buffer was not zeroized after transaction: %q", executor.retainedBuffer)
	}
	if got := response.Header().Get("Clear-Site-Data"); got != `"cache", "storage"` {
		t.Fatalf("completion should clear browser cache/storage, got %q", got)
	}
	assertManagedCanaryAbsent(t, app, response, string(canary))
}

type consumeWitnessAuthority struct {
	delegate *fakeManagedIntentAuthority
	consumed *bool
}

func (witness *consumeWitnessAuthority) Inspect(ctx context.Context, intentRef, humanSessionRef string) (managedSetupIntent, error) {
	return witness.delegate.Inspect(ctx, intentRef, humanSessionRef)
}

func (witness *consumeWitnessAuthority) Consume(ctx context.Context, intentRef, humanSessionRef string) (managedAcceptedIntent, error) {
	accepted, err := witness.delegate.Consume(ctx, intentRef, humanSessionRef)
	if err == nil {
		*witness.consumed = true
	}
	return accepted, err
}

func TestManagedGeneratedModeSendsNoValue(t *testing.T) {
	app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "generated")
	form := "csrf_token=" + app.csrfToken(session) + "&intent_ref=" + managedTestIntentRef + "&secret_value="
	request := managedRequest(t, app, session, sessionCookie, proofCookie, strings.NewReader(form), int64(len(form)))
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther ||
		authority.consumeCount != 1 ||
		executor.count != 1 ||
		!executor.valueObserved ||
		len(executor.retainedBuffer) != 0 {
		t.Fatalf("generated execution should contain no value: status=%d consume=%d execute=%d observed=%v len=%d body=%s", response.Code, authority.consumeCount, executor.count, executor.valueObserved, len(executor.retainedBuffer), response.Body.String())
	}
}

func TestManagedIngressRejectsIntegrityFailuresBeforeValueReadOrConsume(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "missing origin", mutate: func(request *http.Request) { request.Header.Del("Origin") }},
		{name: "referer is not origin", mutate: func(request *http.Request) {
			request.Header.Del("Origin")
			request.Header.Set("Referer", "https://vault.barta.cm/managed-service/setup")
		}},
		{name: "cross origin", mutate: func(request *http.Request) { request.Header.Set("Origin", "https://evil.example") }},
		{name: "cross site fetch", mutate: func(request *http.Request) { request.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{name: "content type parameters", mutate: func(request *http.Request) {
			request.Header.Set("Content-Type", managedSecretFormMediaType+"; charset=utf-8")
		}},
		{name: "compressed", mutate: func(request *http.Request) { request.Header.Set("Content-Encoding", "gzip") }},
		{name: "chunked", mutate: func(request *http.Request) {
			request.ContentLength = -1
			request.TransferEncoding = []string{"chunked"}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "import")
			prefix := "csrf_token=" + app.csrfToken(session) + "&intent_ref=" + managedTestIntentRef + "&secret_value="
			body := []byte(prefix + "JANUS_EARLY_READ_CANARY_357")
			consumed := false
			spy := &managedReadOrderSpy{body: body, secretOffset: len(prefix), intentConsumed: &consumed}
			request := managedRequest(t, app, session, sessionCookie, proofCookie, spy, int64(len(body)))
			test.mutate(request)
			response := httptest.NewRecorder()
			app.routes().ServeHTTP(response, request)
			if response.Code == http.StatusSeeOther ||
				authority.consumeCount != 0 ||
				executor.count != 0 ||
				spy.offset != 0 ||
				spy.earlyRead {
				t.Fatalf("integrity failure crossed value boundary: status=%d consume=%d execute=%d read=%d early=%v", response.Code, authority.consumeCount, executor.count, spy.offset, spy.earlyRead)
			}
			assertManagedCanaryAbsent(t, app, response, "JANUS_EARLY_READ_CANARY_357")
		})
	}
}

func TestManagedIngressRejectsBadCSRFBeforeReadingValue(t *testing.T) {
	app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "import")
	prefix := "csrf_token=wrong-token&intent_ref=" + managedTestIntentRef + "&secret_value="
	body := []byte(prefix + "JANUS_CSRF_CANARY_357")
	consumed := false
	spy := &managedReadOrderSpy{body: body, secretOffset: len(prefix), intentConsumed: &consumed}
	request := managedRequest(t, app, session, sessionCookie, proofCookie, spy, int64(len(body)))
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden ||
		authority.consumeCount != 0 ||
		executor.count != 0 ||
		spy.earlyRead ||
		spy.offset != len(prefix) {
		t.Fatalf("bad CSRF should stop at value-free prefix: status=%d consume=%d execute=%d offset=%d early=%v", response.Code, authority.consumeCount, executor.count, spy.offset, spy.earlyRead)
	}
	assertManagedCanaryAbsent(t, app, response, "JANUS_CSRF_CANARY_357")
}

func TestManagedIncompleteBodyIntentionallyBurnsIntentBeforeValueAdmission(t *testing.T) {
	app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "import")
	form := "csrf_token=" + app.csrfToken(session) + "&intent_ref=" + managedTestIntentRef + "&secret_value=partial"
	request := managedRequest(
		t,
		app,
		session,
		sessionCookie,
		proofCookie,
		strings.NewReader(form),
		int64(len(form)+8),
	)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest ||
		authority.consumeCount != 1 ||
		executor.count != 0 {
		t.Fatalf(
			"incomplete upload must burn exactly one intent before value admission: status=%d consume=%d execute=%d",
			response.Code,
			authority.consumeCount,
			executor.count,
		)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == hostStepUpProofCookie && cookie.MaxAge >= 0 {
			t.Fatalf("incomplete upload must clear the step-up proof: %#v", cookie)
		}
	}
	assertManagedCanaryAbsent(t, app, response, "partial")
}

func TestManagedDuplicateSubmitCannotReplayImport(t *testing.T) {
	app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "import")
	authority.replayAfterOne = true
	executor.expectedValue = []byte("one-time-value")
	form := "csrf_token=" + app.csrfToken(session) + "&intent_ref=" + managedTestIntentRef + "&secret_value=one-time-value"

	for attempt := 1; attempt <= 2; attempt++ {
		request := managedRequest(t, app, session, sessionCookie, proofCookie, strings.NewReader(form), int64(len(form)))
		response := httptest.NewRecorder()
		app.routes().ServeHTTP(response, request)
		if attempt == 1 && response.Code != http.StatusSeeOther {
			t.Fatalf("first submit should complete, got %d body=%s", response.Code, response.Body.String())
		}
		if attempt == 2 && response.Code != http.StatusConflict {
			t.Fatalf("duplicate should be a controlled conflict, got %d body=%s", response.Code, response.Body.String())
		}
	}
	if authority.consumeCount != 2 || executor.count != 1 {
		t.Fatalf("duplicate crossed transaction boundary: consume=%d execute=%d", authority.consumeCount, executor.count)
	}
}

func TestManagedFormDecoderIsStrictAndInPlace(t *testing.T) {
	raw := []byte("a%2Bb+c%20d")
	decoded, err := decodeManagedFormValueInPlace(raw)
	if err != nil || string(decoded) != "a+b c d" {
		t.Fatalf("unexpected decode: %q err=%v", decoded, err)
	}
	for _, invalid := range [][]byte{
		[]byte("value&extra=field"),
		[]byte("truncated%"),
		[]byte("bad%XZ"),
	} {
		if _, err := decodeManagedFormValueInPlace(invalid); err == nil {
			t.Fatalf("expected strict rejection for %q", invalid)
		}
	}
	zeroizeBytes(raw)
	if !allZero(raw) {
		t.Fatalf("decoder backing buffer did not zeroize: %q", raw)
	}
}

func TestManagedStepUpCookieTamperAndExpiryFailClosed(t *testing.T) {
	app, _, _, _, _, proofCookie := managedIngressFixture(t, "generated")
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	tampered := *proofCookie
	tampered.Value += "x"
	request.AddCookie(&tampered)
	if _, ok := app.readManagedStepUpProof(request); ok {
		t.Fatal("tampered proof cookie was accepted")
	}

	expiredWriter := httptest.NewRecorder()
	now := time.Now().UTC()
	app.writeManagedStepUpProof(expiredWriter, managedStepUpProof{
		Schema:          managedStepUpProofDomain,
		IntentRef:       managedTestIntentRef,
		HumanSessionRef: managedHumanSessionRef(app.cfg.OIDCIssuer, managedTestSubject),
		AuthenticatedAt: now.Add(-3 * time.Minute).Unix(),
		ExpiresAt:       now.Add(-time.Minute).Unix(),
	})
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(cookieByName(t, expiredWriter.Result().Cookies(), hostStepUpProofCookie))
	if _, ok := app.readManagedStepUpProof(request); ok {
		t.Fatal("expired proof cookie was accepted")
	}
}

func TestManagedValueBoundaryIsNotAddedToOrdinaryAPI(t *testing.T) {
	app := newTestApp(t)
	for _, route := range app.routeSpecs() {
		lower := strings.ToLower(route.pattern)
		if strings.Contains(lower, "managed-service/setup") && strings.Contains(lower, "/api/") {
			t.Fatalf("managed value boundary leaked into ordinary API: %s", route.pattern)
		}
		if strings.Contains(lower, "secret_value") || strings.Contains(lower, "passwordless") {
			t.Fatalf("route vocabulary exposes a value or alternate auth method: %s", route.pattern)
		}
	}
}

func assertManagedCanaryAbsent(t *testing.T, app *App, response *httptest.ResponseRecorder, canary string) {
	t.Helper()
	if strings.Contains(response.Body.String(), canary) ||
		strings.Contains(response.Header().Get("Location"), canary) {
		t.Fatalf("response leaked managed canary %q: headers=%#v body=%s", canary, response.Header(), response.Body.String())
	}
	for _, cookie := range response.Result().Cookies() {
		if strings.Contains(cookie.Value, canary) {
			t.Fatalf("cookie leaked managed canary %q: %#v", canary, cookie)
		}
	}
	audit, err := json.Marshal(app.store.RecentAudit(32))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(audit, []byte(canary)) {
		t.Fatalf("audit leaked managed canary %q: %s", canary, audit)
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
