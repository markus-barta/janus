package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	managedBrowserAssuranceEnv  = "JANUS_MANAGED_BROWSER_ASSURANCE_SERVER"
	managedBrowserAssuranceAddr = "127.0.0.1:18082"
	managedBrowserRemoveIntent  = "intent_abcdef0123456789"
	managedBrowserRemoveOp      = "op_abcdef0123456789"
)

type managedBrowserAuthority struct {
	mu       sync.Mutex
	intents  map[string]managedSetupIntent
	consumed map[string]bool
}

func newManagedBrowserAuthority(issuer string) *managedBrowserAuthority {
	now := time.Now().UTC()
	create := managedSetupIntent{
		Schema:                 managedSetupIntentSchema,
		SchemaVersion:          managedIntentContractVersion,
		IntentRef:              managedTestIntentRef,
		OperationKind:          "create",
		AllowedSources:         []string{"generated", "import"},
		HostRef:                "host_0123456789abcdef",
		ServiceRef:             "svc_0123456789abcdef",
		SlotRef:                "slot_0123456789abcdef",
		HumanSessionRef:        managedHumanSessionRef(issuer, managedTestSubject),
		IssuerRef:              managedSetupExpectedIssuerRef,
		AudienceRef:            managedSetupExpectedAudienceRef,
		NonceRef:               "nonce_0123456789abcdef",
		DeclarationFingerprint: "decl_0123456789abcdef",
		IssuedAtUnixSeconds:    now.Add(-time.Minute).Unix(),
		ExpiresAtUnixSeconds:   now.Add(time.Hour).Unix(),
		ReturnTarget:           "pharos_service",
	}
	remove := create
	remove.IntentRef = managedBrowserRemoveIntent
	remove.OperationKind = "remove"
	remove.AllowedSources = nil
	remove.NonceRef = "nonce_abcdef0123456789"
	return &managedBrowserAuthority{
		intents: map[string]managedSetupIntent{
			create.IntentRef: create,
			remove.IntentRef: remove,
		},
		consumed: make(map[string]bool),
	}
}

func (authority *managedBrowserAuthority) reset(intentRef string) bool {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if _, ok := authority.intents[intentRef]; !ok {
		return false
	}
	delete(authority.consumed, intentRef)
	return true
}

func (authority *managedBrowserAuthority) Inspect(
	_ context.Context,
	intentRef string,
	humanSessionRef string,
) (managedSetupInspection, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	intent, ok := authority.intents[intentRef]
	if !ok {
		return managedSetupInspection{}, managedIntentError("managed_intent_unknown")
	}
	if intent.HumanSessionRef != humanSessionRef {
		return managedSetupInspection{}, managedIntentError("managed_intent_wrong_user")
	}
	return managedSetupInspection{
		Intent:  intent,
		Context: managedBrowserContext(intent),
	}, nil
}

func (authority *managedBrowserAuthority) Consume(
	_ context.Context,
	intentRef string,
	humanSessionRef string,
	source string,
) (managedAcceptedIntent, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	intent, ok := authority.intents[intentRef]
	if !ok {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_unknown")
	}
	if intent.HumanSessionRef != humanSessionRef {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_wrong_user")
	}
	if authority.consumed[intentRef] {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_replayed")
	}
	if intent.OperationKind == "remove" && source != "remove" ||
		intent.OperationKind != "remove" && !containsManagedSource(intent.AllowedSources, source) {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_source_denied")
	}
	authority.consumed[intentRef] = true
	operationRef := managedTestOpRef
	if intent.OperationKind == "remove" {
		operationRef = managedBrowserRemoveOp
	}
	return managedAcceptedIntent{
		Intent:       intent,
		Context:      managedBrowserContext(intent),
		Source:       source,
		OperationRef: operationRef,
	}, nil
}

func managedBrowserContext(intent managedSetupIntent) managedDeclarationContext {
	context := managedDeclarationContext{
		ServiceLabel:       "Managed browser canary",
		SlotLabel:          "Service credential",
		ConsumerKind:       "managed_service",
		DeliveryKind:       "private_env_file",
		DeliveryProfileRef: "delivery_2d7a0f63c951",
		ReloadProfileRef:   "reload_65bc19f3a087",
		HealthProfileRef:   "health_918d0ce7b4a2",
		BindingState:       "required",
		AllowedSources:     append([]string(nil), intent.AllowedSources...),
	}
	if intent.OperationKind == "remove" {
		context.BindingState = "detached"
		context.DetachProfileRef = "detach_8a0f4e271c93"
	}
	return context
}

type managedBrowserExecutor struct {
	mu                 sync.Mutex
	executions         int
	lastValueByteCount int
}

func (executor *managedBrowserExecutor) Execute(
	_ context.Context,
	accepted managedAcceptedIntent,
	importedValue []byte,
) (managedTransactionResult, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if accepted.Source == "import" && len(importedValue) == 0 ||
		accepted.Source != "import" && len(importedValue) != 0 {
		return managedTransactionResult{}, errors.New("managed browser value shape invalid")
	}
	executor.executions++
	executor.lastValueByteCount = len(importedValue)
	return managedTransactionResult{
		OperationRef:  accepted.OperationRef,
		SecretRef:     managedTestSecretRef,
		Mode:          accepted.Source,
		Generation:    1,
		Phase:         "registered",
		ReasonCode:    "managed_operation_registered",
		ValueReturned: false,
	}, nil
}

func (executor *managedBrowserExecutor) evidence() (int, int) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	return executor.executions, executor.lastValueByteCount
}

func (executor *managedBrowserExecutor) reset() {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	executor.executions = 0
	executor.lastValueByteCount = 0
}

type managedBrowserAuthorization struct {
	nonce string
}

type managedBrowserHarness struct {
	app            *App
	routes         http.Handler
	authority      *managedBrowserAuthority
	executor       *managedBrowserExecutor
	privateKey     *rsa.PrivateKey
	baseURL        string
	authorizations map[string]managedBrowserAuthorization
	mu             sync.Mutex
}

func newManagedBrowserHarness(t *testing.T, baseURL string) *managedBrowserHarness {
	t.Helper()
	app := newTestApp(t)
	issuer := baseURL + "/__managed-browser/issuer"
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	authority := newManagedBrowserAuthority(issuer)
	executor := &managedBrowserExecutor{}
	app.cfg.PublicURL = baseURL
	app.cfg.OIDCIssuer = issuer
	app.cfg.OIDCClientID = "managed-browser-client"
	app.cfg.OIDCSecret = "managed-browser-secret"
	app.cfg.RolePolicy = RolePolicy{
		OwnerSubjects: map[string]bool{managedTestSubject: true},
	}
	app.cfg.ManagedSetup = &managedSetupRuntimeConfig{
		PharosReturnOrigin: baseURL,
	}
	app.oauth = &oauth2.Config{
		ClientID:     app.cfg.OIDCClientID,
		ClientSecret: app.cfg.OIDCSecret,
		RedirectURL:  baseURL + "/oidc/callback",
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  baseURL + "/__managed-browser/authorize",
			TokenURL: baseURL + "/__managed-browser/token",
		},
	}
	app.verifier = oidc.NewVerifier(
		issuer,
		&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&privateKey.PublicKey}},
		&oidc.Config{ClientID: app.cfg.OIDCClientID},
	)
	app.managedSetup = authority
	app.managedTxn = executor
	return &managedBrowserHarness{
		app:            app,
		routes:         app.routes(),
		authority:      authority,
		executor:       executor,
		privateKey:     privateKey,
		baseURL:        baseURL,
		authorizations: make(map[string]managedBrowserAuthorization),
	}
}

func (harness *managedBrowserHarness) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/__managed-browser/session":
		harness.session(response, request)
	case "/__managed-browser/expired":
		harness.expired(response, request)
	case "/__managed-browser/authorize":
		harness.authorize(response, request)
	case "/__managed-browser/token":
		harness.token(response, request)
	case "/__managed-browser/evidence":
		harness.evidence(response)
	default:
		if strings.HasPrefix(request.URL.Path, "/managed-service/operations/") {
			harness.operation(response, request)
			return
		}
		harness.routes.ServeHTTP(response, request)
	}
}

func (harness *managedBrowserHarness) session(response http.ResponseWriter, request *http.Request) {
	intentRef := managedTestIntentRef
	if request.URL.Query().Get("kind") == "remove" {
		intentRef = managedBrowserRemoveIntent
	}
	if !harness.authority.reset(intentRef) {
		http.Error(response, "fixture unavailable", http.StatusBadRequest)
		return
	}
	harness.executor.reset()
	harness.writeSession(response)
	response.Header().Set("Cache-Control", "no-store")
	http.Redirect(
		response,
		request,
		"/managed-service/setup?intent="+url.QueryEscape(intentRef),
		http.StatusFound,
	)
}

func (harness *managedBrowserHarness) expired(response http.ResponseWriter, request *http.Request) {
	harness.executor.reset()
	harness.writeSession(response)
	now := time.Now().UTC()
	harness.app.writeManagedStepUpProof(response, managedStepUpProof{
		Schema:          managedStepUpProofDomain,
		IntentRef:       managedTestIntentRef,
		Source:          "import",
		HumanSessionRef: managedHumanSessionRef(harness.app.cfg.OIDCIssuer, managedTestSubject),
		AuthenticatedAt: now.Add(-10 * time.Minute).Unix(),
		ExpiresAt:       now.Add(-5 * time.Minute).Unix(),
	})
	response.Header().Set("Cache-Control", "no-store")
	http.Redirect(
		response,
		request,
		"/managed-service/setup?intent="+url.QueryEscape(managedTestIntentRef),
		http.StatusFound,
	)
}

func (harness *managedBrowserHarness) writeSession(response http.ResponseWriter) {
	harness.app.writeSession(response, Session{
		Subject: managedTestSubject,
		Name:    "Managed browser reviewer",
		Roles:   []string{RoleViewer, RoleOwner},
		Expiry:  time.Now().UTC().Add(time.Hour),
	})
}

func (harness *managedBrowserHarness) authorize(response http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	if request.Method != http.MethodGet ||
		query.Get("redirect_uri") != harness.baseURL+"/oidc/callback" ||
		query.Get("state") == "" ||
		query.Get("nonce") == "" ||
		query.Get("code_challenge") == "" ||
		query.Get("code_challenge_method") != "S256" ||
		query.Get("prompt") != "login" ||
		query.Get("max_age") != "0" {
		http.Error(response, "authorization denied", http.StatusBadRequest)
		return
	}
	code := randomToken(24)
	harness.mu.Lock()
	harness.authorizations[code] = managedBrowserAuthorization{nonce: query.Get("nonce")}
	harness.mu.Unlock()
	callback, _ := url.Parse(query.Get("redirect_uri"))
	callbackQuery := callback.Query()
	callbackQuery.Set("state", query.Get("state"))
	callbackQuery.Set("code", code)
	callback.RawQuery = callbackQuery.Encode()
	response.Header().Set("Cache-Control", "no-store")
	http.Redirect(response, request, callback.String(), http.StatusFound)
}

func (harness *managedBrowserHarness) token(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.ParseForm() != nil ||
		request.Form.Get("grant_type") != "authorization_code" ||
		request.Form.Get("redirect_uri") != harness.baseURL+"/oidc/callback" ||
		request.Form.Get("code_verifier") == "" {
		http.Error(response, "token denied", http.StatusBadRequest)
		return
	}
	code := request.Form.Get("code")
	harness.mu.Lock()
	authorization, ok := harness.authorizations[code]
	delete(harness.authorizations, code)
	harness.mu.Unlock()
	if !ok {
		http.Error(response, "token denied", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	rawIDToken, err := signManagedBrowserIDToken(harness.privateKey, map[string]any{
		"iss":       harness.app.cfg.OIDCIssuer,
		"sub":       managedTestSubject,
		"aud":       harness.app.cfg.OIDCClientID,
		"exp":       now.Add(5 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"auth_time": now.Unix(),
		"nonce":     authorization.nonce,
		"amr":       []string{"user", "mfa"},
	})
	if err != nil {
		http.Error(response, "token unavailable", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(map[string]any{
		"access_token": "managed-browser-access",
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     rawIDToken,
	})
}

func (harness *managedBrowserHarness) operation(response http.ResponseWriter, request *http.Request) {
	session, ok := harness.app.readSession(request)
	if !ok {
		http.Redirect(response, request, "/", http.StatusFound)
		return
	}
	response.Header().Set("Cache-Control", "no-store, no-transform")
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(response, `<!doctype html><html lang="en"><head><title>Operation registered</title></head><body><main><h1>Operation registered</h1><p>Pharos will show value-free progress.</p><form method="post" action="/logout"><input type="hidden" name="csrf_token" value="`)
	_, _ = io.WriteString(response, harness.app.csrfToken(session))
	_, _ = io.WriteString(response, `"><button type="submit">Sign out</button></form></main></body></html>`)
}

func (harness *managedBrowserHarness) evidence(response http.ResponseWriter) {
	executions, lastValueByteCount := harness.executor.evidence()
	audit, err := json.Marshal(harness.app.store.RecentAudit(128))
	if err != nil {
		http.Error(response, "evidence unavailable", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(map[string]any{
		"schema":                "janus.managed-browser-assurance.v1",
		"executions":            executions,
		"last_value_byte_count": lastValueByteCount,
		"authority_kind":        "test_fixture",
		"audit":                 json.RawMessage(audit),
	})
}

func signManagedBrowserIDToken(privateKey *rsa.PrivateKey, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func TestManagedBrowserAssuranceServer(t *testing.T) {
	if os.Getenv(managedBrowserAssuranceEnv) != "1" {
		t.Skip("managed browser assurance server is started only by Playwright")
	}
	listener, err := net.Listen("tcp", managedBrowserAssuranceAddr)
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + managedBrowserAssuranceAddr
	server := &http.Server{
		Handler:           newManagedBrowserHarness(t, baseURL),
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Println("managed_browser_assurance_server=ready")
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
}
