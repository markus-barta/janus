package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func testConfig() Config {
	return Config{
		Listen:       ":0",
		PublicURL:    "https://vault.barta.cm",
		ProductMode:  "self_hosted",
		DataDir:      tTempDir,
		RequireAuth:  true,
		OIDCIssuer:   "https://auth.inspr.at",
		OIDCClientID: "client",
		OIDCSecret:   "secret",
		CookieKey:    []byte("0123456789abcdef0123456789abcdef"),
		RolePolicy:   RolePolicy{BootstrapOwner: true},
		ScopePolicy:  ScopePolicy{AllowedScopes: map[string]bool{"csb1": true}, Strict: true},
	}
}

var tTempDir = ""

func newTestApp(t *testing.T) *App {
	t.Helper()
	tTempDir = t.TempDir()
	store, err := NewStore(tTempDir, "")
	if err != nil {
		t.Fatal(err)
	}
	permitStore, err := NewPermitStore(tTempDir)
	if err != nil {
		t.Fatal(err)
	}
	return &App{
		cfg:       testConfig(),
		store:     store,
		broker:    NewBroker(store),
		permits:   permitStore,
		templates: mustTemplates(),
	}
}

func assertActionReceiptProof(t *testing.T, receipt ActionReceipt, action, requestID string) {
	t.Helper()
	if receipt.Action != action || receipt.RequestID != requestID {
		t.Fatalf("unexpected receipt identity: %#v", receipt)
	}
	if receipt.Schema != actionReceiptSchema || receipt.Algorithm != actionReceiptAlgorithm {
		t.Fatalf("receipt should carry schema and algorithm: %#v", receipt)
	}
	if !receipt.TamperEvident || receipt.Coverage == "" || receipt.Verification == "" {
		t.Fatalf("receipt should describe its proof: %#v", receipt)
	}
	if len(receipt.ReceiptHash) != 64 || !isLowerHex(receipt.ReceiptHash) {
		t.Fatalf("receipt hash should be lowercase sha256 hex: %#v", receipt)
	}
	if receipt.ReceiptID != "ar_"+receipt.ReceiptHash[:16] {
		t.Fatalf("receipt id should derive from hash: %#v", receipt)
	}
	if !receipt.RoleChecked || !receipt.CSRFChecked || !receipt.ReadinessChecked || !receipt.AuditRecorded {
		t.Fatalf("receipt should record security checks: %#v", receipt)
	}
	if receipt.SecretValueReturned || receipt.RequestBodyReturned || receipt.ValueReturned {
		t.Fatalf("receipt should stay value-free: %#v", receipt)
	}
}

func isLowerHex(value string) bool {
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func assertWitnessFreshnessHeaders(t *testing.T, out *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	capturedAt := out.Header().Get("X-Janus-Witness-Captured-At")
	freshUntil := out.Header().Get("X-Janus-Witness-Fresh-Until")
	if capturedAt == "" || freshUntil == "" {
		t.Fatalf("witness freshness headers should be present: captured_at=%q fresh_until=%q", capturedAt, freshUntil)
	}
	if got := out.Header().Get("X-Janus-Witness-Freshness-Seconds"); got != "300" {
		t.Fatalf("witness freshness header should be 300 seconds, got %q", got)
	}
	capturedTime, err := time.Parse(time.RFC3339, capturedAt)
	if err != nil {
		t.Fatalf("captured_at should be RFC3339, got %q: %v", capturedAt, err)
	}
	freshTime, err := time.Parse(time.RFC3339, freshUntil)
	if err != nil {
		t.Fatalf("fresh_until should be RFC3339, got %q: %v", freshUntil, err)
	}
	if !freshTime.Equal(capturedTime.Add(5 * time.Minute)) {
		t.Fatalf("fresh_until should be 5 minutes after captured_at: captured=%s fresh=%s", capturedAt, freshUntil)
	}
	return capturedAt, freshUntil
}

func testWitnessVerificationRequest(t *testing.T, app *App, session Session, requestID string, capturedAt time.Time) WitnessReceiptVerificationRequest {
	t.Helper()
	roleEvidence := SessionRoleEvidenceFor(session, app.cfg.RequireAuth, app.cfg.OIDCConfigured(), true)
	witness := app.authenticatedBrowserWitness(session, roleEvidence, true)
	capture := AuthenticatedBrowserCaptureFor()
	receipt := AuthenticatedBrowserCaptureReceiptFor(witness, capture, requestID, capturedAt)
	return WitnessReceiptVerificationRequest{ProofLine: receipt.Input, ProofHash: receipt.Hash}
}

func cookieByName(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("expected cookie %s in %#v", name, cookies)
	return nil
}

func mergeCookieJar(existing []*http.Cookie, updates []*http.Cookie) []*http.Cookie {
	jar := make(map[string]*http.Cookie, len(existing)+len(updates))
	for _, cookie := range existing {
		jar[cookie.Name] = cookie
	}
	for _, cookie := range updates {
		if cookie.MaxAge < 0 {
			delete(jar, cookie.Name)
			continue
		}
		jar[cookie.Name] = cookie
	}
	names := make([]string, 0, len(jar))
	for name := range jar {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]*http.Cookie, 0, len(names))
	for _, name := range names {
		out = append(out, jar[name])
	}
	return out
}

func testOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:    "client",
		RedirectURL: "https://vault.barta.cm/oidc/callback",
		Scopes:      []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://auth.example.test/oauth/v2/authorize",
			TokenURL: "https://auth.example.test/oauth/v2/token",
		},
	}
}

func TestDescriptorsNeverExposeValues(t *testing.T) {
	tTempDir = t.TempDir()
	store, err := NewStore(tTempDir, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(store.Descriptors())
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, forbidden := range []string{"\"value\"", "\"secret_value\"", "\"plaintext\"", "\"source\"", "secrets/"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("descriptor response exposed forbidden field %s in %s", forbidden, body)
		}
	}
}

func TestLoadsExternalAgenixCatalog(t *testing.T) {
	dataDir := t.TempDir()
	catalogPath := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(catalogPath, []byte(`[{
		"id":"csb1-real-env",
		"display_name":"Real env metadata",
		"provider":"agenix",
		"classification":"high",
		"owner":"platform",
		"source":"secrets/csb1-real-env.age",
		"consumer_count":2
	}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dataDir, catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	descriptors := store.Descriptors()
	if len(descriptors) != 1 {
		t.Fatalf("expected one descriptor, got %d", len(descriptors))
	}
	if descriptors[0].ID != "csb1-real-env" || descriptors[0].RevealAllowed {
		t.Fatalf("unexpected descriptor: %#v", descriptors[0])
	}
	if descriptors[0].Scope != "csb1" || descriptors[0].EgressMode != "none" || descriptors[0].Lifecycle != LifecycleActive {
		t.Fatalf("expected normalized safe metadata: %#v", descriptors[0])
	}
}

func TestBundledAgenixCatalogHasNoGovernanceGates(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("catalog", "agenix-catalog.json"))
	if os.IsNotExist(err) {
		t.Skip("agenix-catalog.json is nixcfg deploy data, not bundled in the standalone app repo")
	}
	if err != nil {
		t.Fatal(err)
	}
	var descriptors []SecretDescriptor
	if err := json.Unmarshal(raw, &descriptors); err != nil {
		t.Fatal(err)
	}
	if len(descriptors) == 0 {
		t.Fatal("expected bundled catalog descriptors")
	}
	if gates := ValidateCatalog(descriptors); len(gates) != 0 {
		t.Fatalf("bundled catalog should have no governance gates: %#v", gates)
	}
	for _, desc := range descriptors {
		if desc.RevealAllowed {
			t.Fatalf("bundled catalog must remain no-reveal: %#v", desc)
		}
	}
}

func TestAuditHashChainAndRecentAudit(t *testing.T) {
	store, err := NewStore(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	store.AppendAudit(AuditEntry{Action: "one", Outcome: "allowed", Method: http.MethodGet, Path: "/"})
	store.AppendAudit(AuditEntry{Action: "two", Outcome: "denied", Method: http.MethodPost, Path: "/api"})

	posture := store.AuditPosture()
	if posture.Entries != 2 || posture.ChainedEntries != 2 || !posture.ChainVerified || posture.LastHash == "" {
		t.Fatalf("unexpected audit posture: %#v", posture)
	}
	if posture.WarningCount != 1 || auditSeverityCount(posture, "info") != 1 || auditSeverityCount(posture, "warning") != 1 {
		t.Fatalf("unexpected audit severity posture: %#v", posture)
	}
	recent := store.RecentAudit(1)
	if len(recent) != 1 || recent[0].Action != "two" || recent[0].Severity != "warning" || recent[0].PrevHash == "" || recent[0].EventHash == "" {
		t.Fatalf("unexpected recent audit: %#v", recent)
	}
}

func TestAuditExplicitCriticalSeverity(t *testing.T) {
	store, err := NewStore(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	store.AppendAudit(AuditEntry{Action: "audit.chain", Outcome: "failed", Severity: "critical", Method: http.MethodGet, Path: "/readyz"})
	posture := store.AuditPosture()
	if posture.CriticalCount != 1 || auditSeverityCount(posture, "critical") != 1 || !posture.ChainVerified {
		t.Fatalf("unexpected critical audit posture: %#v", posture)
	}
	recent := store.RecentAudit(1)
	if len(recent) != 1 || recent[0].Severity != "critical" {
		t.Fatalf("expected critical audit event: %#v", recent)
	}
}

func TestAuditPostureAcceptsPreSeverityHashChain(t *testing.T) {
	store, err := NewStore(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	legacy := AuditEntry{
		Time:    time.Now().UTC(),
		Action:  "legacy.event",
		Outcome: "allowed",
		Method:  http.MethodGet,
		Path:    "/",
	}
	legacy.EventHash = hashAuditEntry(legacy)
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.auditFile, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	posture := store.AuditPosture()
	if !posture.ChainVerified || posture.UnknownSeverityCount != 1 || auditSeverityCount(posture, "unknown") != 1 {
		t.Fatalf("pre-severity audit row should remain verified and counted unknown: %#v", posture)
	}
}

func TestAuditTrailWitnessScrubsRawPathAndReason(t *testing.T) {
	entry := AuditEntry{
		Time:      time.Now().UTC(),
		Action:    "permit.run.ui",
		Outcome:   "not_executed",
		Severity:  "notice",
		RequestID: "req-safe_123",
		Method:    http.MethodPost,
		Path:      "/ui/permits/p_secret/run/backend_path=/tmp/source_path=/src",
		SecretRef: "zitadel-janus-oidc",
		Reason:    "no execution connector configured in V1.1 request_body=secret env=TOKEN connector_output=secret",
	}
	entry.EventHash = hashAuditEntry(entry)

	trail := AuditTrailFor([]AuditEntry{entry}, AuditPosture{Entries: 1, ChainedEntries: 1, ChainVerified: true, SinkWritable: true, LastHash: entry.EventHash}, true)
	if trail.ValueReturned || trail.VisibleCount != 1 || trail.ChainState != "verified" || trail.LastHashShort == "" {
		t.Fatalf("unexpected audit trail witness: %#v", trail)
	}
	row := trail.Rows[0]
	for _, want := range []string{"POST browser action", "no_connector", "zitadel-janus-oidc", "req-safe_123"} {
		if !strings.Contains(row.Channel+" "+row.ReasonClass+" "+row.Scope+" "+row.RequestID, want) {
			t.Fatalf("audit trail row should include safe witness %q: %#v", want, row)
		}
	}
	joined := row.Channel + " " + row.ReasonClass + " " + row.ChainLink
	for _, forbidden := range []string{"/ui/permits", "request_body=secret", "env=TOKEN", "connector_output=secret", "backend_path=/tmp", "source_path=/src"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("audit trail row leaked raw field %q: %#v", forbidden, row)
		}
	}
}

func TestRecentAuditAPIUsesSanitizedWitnessRows(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.store.AppendAudit(AuditEntry{
		Action:    "warden.resolve.ui",
		Outcome:   "allowed",
		Method:    http.MethodPost,
		Path:      "/ui/warden/resolve/backend_path=/tmp/source_path=/src",
		SecretRef: "zitadel-janus-oidc",
		Reason:    "operator reason request_body=raw-secret env=SECRET connector_output=secret",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/audit/recent", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{`"audit_trail"`, `"audit"`, `"channel":"POST browser action"`, `"reason_class":"allowed_recorded"`, `"raw_path_returned":false`, `"raw_reason_returned":false`, `"request_body_returned":false`, `"env_returned":false`, `"backend_path_returned":false`, `"source_path_returned":false`, `"connector_output_returned":false`, `"secret_value_returned":false`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("recent audit API should include safe witness %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"/ui/warden", "operator reason", "request_body=raw-secret", "env=SECRET", "connector_output=secret", "backend_path=/tmp", "source_path=/src"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("recent audit API leaked raw marker %q: %s", forbidden, body)
		}
	}
}

func auditSeverityCount(posture AuditPosture, severity string) int {
	for _, count := range posture.SeverityCounts {
		if count.Severity == severity {
			return count.Count
		}
	}
	return 0
}

func TestSessionRejectsTamper(t *testing.T) {
	app := newTestApp(t)

	rr := httptest.NewRecorder()
	app.writeSession(rr, Session{Subject: "user-1", Expiry: time.Now().UTC().Add(time.Hour)})
	cookie := rr.Result().Cookies()[0]
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if _, ok := app.readSession(req); !ok {
		t.Fatal("expected valid session")
	}

	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		t.Fatalf("unexpected cookie format: %s", cookie.Value)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, 'x')
	cookie.Value = base64.RawURLEncoding.EncodeToString(raw) + "." + parts[1]

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if _, ok := app.readSession(req); ok {
		t.Fatal("tampered session was accepted")
	}
}

func TestSessionCookieIsStrictAndHostPrefixed(t *testing.T) {
	app := newTestApp(t)

	rr := httptest.NewRecorder()
	app.writeSession(rr, Session{Subject: "user-1", Expiry: time.Now().UTC().Add(time.Hour)})
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one session cookie, got %d", len(cookies))
	}
	if cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie must be Strict; OIDC redirect cookies carry Lax separately, got %v", cookies[0].SameSite)
	}
	if cookies[0].Name != hostSessionCookie {
		t.Fatalf("secure deployments should use host-prefixed session cookie, got %s", cookies[0].Name)
	}
	if !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("session cookie must be secure and httponly: %#v", cookies[0])
	}
}

func TestReadSessionAcceptsLegacyCookieDuringHostPrefixMigration(t *testing.T) {
	app := newTestApp(t)

	rr := httptest.NewRecorder()
	app.writeSession(rr, Session{Subject: "user-1", Expiry: time.Now().UTC().Add(time.Hour)})
	cookie := rr.Result().Cookies()[0]
	if cookie.Name != hostSessionCookie {
		t.Fatalf("expected host-prefixed cookie, got %s", cookie.Name)
	}
	cookie.Name = sessionCookie

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if _, ok := app.readSession(req); !ok {
		t.Fatal("legacy session cookie should be accepted during migration")
	}
}

func TestSessionPostureIsValueFree(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "user-1", Email: "user@example.test", Expiry: time.Now().UTC().Add(time.Hour)}

	posture := app.sessionPosture(session)
	if posture.AbsoluteTTLSeconds != int(defaultSessionTTL.Seconds()) || posture.TTLLabel != "12h" {
		t.Fatalf("unexpected session ttl posture: %#v", posture)
	}
	if posture.SecondsRemaining <= 0 || posture.ExpiresAt == "" || posture.ExpiresLabel == "" {
		t.Fatalf("session expiry should be visible without values: %#v", posture)
	}
	if !posture.CSRFBound || !posture.CookieSigned || !posture.CookieHostPrefixed || posture.ValueReturned {
		t.Fatalf("unexpected session controls: %#v", posture)
	}
	raw, err := json.Marshal(posture)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "user-1") || strings.Contains(string(raw), "user@example.test") {
		t.Fatalf("session posture should not include identity values: %s", raw)
	}
}

func TestSessionRoleEvidenceIsValueFreeAndRoleAware(t *testing.T) {
	session := Session{Subject: "subject-123", Email: "person@example.test", Name: "Person Name", Roles: []string{RoleViewer, RoleAuditor}, Expiry: time.Now().UTC().Add(time.Hour)}

	evidence := SessionRoleEvidenceFor(session, true, true, true)
	if evidence.State != "signed_in" || evidence.AuthMode != "zitadel_oidc" || evidence.ActiveRoleCount != 2 || evidence.ValueReturned {
		t.Fatalf("expected signed-in role evidence: %#v", evidence)
	}
	if evidence.IdentityValuesReturned || evidence.SubjectReturned || evidence.EmailReturned || evidence.NameReturned || evidence.ClaimValuesReturned || evidence.GroupValuesReturned || evidence.TokenReturned || evidence.CookieValueReturned || evidence.RequestBodyReturned || evidence.EnvValuesReturned || evidence.BackendPathReturned {
		t.Fatalf("role evidence should not return identity or backend values: %#v", evidence)
	}
	if !sessionRoleEvidenceHasRole(evidence.Roles, RoleAuditor, "active") || !sessionRoleEvidenceHasRole(evidence.Roles, RoleOperator, "inactive") {
		t.Fatalf("role evidence should distinguish active and inactive roles: %#v", evidence.Roles)
	}
	if !sessionRoleEvidenceHasGate(evidence.Gates, "evidence_export", "available") || !sessionRoleEvidenceHasGate(evidence.Gates, "use_actions", "role_required") || !sessionRoleEvidenceHasGate(evidence.Gates, "identity_boundary", "withheld") {
		t.Fatalf("role evidence should show value-free gates: %#v", evidence.Gates)
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"subject-123", "person@example.test", "Person Name"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("role evidence leaked identity value %q: %s", forbidden, raw)
		}
	}

	local := SessionRoleEvidenceFor(session, false, false, true)
	if local.State != "local_auth_disabled" || local.AuthMode != "local_dev" || local.IdentityProvider != "local_dev" || local.ValueReturned {
		t.Fatalf("local role evidence should stay explicit and value-free: %#v", local)
	}
}

func TestAuthenticatedBrowserWitnessIsValueFreeAndRoleAware(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "subject-123", Email: "person@example.test", Name: "Person Name", Roles: []string{RoleViewer, RoleAuditor}, Expiry: time.Now().UTC().Add(time.Hour)}
	roleEvidence := SessionRoleEvidenceFor(session, true, true, true)

	witness := app.authenticatedBrowserWitness(session, roleEvidence, true)
	if witness.State != "authenticated" || !witness.Authenticated || witness.Flow != "zitadel_oidc_pkce_to_signed_session" || witness.EvidenceSignal != "signed_session_browser_proof_no_identity_values" || witness.ValueReturned {
		t.Fatalf("expected authenticated browser witness: %#v", witness)
	}
	if witness.IdentityValuesReturned || witness.SubjectReturned || witness.EmailReturned || witness.NameReturned || witness.ClaimValuesReturned || witness.GroupValuesReturned || witness.TokenReturned || witness.CookieValueReturned || witness.RequestBodyReturned || witness.EnvValuesReturned || witness.BackendPathReturned || witness.ConnectorOutputReturned || witness.PermitPayloadReturned || witness.SecretValueReturned {
		t.Fatalf("browser witness should not return identity or backend values: %#v", witness)
	}
	if witness.SessionCookiePolicy != "host_prefixed_strict_signed" || witness.CSRFBoundary != "bound_to_signed_session" || witness.CSPBoundary != "script_src_none" {
		t.Fatalf("browser witness should expose browser security posture: %#v", witness)
	}
	if !authenticatedBrowserGateHasState(witness.Gates, "login_completed", "authenticated") || !authenticatedBrowserGateHasState(witness.Gates, "cookie_boundary", "host_prefixed_strict_signed") || !authenticatedBrowserGateHasState(witness.Gates, "value_boundary", "values_withheld") {
		t.Fatalf("browser witness should expose copy-safe gates: %#v", witness.Gates)
	}
	raw, err := json.Marshal(witness)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"subject-123", "person@example.test", "Person Name", "secret-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("browser witness leaked value %q: %s", forbidden, raw)
		}
	}
}

func TestConfigUsesHostPrefixedStateCookieForHTTPS(t *testing.T) {
	app := newTestApp(t)

	if app.cfg.StateCookieName() != hostStateCookie {
		t.Fatalf("secure deployments should use host-prefixed state cookie, got %s", app.cfg.StateCookieName())
	}
}

func TestAuthenticatedBrowserWitnessAPIIsAuthenticatedAndValueFree(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "subject-123", Email: "person@example.test", Name: "Person Name", Roles: []string{RoleViewer, RoleAuditor}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/session-witness", nil)
	req.Header.Set("X-Request-Id", "browser-witness-123")
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	for header, want := range map[string]string{
		"X-Janus-Witness-Schema":            "janus-auth-session-witness-v1",
		"X-Janus-Witness-State":             "authenticated",
		"X-Janus-Witness-Flow":              "zitadel_oidc_pkce_to_signed_session",
		"X-Janus-Witness-Signal":            "signed_session_browser_proof_no_identity_values",
		"X-Janus-Witness-Body-Field":        "witness",
		"X-Janus-Witness-Algorithm":         "sha256-witness-v1",
		"X-Janus-Witness-Hash-Body-Field":   "receipt.hash",
		"X-Janus-Witness-Freshness-Seconds": "300",
		"X-Janus-Value-Returned":            "false",
	} {
		if got := out.Header().Get(header); got != want {
			t.Fatalf("browser witness API should set %s=%q, got %q", header, want, got)
		}
	}
	receiptHash := out.Header().Get("X-Janus-Witness-Hash")
	if len(receiptHash) != 64 {
		t.Fatalf("browser witness API should set 64-char proof hash, got %q", receiptHash)
	}
	capturedAt, freshUntil := assertWitnessFreshnessHeaders(t, out)
	body := out.Body.String()
	for _, want := range []string{`"witness"`, `"capture"`, `"receipt"`, `"schema":"janus-auth-session-witness-v1"`, `"body_field":"witness"`, `"body_field":"receipt.hash"`, `"algorithm":"sha256-witness-v1"`, `"hash_header":"X-Janus-Witness-Hash"`, `"hash":"` + receiptHash + `"`, `"captured_at":"` + capturedAt + `"`, `"fresh_until":"` + freshUntil + `"`, `"freshness_seconds":300`, `"X-Janus-Witness-Captured-At"`, `"X-Janus-Witness-Fresh-Until"`, `"X-Janus-Witness-Freshness-Seconds"`, `"proof":"signed_session_browser_proof_no_identity_values"`, `"replay_safe":true`, `"copy_safe":true`, `"label":"Authenticated browser witness"`, `"state":"authenticated"`, `"flow":"zitadel_oidc_pkce_to_signed_session"`, `"session_cookie_policy":"host_prefixed_strict_signed"`, `"csrf_boundary":"bound_to_signed_session"`, `"csp_boundary":"script_src_none"`, `"evidence_signal":"signed_session_browser_proof_no_identity_values"`, `"key":"login_completed"`, `"key":"value_boundary"`, `"request_id":"browser-witness-123"`, `"identity_values_returned":false`, `"subject_returned":false`, `"email_returned":false`, `"name_returned":false`, `"claim_values_returned":false`, `"group_values_returned":false`, `"token_returned":false`, `"cookie_value_returned":false`, `"request_body_returned":false`, `"env_values_returned":false`, `"backend_path_returned":false`, `"connector_output_returned":false`, `"permit_payload_returned":false`, `"secret_value_returned":false`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("browser witness API should include %s: %s", want, body)
		}
	}
	for _, forbidden := range []string{"subject-123", "person@example.test", "Person Name", "secret-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("browser witness API leaked value %q: %s", forbidden, body)
		}
	}
	assertRouteResponseValueFree(t, "browser witness API", out)
}

func TestSessionWitnessPageRendersCopySafeCapture(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "subject-123", Email: "person@example.test", Name: "Person Name", Roles: []string{RoleViewer, RoleAuditor}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodGet, "/session-witness", nil)
	req.Header.Set("X-Request-Id", "session-witness-page-123")
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	for header, want := range map[string]string{
		"Content-Type":                      "text/html; charset=utf-8",
		"X-Janus-Witness-Schema":            "janus-auth-session-witness-v1",
		"X-Janus-Witness-State":             "authenticated",
		"X-Janus-Witness-Flow":              "zitadel_oidc_pkce_to_signed_session",
		"X-Janus-Witness-Signal":            "signed_session_browser_proof_no_identity_values",
		"X-Janus-Witness-Body-Field":        "witness",
		"X-Janus-Witness-Algorithm":         "sha256-witness-v1",
		"X-Janus-Witness-Hash-Body-Field":   "receipt.hash",
		"X-Janus-Witness-Freshness-Seconds": "300",
		"X-Janus-Value-Returned":            "false",
		"X-Content-Type-Options":            "nosniff",
		"Cross-Origin-Resource-Policy":      "same-origin",
	} {
		if got := out.Header().Get(header); got != want {
			t.Fatalf("session witness page should set %s=%q, got %q", header, want, got)
		}
	}
	if got := out.Header().Get("Content-Security-Policy"); !strings.Contains(got, "script-src 'none'") {
		t.Fatalf("session witness page should keep script disabled: %s", got)
	}
	pageReceiptHash := out.Header().Get("X-Janus-Witness-Hash")
	if len(pageReceiptHash) != 64 {
		t.Fatalf("session witness page should set 64-char proof hash, got %q", pageReceiptHash)
	}
	capturedAt, freshUntil := assertWitnessFreshnessHeaders(t, out)
	body := out.Body.String()
	for _, want := range []string{"Session witness capture", "Evidence handoff", "Capture, verify, retain", "Capture the witness", "Verify the session", "Keep the receipt", "Open proof text", "Open verifier", "Reviewer launch checklist", "Browser session", "Current proof pack", "Evidence receipt", "Human capture", "JANUS-195 real browser proof remains.", "current_session_verifier=true", "Capture proof", "Proof hash", pageReceiptHash, "Captured", "Fresh until", capturedAt, freshUntil, "sha256-witness-v1", "freshness_seconds=300", "captured_at=" + capturedAt, "fresh_until=" + freshUntil, "hash_header=X-Janus-Witness-Hash", "hash_body_field=receipt.hash", "Witness headers", "Session witness value boundary", "janus-auth-session-witness-v1", "state=authenticated", "flow=zitadel_oidc_pkce_to_signed_session", "signed_session_browser_proof_no_identity_values", "X-Janus-Witness-State", "X-Janus-Witness-Flow", "X-Janus-Witness-Signal", "X-Janus-Witness-Hash", "X-Janus-Witness-Captured-At", "X-Janus-Witness-Fresh-Until", "X-Janus-Witness-Freshness-Seconds", "request_id=session-witness-page-123", "copy_safe=true", "replay_safe=true", "identity_values_returned=false", "subject_returned=false", "email_returned=false", "name_returned=false", "claim_values_returned=false", "group_values_returned=false", "token_returned=false", "cookie_value_returned=false", "secret_value_returned=false", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("session witness page should include %s: %s", want, body)
		}
	}
	if !strings.Contains(body, `<a class="button primary" href="/session-witness/verify">Open verifier</a>`) {
		t.Fatalf("session witness page should make the verifier the primary handoff: %s", body)
	}
	for _, forbidden := range []string{"subject-123", "person@example.test", "Person Name", "secret-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("session witness page leaked value %q: %s", forbidden, body)
		}
	}
	assertRouteResponseValueFree(t, "session witness page", out)
}

func TestAuthSmokePageRendersValueFreeLaunchpad(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "subject-123", Email: "person@example.test", Name: "Person Name", Roles: []string{RoleViewer, RoleAuditor}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodGet, "/auth/smoke", nil)
	req.Header.Set("X-Request-Id", "auth-smoke-page-123")
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	for header, want := range map[string]string{
		"Content-Type":                      "text/html; charset=utf-8",
		"X-Janus-Witness-Schema":            "janus-auth-session-witness-v1",
		"X-Janus-Witness-State":             "authenticated",
		"X-Janus-Witness-Flow":              "zitadel_oidc_pkce_to_signed_session",
		"X-Janus-Witness-Signal":            "signed_session_browser_proof_no_identity_values",
		"X-Janus-Witness-Body-Field":        "witness",
		"X-Janus-Witness-Algorithm":         "sha256-witness-v1",
		"X-Janus-Witness-Hash-Body-Field":   "receipt.hash",
		"X-Janus-Witness-Freshness-Seconds": "300",
		"X-Janus-Value-Returned":            "false",
		"X-Content-Type-Options":            "nosniff",
		"Cross-Origin-Resource-Policy":      "same-origin",
	} {
		if got := out.Header().Get(header); got != want {
			t.Fatalf("auth smoke page should set %s=%q, got %q", header, want, got)
		}
	}
	if got := out.Header().Get("Content-Security-Policy"); !strings.Contains(got, "script-src 'none'") {
		t.Fatalf("auth smoke page should keep script disabled: %s", got)
	}
	assertStyleNonceMatchesCSP(t, out)
	receiptHash := out.Header().Get("X-Janus-Witness-Hash")
	if len(receiptHash) != 64 {
		t.Fatalf("auth smoke page should set 64-char witness hash, got %q", receiptHash)
	}
	_, freshUntil := assertWitnessFreshnessHeaders(t, out)
	body := out.Body.String()
	for _, want := range []string{"Authenticated smoke", "Clean sign-in reset", "Three checks, one receipt", "Clean start", "Prove session", "Keep receipt", "Session witness", "Full witness", "Verifier", `href="/auth/reset"`, `href="/session-witness/verify"`, `href="/session-witness"`, `name="csrf_token"`, `id="command-center"`, "auth_smoke_launchpad=true", "authenticated_smoke_launchpad=true", "csrf_bound=true", "janus-auth-session-witness-v1", "state=authenticated", "flow=zitadel_oidc_pkce_to_signed_session", "signed_session_browser_proof_no_identity_values", "host_prefixed_strict_signed", "bound_to_signed_session", "script_src_none", "request_id=auth-smoke-page-123", "proof_hash_header=X-Janus-Witness-Hash", "hash_body_field=receipt.hash", "freshness_seconds=300", freshUntil, receiptHash, "identity_values_returned=false", "subject_returned=false", "email_returned=false", "name_returned=false", "claim_values_returned=false", "group_values_returned=false", "token_returned=false", "cookie_value_returned=false", "request_body_returned=false", "proof_body_returned=false", "env_returned=false", "backend_path_returned=false", "secret_value_returned=false", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("auth smoke page should include %s: %s", want, body)
		}
	}
	for _, forbidden := range []string{"subject-123", "person@example.test", "Person Name", "secret-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret", "proof_line=", "witness_proof_line=", "proof_pack_input=", "janus_current_session_witness_proof", "janus_current_session_evidence_record"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("auth smoke page leaked value %q: %s", forbidden, body)
		}
	}
	assertRouteResponseValueFree(t, "auth smoke page", out)
}

func TestSessionWitnessTextRendersCopySafeCapture(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "subject-123", Email: "person@example.test", Name: "Person Name", Roles: []string{RoleViewer, RoleAuditor}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodGet, "/session-witness.txt", nil)
	req.Header.Set("X-Request-Id", "session-witness-text-123")
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	for header, want := range map[string]string{
		"Content-Type":                      "text/plain; charset=utf-8",
		"Content-Disposition":               `inline; filename="janus-session-witness.txt"`,
		"X-Janus-Witness-Schema":            "janus-auth-session-witness-v1",
		"X-Janus-Witness-State":             "authenticated",
		"X-Janus-Witness-Flow":              "zitadel_oidc_pkce_to_signed_session",
		"X-Janus-Witness-Signal":            "signed_session_browser_proof_no_identity_values",
		"X-Janus-Witness-Body-Field":        "witness",
		"X-Janus-Witness-Algorithm":         "sha256-witness-v1",
		"X-Janus-Witness-Hash-Body-Field":   "receipt.hash",
		"X-Janus-Witness-Freshness-Seconds": "300",
		"X-Janus-Value-Returned":            "false",
		"X-Content-Type-Options":            "nosniff",
		"Cross-Origin-Resource-Policy":      "same-origin",
	} {
		if got := out.Header().Get(header); got != want {
			t.Fatalf("session witness text should set %s=%q, got %q", header, want, got)
		}
	}
	textReceiptHash := out.Header().Get("X-Janus-Witness-Hash")
	if len(textReceiptHash) != 64 {
		t.Fatalf("session witness text should set 64-char proof hash, got %q", textReceiptHash)
	}
	capturedAt, freshUntil := assertWitnessFreshnessHeaders(t, out)
	body := out.Body.String()
	for _, want := range []string{"janus_session_witness", "schema=janus-auth-session-witness-v1", "state=authenticated", "flow=zitadel_oidc_pkce_to_signed_session", "signal=signed_session_browser_proof_no_identity_values", "body_field=witness", "request_id=session-witness-text-123", "captured_at=" + capturedAt, "fresh_until=" + freshUntil, "freshness_seconds=300", "proof_line=schema=janus-auth-session-witness-v1 state=authenticated", "fresh_until=" + freshUntil, "proof_algorithm=sha256-witness-v1", "proof_hash=" + textReceiptHash, "proof_hash_header=X-Janus-Witness-Hash", "proof_hash_body_field=receipt.hash", "copy_safe=true", "replay_safe=true", "identity_values_returned=false", "subject_returned=false", "email_returned=false", "name_returned=false", "claim_values_returned=false", "group_values_returned=false", "token_returned=false", "cookie_value_returned=false", "request_body_returned=false", "env_values_returned=false", "backend_path_returned=false", "connector_output_returned=false", "permit_payload_returned=false", "secret_value_returned=false", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("session witness text should include %s: %s", want, body)
		}
	}
	for _, forbidden := range []string{"subject-123", "person@example.test", "Person Name", "secret-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("session witness text leaked value %q: %s", forbidden, body)
		}
	}
	assertRouteResponseValueFree(t, "session witness text", out)
}

func TestSessionWitnessPageRequiresAuthentication(t *testing.T) {
	app := newTestApp(t)
	for _, path := range []string{"/auth/smoke", "/session-witness", "/session-witness.txt", "/session-witness/verify"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Request-Id", "session-witness-auth-required")
		out := httptest.NewRecorder()
		app.routes().ServeHTTP(out, req)
		wantHref := ""
		switch path {
		case "/auth/smoke":
			wantHref = "/login?next=%2Fauth%2Fsmoke"
		case "/session-witness":
			wantHref = "/login?next=%2Fsession-witness"
		case "/session-witness/verify":
			wantHref = "/login?next=%2Fsession-witness%2Fverify"
		}
		if wantHref == "" {
			if out.Code != http.StatusFound || out.Header().Get("Location") != "/login" {
				t.Fatalf("%s expected direct login redirect, got %d location=%q body=%s", path, out.Code, out.Header().Get("Location"), out.Body.String())
			}
		} else if out.Code != http.StatusOK || out.Header().Get("Location") != "" || !strings.Contains(out.Body.String(), `href="`+wantHref+`"`) || !strings.Contains(out.Body.String(), "janus-login-hero.png") {
			t.Fatalf("%s expected branded login landing with return path %q, got %d location=%q body=%s", path, wantHref, out.Code, out.Header().Get("Location"), out.Body.String())
		}
		assertRouteResponseValueFree(t, "session witness auth boundary", out)
	}
}

func TestSessionWitnessVerifyCurrentUsesCurrentBrowserSession(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "subject-123", Email: "person@example.test", Name: "Person Name", Roles: []string{RoleViewer, RoleAuditor}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	form := url.Values{}
	form.Set("csrf_token", app.csrfToken(session))
	req := httptest.NewRequest(http.MethodPost, "/session-witness/verify-current", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://vault.barta.cm")
	req.Header.Set("X-Request-Id", "verify-current-123")
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected current-session verifier 200, got %d body=%s", out.Code, out.Body.String())
	}
	verificationHash := out.Header().Get("X-Janus-Witness-Verification-Hash")
	if len(verificationHash) != 64 || !isLowerHex(verificationHash) {
		t.Fatalf("current-session verifier should set verification hash header, got %q", verificationHash)
	}
	for header, want := range map[string]string{
		"X-Janus-Witness-Verification-Schema":          "janus-witness-verification-v1",
		"X-Janus-Witness-Verification-Algorithm":       "sha256-witness-verification-v1",
		"X-Janus-Witness-Verification-Hash-Body-Field": "verification.receipt.hash",
		"X-Janus-Value-Returned":                       "false",
	} {
		if got := out.Header().Get(header); got != want {
			t.Fatalf("current-session verifier should set %s=%q, got %q", header, want, got)
		}
	}
	body := out.Body.String()
	for _, want := range []string{"Verification result", "verified", "Verification hash", verificationHash, "schema=janus-witness-verification-v1", "source_request_id=verify-current-123", "hash_match=true", "fresh=true", "verified=true", "input_returned=false", "request_body_returned=false", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("current-session verifier should include %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"proof_line=", "subject-123", "person@example.test", "Person Name", "secret-cookie-secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("current-session verifier leaked forbidden value %q: %s", forbidden, body)
		}
	}
	assertRouteResponseValueFree(t, "current-session verifier", out)
}

func TestWitnessReceiptVerifierVerifiesCopySafeProof(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "subject-123", Email: "person@example.test", Name: "Person Name", Roles: []string{RoleViewer, RoleAuditor}, Expiry: time.Now().UTC().Add(time.Hour)}
	capturedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	req := testWitnessVerificationRequest(t, app, session, "verify-proof-123", capturedAt)

	verification := VerifyAuthenticatedBrowserCaptureReceipt(req, capturedAt.Add(2*time.Minute))
	if !verification.Verified || verification.Status != "verified" || !verification.HashMatch || !verification.Fresh {
		t.Fatalf("expected verified fresh witness receipt: %#v", verification)
	}
	if verification.State != "authenticated" || verification.Flow != "zitadel_oidc_pkce_to_signed_session" || verification.RequestID != "verify-proof-123" || verification.FreshnessSeconds != 300 {
		t.Fatalf("verification should expose normalized safe proof fields: %#v", verification)
	}
	if verification.InputReturned || verification.RequestBodyReturned || verification.ValueReturned {
		t.Fatalf("verification must not return pasted input or values: %#v", verification)
	}
	receipt := WitnessReceiptVerificationReceiptFor(verification, "verify-receipt-123")
	if receipt.Schema != "janus-witness-verification-v1" || receipt.Algorithm != "sha256-witness-verification-v1" || receipt.HashHeader != "X-Janus-Witness-Verification-Hash" || receipt.BodyField != "verification.receipt.hash" {
		t.Fatalf("verification receipt should describe its proof: %#v", receipt)
	}
	if len(receipt.Hash) != 64 || !isLowerHex(receipt.Hash) || !strings.Contains(receipt.Input, "status=verified") || !strings.Contains(receipt.Input, "source_request_id=verify-proof-123") || !strings.Contains(receipt.Input, "hash_match=true") || !strings.Contains(receipt.Input, "fresh=true") || !strings.Contains(receipt.Input, "value_returned=false") {
		t.Fatalf("verification receipt should hash normalized safe fields: %#v", receipt)
	}
	verification.Receipt = &receipt
	raw, err := json.Marshal(verification)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"subject-123", "person@example.test", "Person Name", "secret-cookie-secret", req.ProofLine} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("verification leaked forbidden value %q: %s", forbidden, raw)
		}
	}
}

func TestWitnessReceiptVerifierRejectsBadInputWithoutEcho(t *testing.T) {
	bad := WitnessReceiptVerificationRequest{
		ProofLine: "token=secret-cookie-secret subject=person@example.test value_returned=true",
		ProofHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	verification := VerifyAuthenticatedBrowserCaptureReceipt(bad, time.Now().UTC())
	if verification.Verified || verification.HashMatch || verification.ExpectedHash != "" || verification.Status == "verified" {
		t.Fatalf("bad witness receipt should not verify or expose expected hash: %#v", verification)
	}
	raw, err := json.Marshal(verification)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-cookie-secret", "person@example.test", bad.ProofLine, "token=", "subject="} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("bad verification leaked forbidden input %q: %s", forbidden, raw)
		}
	}
}

func TestSessionWitnessVerifierUIAndAPIAreValueFree(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "subject-123", Email: "person@example.test", Name: "Person Name", Roles: []string{RoleViewer, RoleAuditor}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)
	cookie := rr.Result().Cookies()[0]
	capturedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	verifyReq := testWitnessVerificationRequest(t, app, session, "verify-ui-api-123", capturedAt)

	pageReq := httptest.NewRequest(http.MethodGet, "/session-witness/verify", nil)
	pageReq.AddCookie(cookie)
	pageOut := httptest.NewRecorder()
	app.routes().ServeHTTP(pageOut, pageReq)
	if pageOut.Code != http.StatusOK {
		t.Fatalf("expected verifier page 200, got %d body=%s", pageOut.Code, pageOut.Body.String())
	}
	pageBody := pageOut.Body.String()
	for _, want := range []string{"Witness receipt verifier", "Evidence workstation", "Verify without pasting values", "Verify this session", "Paste a proof line", "Keep the receipt", "Verify current session", "Verify proof line", "Verify witness receipt", `id="proof-line-form"`, `action="/session-witness/verify-current"`, "input_not_returned=true", "input_returned=false", "request_body_returned=false", "value_returned=false"} {
		if !strings.Contains(pageBody, want) {
			t.Fatalf("verifier page should include %q: %s", want, pageBody)
		}
	}
	assertRouteResponseValueFree(t, "session witness verifier page", pageOut)

	form := url.Values{}
	form.Set("csrf_token", app.csrfToken(session))
	form.Set("proof_line", verifyReq.ProofLine)
	form.Set("proof_hash", verifyReq.ProofHash)
	uiReq := httptest.NewRequest(http.MethodPost, "/session-witness/verify", strings.NewReader(form.Encode()))
	uiReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	uiReq.Header.Set("Origin", "https://vault.barta.cm")
	uiReq.AddCookie(cookie)
	uiOut := httptest.NewRecorder()
	app.routes().ServeHTTP(uiOut, uiReq)
	if uiOut.Code != http.StatusOK {
		t.Fatalf("expected verifier UI 200, got %d body=%s", uiOut.Code, uiOut.Body.String())
	}
	uiVerificationHash := uiOut.Header().Get("X-Janus-Witness-Verification-Hash")
	if len(uiVerificationHash) != 64 || !isLowerHex(uiVerificationHash) {
		t.Fatalf("verifier UI should set verification hash header, got %q", uiVerificationHash)
	}
	for header, want := range map[string]string{
		"X-Janus-Witness-Verification-Schema":          "janus-witness-verification-v1",
		"X-Janus-Witness-Verification-Algorithm":       "sha256-witness-verification-v1",
		"X-Janus-Witness-Verification-Hash-Body-Field": "verification.receipt.hash",
		"X-Janus-Value-Returned":                       "false",
	} {
		if got := uiOut.Header().Get(header); got != want {
			t.Fatalf("verifier UI should set %s=%q, got %q", header, want, got)
		}
	}
	uiBody := uiOut.Body.String()
	for _, want := range []string{"Verification result", "Verification hash", uiVerificationHash, "sha256-witness-verification-v1", "verification_hash_header=X-Janus-Witness-Verification-Hash", "verification_hash_body_field=verification.receipt.hash", "schema=janus-witness-verification-v1", "verifier_request_id=", "status=verified", "source_request_id=verify-ui-api-123", "hash_match=true", "fresh=true", "verified=true", "verified", "Hash match", "true", "verify-ui-api-123", verifyReq.ProofHash, "input_returned=false", "request_body_returned=false", "value_returned=false"} {
		if !strings.Contains(uiBody, want) {
			t.Fatalf("verifier UI should include %q: %s", want, uiBody)
		}
	}
	for _, forbidden := range []string{"proof_line=", verifyReq.ProofLine, "subject-123", "person@example.test", "Person Name", "secret-cookie-secret"} {
		if strings.Contains(uiBody, forbidden) {
			t.Fatalf("verifier UI leaked forbidden value %q: %s", forbidden, uiBody)
		}
	}
	assertRouteResponseValueFree(t, "session witness verifier UI", uiOut)

	rawReq, err := json.Marshal(verifyReq)
	if err != nil {
		t.Fatal(err)
	}
	apiReq := httptest.NewRequest(http.MethodPost, "/api/auth/session-witness/verify", strings.NewReader(string(rawReq)))
	apiReq.Header.Set("Content-Type", "application/json")
	apiReq.Header.Set("Origin", "https://vault.barta.cm")
	apiReq.Header.Set("X-CSRF-Token", app.csrfToken(session))
	apiReq.AddCookie(cookie)
	apiOut := httptest.NewRecorder()
	app.routes().ServeHTTP(apiOut, apiReq)
	if apiOut.Code != http.StatusOK {
		t.Fatalf("expected verifier API 200, got %d body=%s", apiOut.Code, apiOut.Body.String())
	}
	apiVerificationHash := apiOut.Header().Get("X-Janus-Witness-Verification-Hash")
	if len(apiVerificationHash) != 64 || !isLowerHex(apiVerificationHash) {
		t.Fatalf("verifier API should set verification hash header, got %q", apiVerificationHash)
	}
	for header, want := range map[string]string{
		"X-Janus-Witness-Verification-Schema":          "janus-witness-verification-v1",
		"X-Janus-Witness-Verification-Algorithm":       "sha256-witness-verification-v1",
		"X-Janus-Witness-Verification-Hash-Body-Field": "verification.receipt.hash",
		"X-Janus-Value-Returned":                       "false",
	} {
		if got := apiOut.Header().Get(header); got != want {
			t.Fatalf("verifier API should set %s=%q, got %q", header, want, got)
		}
	}
	apiBody := apiOut.Body.String()
	for _, want := range []string{`"verification"`, `"receipt"`, `"schema":"janus-witness-verification-v1"`, `"algorithm":"sha256-witness-verification-v1"`, `"hash_header":"X-Janus-Witness-Verification-Hash"`, `"body_field":"verification.receipt.hash"`, `"hash":"` + apiVerificationHash + `"`, `"input":"schema=janus-witness-verification-v1`, `"status":"verified"`, `"hash_match":true`, `"fresh":true`, `"verified":true`, `"request_id":"verify-ui-api-123"`, `"input_returned":false`, `"request_body_returned":false`, `"value_returned":false`} {
		if !strings.Contains(apiBody, want) {
			t.Fatalf("verifier API should include %q: %s", want, apiBody)
		}
	}
	for _, forbidden := range []string{`"proof_line"`, verifyReq.ProofLine, "subject-123", "person@example.test", "Person Name", "secret-cookie-secret"} {
		if strings.Contains(apiBody, forbidden) {
			t.Fatalf("verifier API leaked forbidden value %q: %s", forbidden, apiBody)
		}
	}
	assertRouteResponseValueFree(t, "session witness verifier API", apiOut)

}

func TestWitnessVerifierAPIRequiresCSRF(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "subject-123", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	for _, tc := range []struct {
		path string
		body string
	}{
		{path: "/api/auth/session-witness/verify", body: `{"proof_line":"secret-cookie-secret","proof_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://vault.barta.cm")
		req.AddCookie(rr.Result().Cookies()[0])
		out := httptest.NewRecorder()
		app.routes().ServeHTTP(out, req)
		if out.Code != http.StatusForbidden {
			t.Fatalf("%s expected 403, got %d body=%s", tc.path, out.Code, out.Body.String())
		}
		if strings.Contains(out.Body.String(), "secret-cookie-secret") || !strings.Contains(out.Body.String(), `"csrf_failed"`) {
			t.Fatalf("%s csrf failure should stay value-free: %s", tc.path, out.Body.String())
		}
	}
}

func TestConfigUsesHostPrefixedNonceCookieForHTTPS(t *testing.T) {
	app := newTestApp(t)

	if app.cfg.NonceCookieName() != hostNonceCookie {
		t.Fatalf("secure deployments should use host-prefixed nonce cookie, got %s", app.cfg.NonceCookieName())
	}
}

func TestConfigUsesHostPrefixedPKCECookieForHTTPS(t *testing.T) {
	app := newTestApp(t)

	if app.cfg.PKCECookieName() != hostPKCECookie {
		t.Fatalf("secure deployments should use host-prefixed PKCE cookie, got %s", app.cfg.PKCECookieName())
	}
}

func TestConfigUsesHostPrefixedReturnCookieForHTTPS(t *testing.T) {
	app := newTestApp(t)

	if app.cfg.ReturnCookieName() != hostReturnCookie {
		t.Fatalf("secure deployments should use host-prefixed return cookie, got %s", app.cfg.ReturnCookieName())
	}
}

func TestLoginRedirectBindsOIDCStateNonceAndPKCE(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	out := httptest.NewRecorder()
	app.handleLogin(out, req)
	if out.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d body=%s", out.Code, out.Body.String())
	}

	cookies := out.Result().Cookies()
	if len(cookies) != 4 {
		t.Fatalf("expected state, nonce, PKCE, and attempt cookies, got %#v", cookies)
	}
	state := cookieByName(t, cookies, hostStateCookie)
	nonce := cookieByName(t, cookies, hostNonceCookie)
	pkce := cookieByName(t, cookies, hostPKCECookie)
	attempt := cookieByName(t, cookies, hostAttemptCookie)
	for _, cookie := range []*http.Cookie{state, nonce, pkce} {
		if cookie.Value == "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 300 {
			t.Fatalf("OIDC cookie should be short-lived, secure, httponly, lax: %#v", cookie)
		}
	}
	if attempt.Value == "" || !attempt.Secure || !attempt.HttpOnly || attempt.SameSite != http.SameSiteLaxMode || attempt.MaxAge != int(loginAttemptTTL.Seconds()) {
		t.Fatalf("attempt cookie should be short-lived, secure, httponly, lax: %#v", attempt)
	}

	redirectURL, err := url.Parse(out.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := redirectURL.Query().Get("state"); got != state.Value {
		t.Fatalf("redirect state should match state cookie, got %q want %q", got, state.Value)
	}
	if got := redirectURL.Query().Get("nonce"); got != nonce.Value {
		t.Fatalf("redirect nonce should match nonce cookie, got %q want %q", got, nonce.Value)
	}
	if got := redirectURL.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("redirect should request S256 PKCE challenge, got %q", got)
	}
	if got := redirectURL.Query().Get("code_challenge"); got == "" || got == pkce.Value {
		t.Fatalf("redirect should include derived PKCE challenge, got %q verifier %q", got, pkce.Value)
	}
	if got := redirectURL.Query().Get("code_verifier"); got != "" {
		t.Fatalf("redirect must not leak PKCE verifier, got %q", got)
	}
}

func TestUnauthenticatedRootRendersBrandedLoginLanding(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()

	req := httptest.NewRequest(http.MethodGet, "/?ref=query-secret-sentinel", nil)
	for _, cookie := range []*http.Cookie{
		{Name: hostSessionCookie, Value: "session-cookie-sentinel"},
		{Name: hostStateCookie, Value: "state-cookie-sentinel"},
		{Name: hostNonceCookie, Value: "nonce-cookie-sentinel"},
		{Name: hostPKCECookie, Value: "pkce-cookie-sentinel"},
	} {
		req.AddCookie(cookie)
	}
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK || out.Header().Get("Location") != "" {
		t.Fatalf("unauthenticated root should render the landing page, got %d location=%q body=%s", out.Code, out.Header().Get("Location"), out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{`class="auth-body"`, "/static/janus-logo.svg", `/static/janus-login-hero.png`, "Open Janus", "Continue with Zitadel", `href="/login"`, "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("login landing should render %q: %s", want, body)
		}
	}
	if strings.Count(body, `href="/login"`) != 1 {
		t.Fatalf("login landing should have one clear sign-in action: %s", body)
	}
	for _, forbidden := range []string{"query-secret-sentinel", "session-cookie-sentinel", "state-cookie-sentinel", "nonce-cookie-sentinel", "pkce-cookie-sentinel", "zitadel-janus-oidc", "csb1-age-identity", "every secret, accounted for", "/static/janus-logo-full.png"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("unauthenticated landing leaked %q: %s", forbidden, body)
		}
	}
	if len(out.Result().Cookies()) != 0 {
		t.Fatalf("rendering the landing page must not start OIDC or set cookies: %#v", out.Result().Cookies())
	}
	assertStyleNonceMatchesCSP(t, out)
	assertRouteResponseValueFree(t, "unauthenticated branded landing", out)
}

func TestUnauthenticatedRootHEADMatchesLandingAndAPIStaysJSON(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()

	head := httptest.NewRequest(http.MethodHead, "/", nil)
	headOut := httptest.NewRecorder()
	app.routes().ServeHTTP(headOut, head)
	if headOut.Code != http.StatusOK || headOut.Header().Get("Location") != "" {
		t.Fatalf("HEAD / should match the unauthenticated landing status, got %d location=%q", headOut.Code, headOut.Header().Get("Location"))
	}

	api := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	apiOut := httptest.NewRecorder()
	app.routes().ServeHTTP(apiOut, api)
	if apiOut.Code != http.StatusUnauthorized || !strings.Contains(apiOut.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("unauthenticated API must remain a JSON 401, got %d type=%q body=%s", apiOut.Code, apiOut.Header().Get("Content-Type"), apiOut.Body.String())
	}
	if strings.Contains(apiOut.Body.String(), "auth-landing") || strings.Contains(apiOut.Body.String(), "janus-login-hero") || !strings.Contains(apiOut.Body.String(), `"value_returned":false`) {
		t.Fatalf("API auth denial should be value-free JSON, not login HTML: %s", apiOut.Body.String())
	}
}

func TestLoginHeroStaticAssetMatchesSuppliedImage(t *testing.T) {
	app := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "/static/janus-login-hero.png", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK || out.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("expected embedded PNG, got %d type=%q", out.Code, out.Header().Get("Content-Type"))
	}
	if got := out.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("expected static caching, got %q", got)
	}
	data := out.Body.Bytes()
	if len(data) != 582567 || !strings.HasPrefix(string(data[:8]), "\x89PNG\r\n\x1a\n") {
		t.Fatalf("unexpected hero asset: length=%d signature=%x", len(data), data[:min(8, len(data))])
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != "a9b5749e56a2e1d5adb01a16e047e208fea59a14c58e8a5a0f96bd3254a6fd79" {
		t.Fatalf("hero does not match the supplied image: %s", got)
	}
}

func TestAuthRequiredRedirectCarriesSafeReturnPath(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()

	req := httptest.NewRequest(http.MethodGet, "/auth/smoke", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected branded login landing, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Location"); got != "" {
		t.Fatalf("auth smoke landing should not redirect before the user chooses sign-in, got %q", got)
	}
	if !strings.Contains(out.Body.String(), `href="/login?next=%2Fauth%2Fsmoke"`) || !strings.Contains(out.Body.String(), "janus-login-hero.png") {
		t.Fatalf("auth smoke landing should preserve a safe return path and hero: %s", out.Body.String())
	}
	assertRouteResponseValueFree(t, "auth smoke auth-required landing", out)

	req = httptest.NewRequest(http.MethodGet, "/access?ref=deep-link-secret-sentinel", nil)
	out = httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `href="/login?next=%2Faccess"`) || !strings.Contains(out.Body.String(), "janus-login-hero.png") {
		t.Fatalf("protected deep link should render the hero landing with a safe return path: status=%d body=%s", out.Code, out.Body.String())
	}
	if strings.Contains(out.Body.String(), "deep-link-secret-sentinel") {
		t.Fatalf("protected deep-link query must not reach the login page: %s", out.Body.String())
	}
}

func TestLoginRedirectStoresSafeReturnPathWithoutLeakingToProvider(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()

	req := httptest.NewRequest(http.MethodGet, "/login?next=%2Fauth%2Fsmoke", nil)
	out := httptest.NewRecorder()
	app.handleLogin(out, req)
	if out.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d body=%s", out.Code, out.Body.String())
	}

	returnCookie := cookieByName(t, out.Result().Cookies(), hostReturnCookie)
	if returnCookie.Value == "" || !returnCookie.Secure || !returnCookie.HttpOnly || returnCookie.SameSite != http.SameSiteLaxMode || returnCookie.MaxAge != 300 {
		t.Fatalf("return cookie should be short-lived, secure, httponly, lax: %#v", returnCookie)
	}
	if strings.Contains(returnCookie.Value, "/auth/smoke") {
		t.Fatalf("return cookie should be signed/encoded, got %#v", returnCookie)
	}
	req = httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
	req.AddCookie(returnCookie)
	if got, ok := app.readOIDCLoginReturnPath(req); !ok || got != "/auth/smoke" {
		t.Fatalf("return cookie should recover /auth/smoke, got %q ok=%v", got, ok)
	}

	redirectURL, err := url.Parse(out.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"next", "return", "redirect_uri_return"} {
		if got := redirectURL.Query().Get(forbidden); got != "" {
			t.Fatalf("provider redirect must not receive %s=%q", forbidden, got)
		}
	}
	if strings.Contains(out.Header().Get("Location"), "/auth/smoke") {
		t.Fatalf("provider redirect should not expose return path: %s", out.Header().Get("Location"))
	}
}

func TestSafeLoginReturnPathRejectsOpenRedirectAndUnsafeRoutes(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		ok   bool
	}{
		{raw: "/auth/smoke", want: "/auth/smoke", ok: true},
		{raw: "/auth/smoke?ref=secret-cookie-secret", want: "/auth/smoke", ok: true},
		{raw: "/session-witness", want: "/session-witness", ok: true},
		{raw: "/session-witness/verify", want: "/session-witness/verify", ok: true},
		{raw: "/access?ref=query-secret-sentinel", want: "/access", ok: true},
		{raw: "/requests", want: "/requests", ok: true},
		{raw: "/ledger", want: "/ledger", ok: true},
		{raw: "/assurance", want: "/assurance", ok: true},
		{raw: "/settings", want: "/settings", ok: true},
		{raw: "/vault/new?service=query-secret-sentinel", want: "/vault/new", ok: true},
		{raw: "/", want: "/", ok: true},
		{raw: "https://evil.example/auth/smoke", want: "/", ok: false},
		{raw: "//evil.example/auth/smoke", want: "/", ok: false},
		{raw: "/\\evil.example", want: "/", ok: false},
		{raw: "/oidc/callback", want: "/", ok: false},
		{raw: "/login", want: "/", ok: false},
		{raw: "/auth/reset", want: "/", ok: false},
		{raw: "/api/posture", want: "/", ok: false},
		{raw: "/session-witness.txt", want: "/", ok: false},
		{raw: "/session-witness/evidence/record", want: "/", ok: false},
		{raw: "/logout", want: "/", ok: false},
		{raw: "?next=/auth/smoke", want: "/", ok: false},
		{raw: "/auth/smoke\r\nLocation:https://evil.example", want: "/", ok: false},
	}
	for _, tc := range cases {
		got, ok := safeLoginReturnPath(tc.raw)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("safeLoginReturnPath(%q) got %q ok=%v, want %q ok=%v", tc.raw, got, ok, tc.want, tc.ok)
		}
		if strings.Contains(got, "secret-cookie-secret") || strings.Contains(got, "query-secret-sentinel") || strings.Contains(got, "evil.example") {
			t.Fatalf("safe return path retained unsafe value from %q: %q", tc.raw, got)
		}
	}
}

func TestLoginRedirectClearsUnsafeReturnCookie(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()
	rr := httptest.NewRecorder()
	app.writeOIDCLoginReturnPath(rr, "/auth/smoke")
	staleReturn := cookieByName(t, rr.Result().Cookies(), hostReturnCookie)

	req := httptest.NewRequest(http.MethodGet, "/login?next=https%3A%2F%2Fevil.example%2Fauth%2Fsmoke", nil)
	req.AddCookie(staleReturn)
	out := httptest.NewRecorder()
	app.handleLogin(out, req)
	if out.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d body=%s", out.Code, out.Body.String())
	}
	if strings.Contains(out.Header().Get("Location"), "evil.example") {
		t.Fatalf("login redirect leaked unsafe return path: %s", out.Header().Get("Location"))
	}
	cleared := map[string]bool{}
	for _, cookie := range out.Result().Cookies() {
		if cookie.MaxAge < 0 {
			cleared[cookie.Name] = true
			if cookie.Value != "" {
				t.Fatalf("return clear cookie should not carry a value: %#v", cookie)
			}
		}
	}
	for _, name := range []string{hostReturnCookie, returnCookie} {
		if !cleared[name] {
			t.Fatalf("unsafe next should clear %s; cleared=%#v cookies=%#v", name, cleared, out.Result().Cookies())
		}
	}
}

func TestLoginRedirectUsesNoStoreHeaders(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("login redirect should not be cached, got Cache-Control %q", got)
	}
	if got := out.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("login redirect should include legacy no-cache pragma, got %q", got)
	}
	if got := out.Header().Get("Expires"); got != "0" {
		t.Fatalf("login redirect should include legacy expires header, got %q", got)
	}
}

func TestAuthResetClearsAllJanusCookiesAndRendersValueFreeRecovery(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()

	req := httptest.NewRequest(http.MethodGet, "/auth/reset", nil)
	req.Header.Set("X-Request-Id", "auth-reset-123")
	for _, name := range []string{hostSessionCookie, sessionCookie, hostStateCookie, stateCookie, hostNonceCookie, nonceCookie, hostPKCECookie, pkceCookie, hostReturnCookie, returnCookie, hostAttemptCookie, attemptCookie} {
		req.AddCookie(&http.Cookie{Name: name, Value: name + "-secret-cookie-secret"})
	}
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected reset page 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Clean sign-in reset", "Auth recovery", "reset_complete", "Sign in cleanly", "session_cookie_cleared=true", "oidc_cookies_cleared=true", "attempt_cookie_cleared=true", "cookie_value_returned=false", "value_returned=false", "request_id=auth-reset-123"} {
		if !strings.Contains(body, want) {
			t.Fatalf("auth reset page should include %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"secret-cookie-secret", "state-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret", "attempt-cookie-secret", "raw-secret-value", "token_returned=true", "value_returned=true"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("auth reset page leaked forbidden value %q: %s", forbidden, body)
		}
	}
	cleared := map[string]bool{}
	for _, cookie := range out.Result().Cookies() {
		if cookie.MaxAge < 0 {
			cleared[cookie.Name] = true
		}
		if cookie.Value != "" {
			t.Fatalf("auth reset clearing cookie should not carry a value: %#v", cookie)
		}
	}
	for _, name := range []string{hostSessionCookie, sessionCookie, hostStateCookie, stateCookie, hostNonceCookie, nonceCookie, hostPKCECookie, pkceCookie, hostReturnCookie, returnCookie, hostAttemptCookie, attemptCookie} {
		if !cleared[name] {
			t.Fatalf("expected auth reset to clear %s; cleared=%#v cookies=%#v", name, cleared, out.Result().Cookies())
		}
	}
	for header, want := range map[string]string{
		"Content-Type":                      "text/html; charset=utf-8",
		"Cache-Control":                     "no-store",
		"X-Content-Type-Options":            "nosniff",
		"Cross-Origin-Resource-Policy":      "same-origin",
		"Cross-Origin-Opener-Policy":        "same-origin",
		"Cross-Origin-Embedder-Policy":      "credentialless",
		"X-Frame-Options":                   "DENY",
		"Strict-Transport-Security":         "max-age=31536000; includeSubDomains",
		"X-Permitted-Cross-Domain-Policies": "none",
	} {
		if got := out.Header().Get(header); got != want {
			t.Fatalf("auth reset should set %s=%q, got %q", header, want, got)
		}
	}
	if got := out.Header().Get("Content-Security-Policy"); !strings.Contains(got, "script-src 'none'") || !strings.Contains(got, "form-action 'self'") {
		t.Fatalf("auth reset page should keep strict CSP, got %q", got)
	}
	recent := app.store.RecentAudit(1)
	if len(recent) != 1 || recent[0].Action != "auth.login.clean_reset" || recent[0].Outcome != "allowed" || recent[0].RequestID != "auth-reset-123" {
		t.Fatalf("auth reset should write a correlated audit event, got %#v", recent)
	}
	assertRouteResponseValueFree(t, "auth reset", out)
}

func TestLoginResetQueryUsesCleanResetPage(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()

	req := httptest.NewRequest(http.MethodGet, "/login?reset=1", nil)
	req.Header.Set("X-Request-Id", "login-reset-query-123")
	req.AddCookie(&http.Cookie{Name: hostSessionCookie, Value: "session-cookie-secret"})
	req.AddCookie(&http.Cookie{Name: hostAttemptCookie, Value: "attempt-cookie-secret"})
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected clean reset page, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Clean sign-in reset", "request_id=login-reset-query-123", "session_cookie_cleared=true", "attempt_cookie_cleared=true", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("login reset query should render clean reset page with %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"session-cookie-secret", "attempt-cookie-secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("login reset query leaked forbidden value %q: %s", forbidden, body)
		}
	}
}

func TestCallbackBadStateRendersValueFreeAuthError(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()
	app.verifier = &oidc.IDTokenVerifier{}

	req := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=bad", nil)
	req.AddCookie(&http.Cookie{Name: hostStateCookie, Value: "state-cookie-secret"})
	req.AddCookie(&http.Cookie{Name: hostNonceCookie, Value: "nonce-cookie-secret"})
	req.AddCookie(&http.Cookie{Name: hostPKCECookie, Value: "pkce-cookie-secret"})
	req.Header.Set("X-Request-Id", "auth-test-123")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Login needs a fresh start", "login_restart_required", "value_returned=false", "request_id=auth-test-123", "Try again"} {
		if !strings.Contains(body, want) {
			t.Fatalf("auth error page should include %q: %s", want, body)
		}
	}
	if got := out.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("auth error page should be HTML, got %q", got)
	}
	if got := out.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("auth error page should not be cached, got %q", got)
	}
	if got := out.Header().Get("Content-Security-Policy"); !strings.Contains(got, "script-src 'none'") {
		t.Fatalf("auth error page should keep no-script CSP, got %q", got)
	}
	for _, forbidden := range []string{"bad_state", "missing_nonce", "missing_pkce", "code_exchange_failed", "id_token_verify_failed"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("auth error page should not expose internal reason %q: %s", forbidden, body)
		}
	}
	for _, forbidden := range []string{"state-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret", "plaintext"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("auth error page leaked %q: %s", forbidden, body)
		}
	}
	cleared := map[string]bool{}
	for _, cookie := range out.Result().Cookies() {
		if cookie.MaxAge < 0 {
			cleared[cookie.Name] = true
		}
	}
	for _, name := range []string{hostStateCookie, hostNonceCookie, hostPKCECookie, hostReturnCookie, stateCookie, nonceCookie, pkceCookie, returnCookie} {
		if !cleared[name] {
			t.Fatalf("expected callback failure to clear %s; cleared=%#v cookies=%#v", name, cleared, out.Result().Cookies())
		}
	}
}

func TestCallbackProviderErrorRendersSafeAuthFailure(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()
	app.verifier = &oidc.IDTokenVerifier{}

	req := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=state-cookie-secret&error=access_denied&error_description=raw-secret-value", nil)
	req.AddCookie(&http.Cookie{Name: hostStateCookie, Value: "state-cookie-secret"})
	req.AddCookie(&http.Cookie{Name: hostNonceCookie, Value: "nonce-cookie-secret"})
	req.AddCookie(&http.Cookie{Name: hostPKCECookie, Value: "pkce-cookie-secret"})
	req.Header.Set("X-Request-Id", "auth-provider-error-123")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Login was not completed", "identity_login_denied", "provider_error_returned=false", "raw_callback_query_returned=false", "token_returned=false", "request_id=auth-provider-error-123", "Reset login session"} {
		if !strings.Contains(body, want) {
			t.Fatalf("provider error page should include %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"access_denied", "raw-secret-value", "state-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("provider error page leaked %q: %s", forbidden, body)
		}
	}
}

func TestLoginLoopGuardPausesBeforeAnotherRedirect(t *testing.T) {
	app := newTestApp(t)
	app.oauth = testOAuthConfig()

	var jar []*http.Cookie
	for i := 0; i < maxLoginAttempts; i++ {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		for _, cookie := range jar {
			req.AddCookie(cookie)
		}
		out := httptest.NewRecorder()
		app.routes().ServeHTTP(out, req)
		if out.Code != http.StatusFound {
			t.Fatalf("attempt %d should redirect, got %d body=%s", i+1, out.Code, out.Body.String())
		}
		jar = mergeCookieJar(jar, out.Result().Cookies())
	}

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.Header.Set("X-Request-Id", "loop-guard-123")
	for _, cookie := range jar {
		req.AddCookie(cookie)
	}
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusTooManyRequests {
		t.Fatalf("expected loop guard 429, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Location"); got != "" {
		t.Fatalf("loop guard should render Janus page instead of redirecting, got Location %q", got)
	}
	body := out.Body.String()
	for _, want := range []string{"Login loop paused", "login_loop_paused", "Redirect loop guard", "Reset login session", "request_id=loop-guard-123", "provider_error_returned=false", "cookie_value_returned=false", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("loop guard page should include %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"auth.example.test", "state-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret", "raw-secret-value"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("loop guard page leaked %q: %s", forbidden, body)
		}
	}
}

func TestAuthFailurePostureIsValueFree(t *testing.T) {
	posture := AuthFailurePostureFor(testConfig())
	if posture.State != "ready" || posture.Label != "Auth failure posture" || posture.EvidenceSignal != "presence_only_auth_failure_posture" {
		t.Fatalf("unexpected auth failure posture: %#v", posture)
	}
	if posture.LoopGuard.State != "enabled" || posture.LoopGuard.MaxAttempts != maxLoginAttempts || posture.LoopGuard.WindowSeconds != int(loginAttemptTTL.Seconds()) {
		t.Fatalf("loop guard should be explicit: %#v", posture.LoopGuard)
	}
	if posture.RawCallbackQueryReturned || posture.ProviderErrorReturned || posture.RedirectURLReturned || posture.TokenReturned || posture.CookieValueReturned || posture.RequestBodyReturned || posture.EnvReturned || posture.BackendPathReturned || posture.ValueReturned {
		t.Fatalf("auth failure posture should stay value-free: %#v", posture)
	}
	for _, key := range []string{"login_restart_required", "login_integrity_check_failed", "identity_login_denied", "authorization_code_missing", "identity_response_failed", "login_loop_paused"} {
		if !authFailurePostureHasReason(posture, key) {
			t.Fatalf("auth failure posture should include %q: %#v", key, posture)
		}
	}
}

func TestAPIRequiresAuthReturnsValueFreeJSON(t *testing.T) {
	app := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Location"); got != "" {
		t.Fatalf("API auth denial should not redirect, got Location %q", got)
	}
	if got := out.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("API auth denial should be JSON, got %q", got)
	}
	body := out.Body.String()
	if !strings.Contains(body, `"error":"auth_required"`) || !strings.Contains(body, `"value_returned":false`) {
		t.Fatalf("API auth denial should be value-free JSON: %s", body)
	}
}

func TestAPISetupIncompleteReturnsValueFreeJSON(t *testing.T) {
	app := newTestApp(t)
	app.cfg.OIDCSecret = ""

	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("API setup denial should be JSON, got %q", got)
	}
	body := out.Body.String()
	if !strings.Contains(body, `"error":"auth_not_configured"`) || !strings.Contains(body, `"value_returned":false`) {
		t.Fatalf("API setup denial should be value-free JSON: %s", body)
	}
}

func TestValidOIDCNonce(t *testing.T) {
	if !validOIDCNonce("nonce-123", "nonce-123") {
		t.Fatal("matching nonce should be valid")
	}
	for _, tc := range []struct {
		name     string
		expected string
		got      string
	}{
		{name: "missing expected", expected: "", got: "nonce-123"},
		{name: "missing claim", expected: "nonce-123", got: ""},
		{name: "mismatch", expected: "nonce-123", got: "nonce-456"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if validOIDCNonce(tc.expected, tc.got) {
				t.Fatal("nonce should be rejected")
			}
		})
	}
}

func TestLogoutRequiresCSRF(t *testing.T) {
	app := newTestApp(t)
	rr := httptest.NewRecorder()
	app.writeSession(rr, Session{Subject: "user-1", Expiry: time.Now().UTC().Add(time.Hour)})
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(rr.Result().Cookies()[0])
	req.Header.Set("X-Request-Id", "logout-test-123")

	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("expected CSRF denial, got %d", out.Code)
	}
	body := out.Body.String()
	for _, want := range []string{"Sign out needs a fresh page", "logout_integrity_check_failed", "value_returned=false", "request_id=logout-test-123"} {
		if !strings.Contains(body, want) {
			t.Fatalf("logout CSRF page should include %q: %s", want, body)
		}
	}
}

func TestWardenResolveReturnsHandleOnly(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "user-1", Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"zitadel-janus-oidc","reason":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://vault.barta.cm")
	req.Header.Set("X-CSRF-Token", app.csrfToken(session))
	req.Header.Set("X-Request-Id", "receipt-handle-1")
	req.AddCookie(rr.Result().Cookies()[0])

	out := httptest.NewRecorder()
	app.withAuth(app.handleResolveHandle)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	if !strings.Contains(body, `"value_returned":false`) || strings.Contains(body, `"plaintext"`) {
		t.Fatalf("handle response is not value-free: %s", body)
	}
	for _, want := range []string{`"receipt"`, `"schema":"janus-action-receipt-v1"`, `"algorithm":"sha256-json-v1"`, `"receipt_id":"ar_`, `"receipt_hash":"`, `"action":"warden.resolve"`, `"request_id":"receipt-handle-1"`, `"role_checked":true`, `"csrf_checked":true`, `"readiness_checked":true`, `"audit_recorded":true`, `"boundary":"metadata_only"`, `"tamper_evident":true`, `"secret_value_returned":false`, `"request_body_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("handle response should include action receipt %s: %s", want, body)
		}
	}
	var decoded struct {
		Receipt ActionReceipt `json:"receipt"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	assertActionReceiptProof(t, decoded.Receipt, "warden.resolve", "receipt-handle-1")
}

func TestCrossOriginMutationDeniedWithValidCSRF(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "operator", Roles: []string{RoleOperator, RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"zitadel-janus-oidc","reason":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("X-CSRF-Token", app.csrfToken(session))
	req.AddCookie(rr.Result().Cookies()[0])

	out := httptest.NewRecorder()
	app.withAuth(app.requireRole(RoleOperator, "warden.resolve", app.handleResolveHandle))(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", out.Code, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), `"csrf_failed"`) || !strings.Contains(out.Body.String(), `"value_returned":false`) {
		t.Fatalf("cross-origin denial should be value-free CSRF JSON: %s", out.Body.String())
	}
}

func TestWardenResolveWorksWhenAuthDisabledForLocalSmoke(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"zitadel-janus-oidc","reason":"local smoke"}`))
	req.Header.Set("Content-Type", "application/json")

	out := httptest.NewRecorder()
	app.withAuth(app.handleResolveHandle)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	if strings.Contains(out.Body.String(), `"plaintext"`) {
		t.Fatalf("response should be value-free: %s", out.Body.String())
	}
}

func TestPermitAPIsReturnValueFreeActionReceipts(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	create := httptest.NewRequest(http.MethodPost, "/api/permits", strings.NewReader(`{"ref":"zitadel-janus-oidc","action":"metadata_use","destination":"dashboard","reason":"local smoke"}`))
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("X-Request-Id", "receipt-permit-create")
	createOut := httptest.NewRecorder()
	app.routes().ServeHTTP(createOut, create)
	if createOut.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", createOut.Code, createOut.Body.String())
	}
	createBody := createOut.Body.String()
	for _, want := range []string{`"receipt"`, `"schema":"janus-action-receipt-v1"`, `"algorithm":"sha256-json-v1"`, `"receipt_id":"ar_`, `"receipt_hash":"`, `"action":"permit.create"`, `"request_id":"receipt-permit-create"`, `"audit_recorded":true`, `"boundary":"metadata_only"`, `"tamper_evident":true`, `"secret_value_returned":false`, `"request_body_returned":false`, `"value_returned":false`} {
		if !strings.Contains(createBody, want) {
			t.Fatalf("permit create should include action receipt %s: %s", want, createBody)
		}
	}
	assertRouteResponseValueFree(t, "permit create receipt", createOut)

	var created struct {
		Permit  Permit        `json:"permit"`
		Receipt ActionReceipt `json:"receipt"`
	}
	if err := json.Unmarshal(createOut.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	assertActionReceiptProof(t, created.Receipt, "permit.create", "receipt-permit-create")
	run := httptest.NewRequest(http.MethodPost, "/api/permits/"+created.Permit.ID+"/run", nil)
	run.SetPathValue("permitID", created.Permit.ID)
	run.Header.Set("X-Request-Id", "receipt-permit-run")
	runOut := httptest.NewRecorder()
	app.routes().ServeHTTP(runOut, run)
	if runOut.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", runOut.Code, runOut.Body.String())
	}
	runBody := runOut.Body.String()
	for _, want := range []string{`"receipt"`, `"schema":"janus-action-receipt-v1"`, `"algorithm":"sha256-json-v1"`, `"receipt_id":"ar_`, `"receipt_hash":"`, `"action":"permit.run"`, `"request_id":"receipt-permit-run"`, `"audit_recorded":true`, `"boundary":"metadata_only"`, `"tamper_evident":true`, `"secret_value_returned":false`, `"request_body_returned":false`, `"value_returned":false`} {
		if !strings.Contains(runBody, want) {
			t.Fatalf("permit run should include action receipt %s: %s", want, runBody)
		}
	}
	var ran struct {
		Receipt ActionReceipt `json:"receipt"`
	}
	if err := json.Unmarshal(runOut.Body.Bytes(), &ran); err != nil {
		t.Fatal(err)
	}
	assertActionReceiptProof(t, ran.Receipt, "permit.run", "receipt-permit-run")
	assertRouteResponseValueFree(t, "permit run receipt", runOut)
}

func TestSensitiveAPIFailsClosedWhenReadinessDegraded(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.permits = nil

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"zitadel-janus-oidc","reason":"local smoke"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "degraded-api-1")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{`"error":"system_degraded"`, `"request_id":"degraded-api-1"`, `"redacted":true`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("degraded API denial should include %s: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") || strings.Contains(body, "secret-cookie-secret") {
		t.Fatalf("degraded API denial should remain value-free: %s", body)
	}
}

func TestOversizedAPIRequestIsRejectedValueFree(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(strings.Repeat("x", int(maxRequestBody)+1)))
	req.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	if !strings.Contains(body, `"request_too_large"`) || !strings.Contains(body, `"value_returned":false`) || strings.Contains(body, "plaintext") {
		t.Fatalf("oversized denial should be value-free JSON: %s", body)
	}
}

func TestFailedLookupDoesNotEchoRefIntoAuditSecretRef(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"do-not-echo-this","reason":"local smoke"}`))
	req.Header.Set("Content-Type", "application/json")

	out := httptest.NewRecorder()
	app.withAuth(app.handleResolveHandle)(out, req)
	if out.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", out.Code, out.Body.String())
	}
	recent := app.store.RecentAudit(1)
	if len(recent) != 1 {
		t.Fatalf("expected one audit event, got %d", len(recent))
	}
	if recent[0].SecretRef != "" {
		t.Fatalf("failed lookup echoed ref into audit secret_ref: %#v", recent[0])
	}
}

func TestPostureAPIIsValueFree(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	out := httptest.NewRecorder()
	app.withAuth(app.handlePosture)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	if !strings.Contains(body, `"value_returned":false`) || strings.Contains(body, `"plaintext"`) {
		t.Fatalf("posture response should be value-free: %s", body)
	}
	if !strings.Contains(body, `"catalog_gate_count"`) {
		t.Fatalf("posture response should include catalog gates: %s", body)
	}
	if !strings.Contains(body, `"access"`) || !strings.Contains(body, `"role_gated_audit_evidence"`) {
		t.Fatalf("posture response should include access policy: %s", body)
	}
	if !strings.Contains(body, `"role_duty_matrix":true`) || !strings.Contains(body, `"duty_model":"shared_v1_roles_with_hard_separation"`) || !strings.Contains(body, `"claim_policy":"explicit_only"`) || !strings.Contains(body, `"implicit_elevated_claims":false`) || !strings.Contains(body, `"key":"implicit_elevated_claims"`) || !strings.Contains(body, `"state":"disabled"`) {
		t.Fatalf("posture response should include role duty matrix posture: %s", body)
	}
	if !strings.Contains(body, `"role_availability"`) || !strings.Contains(body, `"dashboard_strip":true`) || !strings.Contains(body, `"role_availability_ux"`) {
		t.Fatalf("posture response should include role availability UX: %s", body)
	}
	if !strings.Contains(body, `"action_readiness"`) || !strings.Contains(body, `"key":"evidence_export"`) || !strings.Contains(body, `"key":"handle_issue"`) || !strings.Contains(body, `"key":"permit_run_check"`) || !strings.Contains(body, `"action_readiness":"role_and_readiness_matrix"`) || !strings.Contains(body, `"role_aware_action_readiness"`) {
		t.Fatalf("posture response should include action readiness matrix: %s", body)
	}
	if !strings.Contains(body, `"action_receipts":"mutation_result_receipts"`) || !strings.Contains(body, `"action_receipt_integrity":"tamper_evident_hash_proof"`) || !strings.Contains(body, `"action_receipt_verification":"copy_safe_ui_fields"`) || !strings.Contains(body, `"value_free_action_receipts"`) || !strings.Contains(body, `"tamper_evident_action_receipts"`) || !strings.Contains(body, `"action_receipt_verification_ux"`) {
		t.Fatalf("posture response should include action receipt capability: %s", body)
	}
	if !strings.Contains(body, `"audit_failure_drill"`) || !strings.Contains(body, `"scenario":"audit_sink_or_chain_degraded"`) || !strings.Contains(body, `"key":"sink_write"`) || !strings.Contains(body, `"key":"public_readiness"`) || !strings.Contains(body, `"audit_failure_drill":"fail_closed_dashboard_posture_evidence"`) {
		t.Fatalf("posture response should include audit failure drill: %s", body)
	}
	if !strings.Contains(body, `"auth_failure_posture"`) || !strings.Contains(body, `"label":"Auth failure posture"`) || !strings.Contains(body, `"evidence_signal":"presence_only_auth_failure_posture"`) || !strings.Contains(body, `"identity_provider":"zitadel_oidc"`) || !strings.Contains(body, `"key":"login_loop_paused"`) || !strings.Contains(body, `"raw_callback_query_returned":false`) || !strings.Contains(body, `"provider_error_returned":false`) || !strings.Contains(body, `"redirect_url_returned":false`) || !strings.Contains(body, `"token_returned":false`) || !strings.Contains(body, `"cookie_value_returned":false`) || !strings.Contains(body, `"request_body_returned":false`) || !strings.Contains(body, `"env_returned":false`) || !strings.Contains(body, `"backend_path_returned":false`) || !strings.Contains(body, `"auth_failure_posture":"safe_reason_codes_no_provider_values"`) || !strings.Contains(body, `"oidc_redirect_loop_guard"`) {
		t.Fatalf("posture response should include auth failure posture: %s", body)
	}
	if !strings.Contains(body, `"authenticated_role_evidence"`) || !strings.Contains(body, `"label":"Signed-in role receipt"`) || !strings.Contains(body, `"evidence_signal":"signed_in_role_receipt_no_identity_values"`) || !strings.Contains(body, `"identity_boundary":"identity_claim_values_withheld"`) || !strings.Contains(body, `"key":"identity_boundary"`) || !strings.Contains(body, `"identity_values_returned":false`) || !strings.Contains(body, `"subject_returned":false`) || !strings.Contains(body, `"email_returned":false`) || !strings.Contains(body, `"name_returned":false`) || !strings.Contains(body, `"claim_values_returned":false`) || !strings.Contains(body, `"group_values_returned":false`) || !strings.Contains(body, `"token_returned":false`) || !strings.Contains(body, `"cookie_value_returned":false`) || !strings.Contains(body, `"authenticated_role_receipt"`) {
		t.Fatalf("posture response should include authenticated role evidence: %s", body)
	}
	if !strings.Contains(body, `"authenticated_browser_witness"`) || !strings.Contains(body, `"label":"Authenticated browser witness"`) || !strings.Contains(body, `"flow":"local_dev_signed_session"`) || !strings.Contains(body, `"session_cookie_policy":"host_prefixed_strict_signed"`) || !strings.Contains(body, `"csrf_boundary":"bound_to_signed_session"`) || !strings.Contains(body, `"csp_boundary":"script_src_none"`) || !strings.Contains(body, `"evidence_signal":"signed_session_browser_proof_no_identity_values"`) || !strings.Contains(body, `"connector_output_returned":false`) || !strings.Contains(body, `"permit_payload_returned":false`) || !strings.Contains(body, `"secret_value_returned":false`) || !strings.Contains(body, `"authenticated_browser_witness_api"`) {
		t.Fatalf("posture response should include authenticated browser witness: %s", body)
	}
	if !strings.Contains(body, `"role_policy_readiness"`) || !strings.Contains(body, `"label":"Role policy readiness"`) || !strings.Contains(body, `"evidence_signal":"bootstrap_to_explicit_zitadel_lanes"`) || !strings.Contains(body, `"key":"zitadel_lanes"`) || !strings.Contains(body, `"bootstrap_owner_state"`) || !strings.Contains(body, `"subject_binding_configured"`) || !strings.Contains(body, `"group_binding_configured"`) || !strings.Contains(body, `"subject_values_returned":false`) || !strings.Contains(body, `"group_values_returned":false`) || !strings.Contains(body, `"claim_values_returned":false`) || !strings.Contains(body, `"token_returned":false`) || !strings.Contains(body, `"backend_path_returned":false`) || !strings.Contains(body, `"role_policy_readiness_workflow"`) {
		t.Fatalf("posture response should include role policy readiness workflow: %s", body)
	}
	if !strings.Contains(body, `"scope"`) || !strings.Contains(body, `"scope_bound_metadata"`) {
		t.Fatalf("posture response should include scope policy: %s", body)
	}
	if !strings.Contains(body, `"lifecycle"`) || !strings.Contains(body, `"lifecycle_gated_normal_use"`) {
		t.Fatalf("posture response should include lifecycle policy: %s", body)
	}
	if !strings.Contains(body, `"permits"`) || !strings.Contains(body, `"persistent_permit_records"`) {
		t.Fatalf("posture response should include permit persistence: %s", body)
	}
	if !strings.Contains(body, `"cookies"`) || !strings.Contains(body, `"host_prefixed_cookies"`) {
		t.Fatalf("posture response should include cookie hardening: %s", body)
	}
	if !strings.Contains(body, `"request_correlation"`) || !strings.Contains(body, `"request_correlation_ids"`) {
		t.Fatalf("posture response should include request correlation: %s", body)
	}
	if !strings.Contains(body, `"cors"`) || !strings.Contains(body, `"policy":"deny_by_default"`) || !strings.Contains(body, `"access_control_allow_origin":"absent"`) || !strings.Contains(body, `"deny_by_default_cors"`) {
		t.Fatalf("posture response should include deny-by-default CORS posture: %s", body)
	}
	if !strings.Contains(body, `"assurance"`) || !strings.Contains(body, `"route_value_leak_sentinel":true`) || !strings.Contains(body, `"json_errors_request_id":true`) || !strings.Contains(body, `"backend_source_paths":"not_returned"`) || !strings.Contains(body, `"role_policy_proof":"explicit_counts_no_values"`) || !strings.Contains(body, `"role_claim_policy":"explicit_only_no_ambient_grants"`) || !strings.Contains(body, `"route_value_leak_sentinel"`) || !strings.Contains(body, `"request_correlated_json_errors"`) || !strings.Contains(body, `"strict_role_claim_policy"`) {
		t.Fatalf("posture response should include route value-leak assurance: %s", body)
	}
	if !strings.Contains(body, `"evidence_export_boundary":"dashboard_and_json"`) || !strings.Contains(body, `"evidence_export_boundary_ux"`) {
		t.Fatalf("posture response should include evidence export boundary posture: %s", body)
	}
	if !strings.Contains(body, `"evidence_download":"auditor_json_with_pack_hash"`) || !strings.Contains(body, `"evidence_download_receipt"`) {
		t.Fatalf("posture response should include evidence download affordance: %s", body)
	}
	if !strings.Contains(body, `"evidence_receipt"`) || !strings.Contains(body, `"state":"ready"`) || !strings.Contains(body, `"hash_header":"X-Janus-Evidence-Hash"`) || !strings.Contains(body, `"body_field":"integrity.pack_hash"`) || !strings.Contains(body, `"evidence_receipt":"download_header_body_match"`) || !strings.Contains(body, `"exact_evidence_download_receipt"`) {
		t.Fatalf("posture response should include exact evidence receipt posture: %s", body)
	}
	if !strings.Contains(body, `"assurance_summary"`) || !strings.Contains(body, `"verdict"`) || !strings.Contains(body, `"Value boundary"`) || !strings.Contains(body, `"human_readable_assurance_summary"`) || !strings.Contains(body, `"human_readable_summary":"dashboard_posture_evidence"`) {
		t.Fatalf("posture response should include human-readable assurance summary: %s", body)
	}
	if !strings.Contains(body, `"assurance_gates"`) || !strings.Contains(body, `"key":"role_denial"`) || !strings.Contains(body, `"key":"catalog_metadata"`) || !strings.Contains(body, `"key":"degraded_actions"`) || !strings.Contains(body, `"key":"value_leak_sentinel"`) || !strings.Contains(body, `"assurance_gate_proof_strip"`) {
		t.Fatalf("posture response should include assurance gate proofs: %s", body)
	}
	if !strings.Contains(body, `"negative_path_assurance"`) || !strings.Contains(body, `"key":"audit_sink_degraded"`) || !strings.Contains(body, `"key":"sensitive_action_guard"`) || !strings.Contains(body, `"negative_path_assurance_matrix"`) || !strings.Contains(body, `"negative_path_assurance":"dashboard_posture_evidence"`) {
		t.Fatalf("posture response should include negative-path assurance: %s", body)
	}
	if !strings.Contains(body, `"degraded_guidance"`) || !strings.Contains(body, `"key":"audit_sink"`) || !strings.Contains(body, `"key":"evidence_export"`) || !strings.Contains(body, `"degraded_guidance_panel"`) || !strings.Contains(body, `"degraded_guidance":"dashboard_posture_evidence"`) {
		t.Fatalf("posture response should include degraded-state guidance: %s", body)
	}
	if !strings.Contains(body, `"operational_status"`) || !strings.Contains(body, `"key":"role_duties"`) || !strings.Contains(body, `"key":"value_boundary"`) || !strings.Contains(body, `"operational_status_strip"`) || !strings.Contains(body, `"operational_status":"dashboard_posture_strip"`) {
		t.Fatalf("posture response should include operational status strip: %s", body)
	}
	if !strings.Contains(body, `"mode_posture"`) || !strings.Contains(body, `"current":"Self-hosted"`) || !strings.Contains(body, `"enterprise":"not_claimed"`) || !strings.Contains(body, `"mode_posture_evidence"`) {
		t.Fatalf("posture response should include product-mode evidence: %s", body)
	}
	if !strings.Contains(body, `"privacy_posture"`) || !strings.Contains(body, `"key":"request_bodies"`) || !strings.Contains(body, `"key":"prompt_command_env"`) || !strings.Contains(body, `"key":"auth_cookie_secrets"`) || !strings.Contains(body, `"privacy_retention_posture"`) || !strings.Contains(body, `"privacy_retention":"dashboard_posture_evidence"`) {
		t.Fatalf("posture response should include privacy and retention posture: %s", body)
	}
	if !strings.Contains(body, `"response_hardening"`) || !strings.Contains(body, `"no_store_responses"`) {
		t.Fatalf("posture response should include response hardening: %s", body)
	}
	if !strings.Contains(body, `"request_limits"`) || !strings.Contains(body, `"max_body_bytes":4096`) || !strings.Contains(body, `"request_body_size_limit"`) {
		t.Fatalf("posture response should include request body limits: %s", body)
	}
	if !strings.Contains(body, `"availability"`) || !strings.Contains(body, `"sensitive_actions_require_readiness":true`) || !strings.Contains(body, `"degraded_sensitive_action_guard"`) {
		t.Fatalf("posture response should include degraded sensitive-action guard: %s", body)
	}
	if !strings.Contains(body, `"degraded_dashboard_banner"`) {
		t.Fatalf("posture response should include degraded dashboard banner capability: %s", body)
	}
	if !strings.Contains(body, `"safe_failure_pages":true`) || !strings.Contains(body, `"safe_auth_failure_pages"`) || !strings.Contains(body, `"auth_error_view":"safe_category_request_id"`) || !strings.Contains(body, `"oidc_redirect_loop_guard":"bounded_attempt_cookie_no_values"`) {
		t.Fatalf("posture response should include safe auth failure pages: %s", body)
	}
	if !strings.Contains(body, `"safe_http_boundary_failures":true`) || !strings.Contains(body, `"safe_http_boundary_failures"`) || !strings.Contains(body, `"http_boundary_error_view":"safe_category_request_id"`) {
		t.Fatalf("posture response should include safe HTTP boundary failures: %s", body)
	}
	if !strings.Contains(body, `"public_health_redacted":true`) || !strings.Contains(body, `"redacted_public_health"`) {
		t.Fatalf("posture response should include redacted public health: %s", body)
	}
	if !strings.Contains(body, `"public_readiness_redacted":true`) || !strings.Contains(body, `"redacted_public_readiness"`) {
		t.Fatalf("posture response should include redacted public readiness: %s", body)
	}
	if !strings.Contains(body, `"public_readiness_auth_redacted":true`) || !strings.Contains(body, `"minimal_public_readiness"`) {
		t.Fatalf("posture response should include minimal public readiness: %s", body)
	}
	if !strings.Contains(body, `"script_src":"none"`) || !strings.Contains(body, `"no_script_csp"`) {
		t.Fatalf("posture response should include no-script CSP hardening: %s", body)
	}
	if !strings.Contains(body, `"cross_origin_resource_policy":"same-origin"`) || !strings.Contains(body, `"cross_domain_policy":"none"`) || !strings.Contains(body, `"browser_isolation_headers"`) {
		t.Fatalf("posture response should include browser isolation headers: %s", body)
	}
	if !strings.Contains(body, `"cross_origin_embedder_policy":"credentialless"`) || !strings.Contains(body, `"cross_origin_opener_policy":"same-origin"`) || !strings.Contains(body, `"dns_prefetch_control":"off"`) || !strings.Contains(body, `"origin_agent_cluster":true`) || !strings.Contains(body, `"security_header_regression":"core_routes"`) || !strings.Contains(body, `"security_header_regression_table"`) {
		t.Fatalf("posture response should include security header regression posture: %s", body)
	}
	if !strings.Contains(body, `"audit_event_severity"`) || !strings.Contains(body, `"severity_counts"`) {
		t.Fatalf("posture response should include audit severity: %s", body)
	}
	if !strings.Contains(body, `"api_errors"`) || !strings.Contains(body, `"api_json_auth_errors"`) {
		t.Fatalf("posture response should include API error posture: %s", body)
	}
	if !strings.Contains(body, `"rate_limit_retry_after":true`) || !strings.Contains(body, `"rate_limit_request_id":true`) || !strings.Contains(body, `"operational_rate_limit_denials"`) {
		t.Fatalf("posture response should include operational rate-limit denials: %s", body)
	}
	if !strings.Contains(body, `"readiness"`) || !strings.Contains(body, `"value_free_readiness"`) {
		t.Fatalf("posture response should include readiness posture: %s", body)
	}
	if !strings.Contains(body, `"auth"`) || !strings.Contains(body, `"oidc_nonce_bound_login"`) || !strings.Contains(body, `"pkce_s256_auth_code"`) || !strings.Contains(body, `"oidc_redirect_loop_guard":"bounded_attempt_cookie"`) {
		t.Fatalf("posture response should include hardened OIDC login controls: %s", body)
	}
	if !strings.Contains(body, `"session"`) || !strings.Contains(body, `"signed_session_expiry"`) {
		t.Fatalf("posture response should include session posture: %s", body)
	}
	if !strings.Contains(body, `"cookie_same_site":"Strict"`) || !strings.Contains(body, `"session_same_site":"Strict"`) || !strings.Contains(body, `"oidc_login_same_site":"Lax"`) || !strings.Contains(body, `"strict_session_cookie"`) {
		t.Fatalf("posture response should include strict session cookie split: %s", body)
	}
	if !strings.Contains(body, `"same_origin_mutations":"origin_or_referer_when_present"`) || !strings.Contains(body, `"same_origin_mutation_guard"`) {
		t.Fatalf("posture response should include same-origin mutation guard: %s", body)
	}
	if !strings.Contains(body, `"approved_use"`) || !strings.Contains(body, `"approved_metadata_use_enforced"`) {
		t.Fatalf("posture response should include approved-use enforcement: %s", body)
	}
}

func TestEvidenceExportIsValueFree(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.store.AppendAudit(AuditEntry{
		Action:    "permit.run.ui",
		Outcome:   "not_executed",
		Method:    http.MethodPost,
		Path:      "/ui/permits/p_secret/run/backend_path=/tmp/source_path=/src",
		SecretRef: "zitadel-janus-oidc",
		Reason:    "no execution connector configured in V1.1 request_body=raw-secret env=SECRET connector_output=secret",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/evidence", nil)
	out := httptest.NewRecorder()
	app.withAuth(app.handleEvidence)(out, req)
	if out.Code != http.StatusOK {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if got := out.Header().Get("Content-Disposition"); !strings.Contains(got, "janus-evidence.json") {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	headerHash := out.Header().Get("X-Janus-Evidence-Hash")
	if len(headerHash) != 64 || out.Header().Get("X-Janus-Evidence-Algorithm") != "sha256-json-v1" || out.Header().Get("X-Janus-Evidence-Body-Field") != "integrity.pack_hash" || out.Header().Get("X-Janus-Value-Returned") != "false" {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	body := out.Body.String()
	if !strings.Contains(body, `"value_returned":false`) || strings.Contains(body, `"plaintext"`) {
		t.Fatal(minimizationDiagnostic("forbidden_literal"))
	}
	var pack EvidencePack
	if err := json.Unmarshal(out.Body.Bytes(), &pack); err != nil {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if pack.Integrity == nil || pack.Integrity.PackHash != headerHash {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if pack.Receipt == nil || pack.Receipt.PackHash != headerHash || pack.Receipt.HashHeader != "X-Janus-Evidence-Hash" || pack.Receipt.BodyField != "integrity.pack_hash" || pack.Receipt.ValueReturned {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if pack.AuditTrail.ValueReturned || !pack.AuditTrail.ChronologicalHistory || !pack.AuditTrail.ReceiptHashLinkage || pack.AuditTrail.RawPathReturned || pack.AuditTrail.RawReasonReturned || pack.AuditTrail.RequestBodyReturned || pack.AuditTrail.EnvReturned || pack.AuditTrail.BackendPathReturned || pack.AuditTrail.SourcePathReturned || pack.AuditTrail.ConnectorOutputReturned || pack.AuditTrail.PermitPayloadValueReturned || pack.AuditTrail.SecretValueReturned {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if len(pack.RecentAudit) == 0 || pack.RecentAudit[0].Channel != "POST browser action" || pack.RecentAudit[0].ReasonClass != "no_connector" || pack.RecentAudit[0].Scope != "zitadel-janus-oidc" {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	for _, want := range []string{`"audit_trail"`, `"recent_audit"`, `"channel":"POST browser action"`, `"reason_class":"no_connector"`, `"chronological_history":true`, `"receipt_hash_linkage":true`, `"raw_path_returned":false`, `"raw_reason_returned":false`, `"request_body_returned":false`, `"env_returned":false`, `"backend_path_returned":false`, `"source_path_returned":false`, `"connector_output_returned":false`, `"permit_payload_value_returned":false`, `"secret_value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatal(minimizationDiagnostic("evidence_shape"))
		}
	}
	for _, forbidden := range []string{"/ui/permits", "request_body=raw-secret", "env=SECRET", "connector_output=secret", "backend_path=/tmp", "source_path=/src"} {
		if strings.Contains(body, forbidden) {
			t.Fatal(minimizationDiagnostic("forbidden_literal"))
		}
	}
	if !strings.Contains(body, `"redaction_model"`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if !strings.Contains(body, `"evidence_boundary"`) || !strings.Contains(body, `"gate":"export_ready"`) || !strings.Contains(body, `"secret_values"`) || !strings.Contains(body, `"backend_source_paths"`) || !strings.Contains(body, `"hash_available":true`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if !strings.Contains(body, `"evidence_receipt"`) || !strings.Contains(body, `"hash_header":"X-Janus-Evidence-Hash"`) || !strings.Contains(body, `"body_field":"integrity.pack_hash"`) || !strings.Contains(body, `"coverage":"evidence_json_without_integrity_or_receipt"`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if !strings.Contains(body, `"assurance_summary"`) || !strings.Contains(body, `"proven"`) || !strings.Contains(body, `"review"`) || !strings.Contains(body, `"Browser and API boundary"`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if !strings.Contains(body, `"operational_status"`) || !strings.Contains(body, `"key":"evidence_export"`) || !strings.Contains(body, `"key":"scope_boundary"`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if !strings.Contains(body, `"action_readiness"`) || !strings.Contains(body, `"key":"posture_view"`) || !strings.Contains(body, `"key":"policy_posture"`) || !strings.Contains(body, `"value_returned":false`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if !strings.Contains(body, `"authenticated_role_evidence"`) || !strings.Contains(body, `"label":"Signed-in role receipt"`) || !strings.Contains(body, `"evidence_signal":"signed_in_role_receipt_no_identity_values"`) || !strings.Contains(body, `"identity_values_returned":false`) || !strings.Contains(body, `"subject_returned":false`) || !strings.Contains(body, `"email_returned":false`) || !strings.Contains(body, `"name_returned":false`) || !strings.Contains(body, `"claim_values_returned":false`) || !strings.Contains(body, `"token_returned":false`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if pack.AuthenticatedBrowser.ValueReturned || pack.AuthenticatedBrowser.IdentityValuesReturned || pack.AuthenticatedBrowser.TokenReturned || pack.AuthenticatedBrowser.CookieValueReturned || pack.AuthenticatedBrowser.SecretValueReturned {
		t.Fatal(minimizationDiagnostic("forbidden_literal"))
	}
	if !strings.Contains(body, `"authenticated_browser_witness"`) || !strings.Contains(body, `"label":"Authenticated browser witness"`) || !strings.Contains(body, `"evidence_signal":"signed_session_browser_proof_no_identity_values"`) || !strings.Contains(body, `"session_cookie_policy":"host_prefixed_strict_signed"`) || !strings.Contains(body, `"csrf_boundary":"bound_to_signed_session"`) || !strings.Contains(body, `"csp_boundary":"script_src_none"`) || !strings.Contains(body, `"connector_output_returned":false`) || !strings.Contains(body, `"permit_payload_returned":false`) || !strings.Contains(body, `"secret_value_returned":false`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if !strings.Contains(body, `"assurance_gates"`) || !strings.Contains(body, `"key":"value_leak_sentinel"`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if !strings.Contains(body, `"negative_path_assurance"`) || !strings.Contains(body, `"key":"role_denial"`) || !strings.Contains(body, `"key":"audit_sink_degraded"`) || !strings.Contains(body, `"key":"request_correlation"`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if !strings.Contains(body, `"degraded_guidance"`) || !strings.Contains(body, `"key":"readiness"`) || !strings.Contains(body, `"key":"audit_sink"`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if !strings.Contains(body, `"privacy_posture"`) || !strings.Contains(body, `"key":"raw_metadata"`) || !strings.Contains(body, `"cookie_secrets"`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if !strings.Contains(body, `"scope_posture"`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if !strings.Contains(body, `"lifecycle_posture"`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if !strings.Contains(body, `"permit_posture"`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
	if !strings.Contains(body, `"integrity"`) || !strings.Contains(body, `"pack_hash"`) {
		t.Fatal(minimizationDiagnostic("evidence_shape"))
	}
}

func TestEvidenceExportRequiresAuditorRole(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RolePolicy = RolePolicy{
		AuditorSubjects: map[string]bool{"auditor": true},
		BootstrapOwner:  false,
	}
	session := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodGet, "/api/evidence", nil)
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.withAuth(app.requireRole(RoleAuditor, "evidence.export", app.handleEvidence))(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", out.Code, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), `"value_returned":false`) {
		t.Fatalf("denial must be value-free: %s", out.Body.String())
	}
	recent := app.store.RecentAudit(1)
	if len(recent) != 1 || recent[0].Outcome != "denied" || !strings.Contains(recent[0].Reason, "auditor") {
		t.Fatalf("expected denied role audit event: %#v", recent)
	}
}

func TestWardenAPIRequiresOperatorRole(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"zitadel-janus-oidc","reason":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.withAuth(app.requireRole(RoleOperator, "warden.resolve", app.handleResolveHandle))(out, req)

	if out.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", out.Code, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), `"role_denied"`) || !strings.Contains(out.Body.String(), `"value_returned":false`) {
		t.Fatalf("operator denial should be value-free: %s", out.Body.String())
	}
	recent := app.store.RecentAudit(1)
	if len(recent) != 1 || recent[0].Outcome != "denied" || !strings.Contains(recent[0].Reason, "operator") {
		t.Fatalf("expected denied operator audit event: %#v", recent)
	}
}

func TestAssuranceGateProofDirectAbuseCases(t *testing.T) {
	t.Run("viewer role denial is value-free and audited", func(t *testing.T) {
		app := newTestApp(t)
		session := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
		rr := httptest.NewRecorder()
		app.writeSession(rr, session)

		req := httptest.NewRequest(http.MethodGet, "/api/evidence", nil)
		req.AddCookie(rr.Result().Cookies()[0])
		out := httptest.NewRecorder()
		app.withAuth(app.requireRole(RoleAuditor, "evidence.export", app.handleEvidence))(out, req)
		if out.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d body=%s", out.Code, out.Body.String())
		}
		assertRouteResponseValueFree(t, "viewer role denial", out)
		recent := app.store.RecentAudit(1)
		if len(recent) != 1 || recent[0].Outcome != "denied" || !strings.Contains(recent[0].Reason, "auditor") {
			t.Fatalf("expected denied auditor audit event: %#v", recent)
		}
	})

	t.Run("malformed catalog metadata opens gates", func(t *testing.T) {
		gates := ValidateCatalog([]SecretDescriptor{{}})
		for _, code := range []string{"missing_id", "missing_owner", "weak_classification", "missing_scope", "missing_source", "missing_consumers", "no_approved_use_profile"} {
			if !catalogGateHasCode(gates, code) {
				t.Fatalf("expected catalog gate %q in %#v", code, gates)
			}
		}
		proof := AssuranceGatesFor(true, len(gates), AccessPosture{RoleDutyMatrix: true, RequiredRoles: map[string]string{"/api/evidence": RoleAuditor}})
		if proof.ValueReturned || proof.ReviewCount == 0 || !assuranceGateHasKey(proof.Gates, "catalog_metadata") {
			t.Fatalf("assurance gate proof should expose catalog review without values: %#v", proof)
		}
	})

	t.Run("degraded sensitive action is blocked value-free", func(t *testing.T) {
		app := newTestApp(t)
		app.cfg.RequireAuth = false
		app.permits = nil

		req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"zitadel-janus-oidc","reason":"local smoke"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-Id", "assurance-degraded-1")
		out := httptest.NewRecorder()
		app.routes().ServeHTTP(out, req)
		if out.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d body=%s", out.Code, out.Body.String())
		}
		assertRouteResponseValueFree(t, "degraded sensitive action", out)
		if !strings.Contains(out.Body.String(), `"system_degraded"`) || !strings.Contains(out.Body.String(), `"request_id":"assurance-degraded-1"`) {
			t.Fatalf("degraded denial should be clear and correlated: %s", out.Body.String())
		}
	})
}

func TestNegativePathAssuranceMatrix(t *testing.T) {
	proof := NegativePathAssuranceFor(true, 0, AccessPosture{
		RoleDutyMatrix: true,
		RequiredRoles: map[string]string{
			"/api/evidence":            RoleAuditor,
			"POST /api/warden/resolve": RoleOperator,
		},
	}, AuditPosture{SinkWritable: true, ChainVerified: true})
	if proof.ValueReturned || proof.ReviewCount != 0 || proof.CoveredCount < 5 {
		t.Fatalf("negative-path assurance should be covered and value-free: %#v", proof)
	}
	for _, key := range []string{"role_denial", "catalog_gate", "audit_sink_degraded", "sensitive_action_guard", "value_leak_sentinel", "request_correlation"} {
		if !negativePathHasKey(proof.Cases, key) {
			t.Fatalf("negative-path assurance should cover %q: %#v", key, proof)
		}
	}

	degraded := NegativePathAssuranceFor(false, 2, AccessPosture{}, AuditPosture{})
	if degraded.ReviewCount == 0 || !negativePathHasState(degraded.Cases, "audit_sink_degraded", "blocking") || !negativePathHasState(degraded.Cases, "sensitive_action_guard", "blocking") {
		t.Fatalf("degraded negative-path assurance should show blocking states: %#v", degraded)
	}
}

func TestNegativePathAssuranceSharedByPostureAndEvidence(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	session := Session{Subject: "dev-local", Roles: AllRoles(), Expiry: time.Now().UTC().Add(time.Hour)}

	posture := app.postureBody(session)
	postureProof, ok := posture["negative_path_assurance"].(NegativePathAssurance)
	if !ok {
		t.Fatalf("posture should expose typed negative-path assurance")
	}
	postureGuidance, ok := posture["degraded_guidance"].(DegradedGuidance)
	if !ok {
		t.Fatalf("posture should expose typed degraded-state guidance")
	}
	postureActionReadiness, ok := posture["action_readiness"].(ActionReadiness)
	if !ok {
		t.Fatalf("posture should expose typed action readiness")
	}
	postureAuditDrill, ok := posture["audit_failure_drill"].(AuditFailureDrill)
	if !ok {
		t.Fatalf("posture should expose typed audit failure drill")
	}
	postureAuthFailure, ok := posture["auth_failure_posture"].(AuthFailurePosture)
	if !ok {
		t.Fatalf("posture should expose typed auth failure posture")
	}
	postureAuthenticatedRole, ok := posture["authenticated_role_evidence"].(SessionRoleEvidence)
	if !ok {
		t.Fatalf("posture should expose typed authenticated role evidence")
	}
	postureAuthenticatedBrowser, ok := posture["authenticated_browser_witness"].(AuthenticatedBrowserWitness)
	if !ok {
		t.Fatalf("posture should expose typed authenticated browser witness")
	}
	postureRolePolicyReadiness, ok := posture["role_policy_readiness"].(RolePolicyReadiness)
	if !ok {
		t.Fatalf("posture should expose typed role policy readiness")
	}
	postureAccess, ok := posture["access"].(AccessPosture)
	if !ok {
		t.Fatalf("posture should expose typed access posture")
	}
	pack := app.evidencePack(session)
	if !reflect.DeepEqual(postureProof, pack.NegativePath) {
		t.Fatalf("posture and evidence should share the same negative-path proof: posture=%#v evidence=%#v", postureProof, pack.NegativePath)
	}
	if !reflect.DeepEqual(postureGuidance, pack.Guidance) {
		t.Fatalf("posture and evidence should share the same degraded guidance: posture=%#v evidence=%#v", postureGuidance, pack.Guidance)
	}
	if !reflect.DeepEqual(postureActionReadiness, pack.ActionReadiness) {
		t.Fatalf("posture and evidence should share the same action readiness: posture=%#v evidence=%#v", postureActionReadiness, pack.ActionReadiness)
	}
	if !reflect.DeepEqual(postureAuditDrill, pack.AuditDrill) {
		t.Fatalf("posture and evidence should share the same audit failure drill: posture=%#v evidence=%#v", postureAuditDrill, pack.AuditDrill)
	}
	if !reflect.DeepEqual(postureAuthFailure, pack.AuthFailure) {
		t.Fatalf("posture and evidence should share the same auth failure posture: posture=%#v evidence=%#v", postureAuthFailure, pack.AuthFailure)
	}
	if !reflect.DeepEqual(postureAuthenticatedRole, pack.AuthenticatedRole) {
		t.Fatalf("posture and evidence should share the same authenticated role evidence: posture=%#v evidence=%#v", postureAuthenticatedRole, pack.AuthenticatedRole)
	}
	if !reflect.DeepEqual(postureAuthenticatedBrowser, pack.AuthenticatedBrowser) {
		t.Fatalf("posture and evidence should share the same authenticated browser witness: posture=%#v evidence=%#v", postureAuthenticatedBrowser, pack.AuthenticatedBrowser)
	}
	if !reflect.DeepEqual(postureRolePolicyReadiness, pack.RolePolicyReadiness) {
		t.Fatalf("posture and evidence should share the same role policy readiness: posture=%#v evidence=%#v", postureRolePolicyReadiness, pack.RolePolicyReadiness)
	}
	if !reflect.DeepEqual(postureAccess, pack.AccessPosture) {
		t.Fatalf("posture and evidence should share the same access posture: posture=%#v evidence=%#v", postureAccess, pack.AccessPosture)
	}
	if pack.NegativePath.ValueReturned || !negativePathHasKey(pack.NegativePath.Cases, "value_leak_sentinel") {
		t.Fatalf("negative-path evidence should stay value-free and include leak sentinel: %#v", pack.NegativePath)
	}
}

func TestAuditFailureDrillCoversHealthyAndDegradedStates(t *testing.T) {
	healthy := AuditFailureDrillFor(true, AuditPosture{SinkWritable: true, ChainVerified: true})
	if healthy.ValueReturned || healthy.Status != "armed" || healthy.BlockedCount != 0 {
		t.Fatalf("healthy audit drill should be armed and value-free: %#v", healthy)
	}
	for _, key := range []string{"sink_write", "chain_verify", "sensitive_actions", "public_readiness", "operator_recovery"} {
		if !auditDrillHasKey(healthy.Checks, key) {
			t.Fatalf("healthy audit drill should include %q: %#v", key, healthy)
		}
	}
	if !auditDrillHasState(healthy.Checks, "public_readiness", "redacted") || !auditDrillHasState(healthy.Checks, "operator_recovery", "documented") {
		t.Fatalf("healthy audit drill should prove redaction and recovery docs: %#v", healthy)
	}

	degraded := AuditFailureDrillFor(false, AuditPosture{ChainVerified: false})
	if degraded.Status != "blocking" || degraded.BlockedCount < 2 || degraded.ValueReturned {
		t.Fatalf("degraded audit drill should block and stay value-free: %#v", degraded)
	}
	if !auditDrillHasState(degraded.Checks, "sink_write", "blocked") || !auditDrillHasState(degraded.Checks, "chain_verify", "blocked") || !auditDrillHasState(degraded.Checks, "sensitive_actions", "blocking") {
		t.Fatalf("degraded audit drill should name blocking controls: %#v", degraded)
	}
	if !auditDrillHasNext(degraded.Checks, "operator_recovery", "Fix audit storage first") {
		t.Fatalf("degraded audit drill should include operator recovery: %#v", degraded)
	}
}

func TestDegradedGuidanceCoversReadyBlockedAndRoleGatedStates(t *testing.T) {
	audit := AuditPosture{SinkWritable: true, ChainVerified: true}
	ready := DegradedGuidanceFor(true, audit, EvidenceBoundaryFor(true, true))
	if ready.ValueReturned || ready.BlockedCount != 0 || ready.ReviewCount != 0 {
		t.Fatalf("ready self-hosted guidance should be clear and value-free: %#v", ready)
	}
	if !degradedGuidanceHasState(ready.Items, "readiness", "ready") || !degradedGuidanceHasState(ready.Items, "audit_sink", "ready") {
		t.Fatalf("ready guidance should name clear states: %#v", ready)
	}

	auditDown := DegradedGuidanceFor(false, AuditPosture{ChainVerified: true}, EvidenceBoundaryFor(true, true))
	if auditDown.BlockedCount == 0 || !degradedGuidanceHasState(auditDown.Items, "audit_sink", "blocked") || !degradedGuidanceHasAction(auditDown.Items, "audit_sink", "Recover audit storage") {
		t.Fatalf("audit-down guidance should explain recovery: %#v", auditDown)
	}

	viewer := DegradedGuidanceFor(true, audit, EvidenceBoundaryFor(false, false))
	if viewer.ReviewCount == 0 || !degradedGuidanceHasState(viewer.Items, "evidence_export", "role gated") || !degradedGuidanceHasAction(viewer.Items, "evidence_export", "Use an auditor session") {
		t.Fatalf("viewer guidance should explain evidence role gate: %#v", viewer)
	}
}

func TestPostureGuidanceIsSessionAwareForEvidenceGate(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{`"degraded_guidance"`, `"key":"evidence_export"`, `"state":"role gated"`, `"evidence_receipt"`, `"state":"role_gated"`, `"hash_header":"X-Janus-Evidence-Hash"`, `"body_field":"integrity.pack_hash"`, "Use an auditor session", `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("viewer posture guidance should include %s: %s", want, body)
		}
	}
	assertRouteResponseValueFree(t, "viewer posture guidance", out)
}

func TestAuditSinkDegradedBlocksSensitiveActions(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.store.auditFile = filepath.Join(t.TempDir(), "missing-parent", "audit.jsonl")

	readiness, ready := app.readinessBody()
	if ready {
		t.Fatalf("audit sink degradation should fail readiness: %#v", readiness)
	}
	checks, ok := readiness["checks"].(map[string]bool)
	if !ok || checks["audit_sink"] {
		t.Fatalf("readiness should show audit sink degraded: %#v", readiness)
	}
	posture := app.postureBody(Session{Subject: "operator", Roles: AllRoles(), Expiry: time.Now().UTC().Add(time.Hour)})
	drill, ok := posture["audit_failure_drill"].(AuditFailureDrill)
	if !ok || drill.Status != "blocking" || !auditDrillHasState(drill.Checks, "sink_write", "blocked") || drill.ValueReturned {
		t.Fatalf("posture should expose blocking audit failure drill: %#v", posture["audit_failure_drill"])
	}

	req := httptest.NewRequest(http.MethodPost, "/api/warden/resolve", strings.NewReader(`{"ref":"raw-secret-value","reason":"plaintext body should not echo"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "audit-down-1")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", out.Code, out.Body.String())
	}
	assertRouteResponseValueFree(t, "audit sink degraded", out)
	assertJSONErrorRequestCorrelated(t, "audit sink degraded", "audit-down-1", out)
	if !strings.Contains(out.Body.String(), `"audit_sink":false`) || !strings.Contains(out.Body.String(), `"system_degraded"`) {
		t.Fatalf("audit degradation denial should be explicit and safe: %s", out.Body.String())
	}
}

func TestSensitiveAPIsFailClosedWhenReadinessDegraded(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
	}{
		{name: "evidence export", method: http.MethodGet, path: "/api/evidence"},
		{name: "resolve handle", method: http.MethodPost, path: "/api/warden/resolve", body: `{"ref":"raw-secret-value","reason":"plaintext body should not echo"}`, contentType: "application/json"},
		{name: "create permit", method: http.MethodPost, path: "/api/permits", body: `{"ref":"raw-secret-value","action":"metadata_use","destination":"secrets/backend","reason":"plaintext body should not echo"}`, contentType: "application/json"},
		{name: "run permit", method: http.MethodPost, path: "/api/permits/raw-secret-value/run"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := newTestApp(t)
			app.cfg.RequireAuth = false
			app.permits = nil

			reqID := "degraded-" + strings.NewReplacer(" ", "-", "/", "-").Replace(tc.name)
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("X-Request-Id", reqID)
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			out := httptest.NewRecorder()
			app.routes().ServeHTTP(out, req)
			if out.Code != http.StatusServiceUnavailable {
				t.Fatalf("expected 503, got %d body=%s", out.Code, out.Body.String())
			}
			assertRouteResponseValueFree(t, tc.name, out)
			assertJSONErrorRequestCorrelated(t, tc.name, reqID, out)
			for _, want := range []string{`"error":"system_degraded"`, `"redacted":true`, `"value_returned":false`} {
				if !strings.Contains(out.Body.String(), want) {
					t.Fatalf("%s degraded denial should include %s: %s", tc.name, want, out.Body.String())
				}
			}
		})
	}
}

func TestRolePolicyMapsZitadelClaims(t *testing.T) {
	roles := DeriveRoles("user-1", "user@example.test", []string{"janus:auditor"}, RolePolicy{
		AuditorGroups:  map[string]bool{"janus:auditor": true},
		BootstrapOwner: false,
	})
	if !hasTestRole(roles, RoleViewer) || !hasTestRole(roles, RoleAuditor) {
		t.Fatalf("expected viewer and auditor roles, got %#v", roles)
	}
	if hasTestRole(roles, RoleSecurityAdmin) {
		t.Fatalf("auditor claim should not grant security admin: %#v", roles)
	}
}

func TestRolePolicyRejectsUnconfiguredElevatedClaims(t *testing.T) {
	for _, claim := range []string{"janus:admin", "janus_admin", "janus-admin", "janus:auditor", "janus:operator"} {
		roles := DeriveRoles("user-1", "user@example.test", []string{claim}, RolePolicy{BootstrapOwner: false})
		if !hasTestRole(roles, RoleViewer) || hasTestRole(roles, RoleSecurityAdmin) || hasTestRole(roles, RoleAuditor) || hasTestRole(roles, RoleOperator) {
			t.Fatalf("unconfigured claim %q should only grant viewer, got %#v", claim, roles)
		}
	}
	posture := AccessPostureFor(RolePolicy{BootstrapOwner: false})
	if posture.ClaimPolicy != "explicit_only" || posture.ImplicitElevatedClaims || !accessSourceHasState(posture.BindingSources, "implicit_elevated_claims", "disabled") || posture.ValueReturned {
		t.Fatalf("access posture should prove strict claim policy without values: %#v", posture)
	}
}

func TestRolePolicyLegacyBootstrapOwnerGrantsNoElevatedRoles(t *testing.T) {
	roles := DeriveRoles("owner", "", nil, RolePolicy{BootstrapOwner: true})
	if len(roles) != 1 || roles[0] != RoleViewer {
		t.Fatalf("legacy bootstrap must be inert, got %#v", roles)
	}
}

func TestRolePolicyExplicitOwnerBindingClosesBootstrapGate(t *testing.T) {
	policy := RolePolicy{
		SecurityAdminSubjects: map[string]bool{"security-subject": true},
		OwnerSubjects:         map[string]bool{"owner-subject": true},
		ApproverSubjects:      map[string]bool{"approver-subject": true},
		AuditorSubjects:       map[string]bool{"auditor-subject": true},
		OperatorSubjects:      map[string]bool{"operator-subject": true},
		BreakGlassAdminGroups: map[string]bool{"break-glass-group": true},
		ServiceAdminGroups:    map[string]bool{"service-group": true},
		WorkloadAdminGroups:   map[string]bool{"workload-group": true},
	}
	roles := DeriveRoles("security-subject", "", nil, policy)
	for _, role := range []string{RoleViewer, RoleSecurityAdmin} {
		if !hasTestRole(roles, role) {
			t.Fatalf("expected exact role %s in %#v", role, roles)
		}
	}
	posture := AccessPostureFor(policy)
	if !posture.ExplicitBindings || posture.BootstrapOwner || posture.GateCount != 0 || posture.ValueReturned {
		t.Fatalf("explicit role policy should close bootstrap gate: %#v", posture)
	}
	if posture.SubjectBindingCount != 5 || posture.GroupBindingCount != 3 || posture.ElevatedBindingCount != 8 || posture.ClaimPolicy != "explicit_only" || posture.ImplicitElevatedClaims {
		t.Fatalf("explicit role policy should expose value-free binding counts: %#v", posture)
	}
	if !accessSourceHasState(posture.BindingSources, "subject_bindings", "configured") || !accessSourceHasState(posture.BindingSources, "implicit_elevated_claims", "disabled") || !accessSourceHasState(posture.BindingSources, "bootstrap_owner", "off") {
		t.Fatalf("explicit role policy should expose source states: %#v", posture)
	}
}

func TestRolePolicyReadinessDistinguishesBootstrapAndExplicitLanes(t *testing.T) {
	bootstrap := RolePolicyReadinessFor(RolePolicy{BootstrapOwner: true}, AccessPostureFor(RolePolicy{BootstrapOwner: true}))
	if bootstrap.Ready || bootstrap.Status != "blocked" || bootstrap.BootstrapOwnerState != "blocked_legacy" || !bootstrap.BootstrapOwnerBlocked || bootstrap.ReadyLanes != 0 || bootstrap.MissingLanes != 8 || bootstrap.TotalLanes != 8 || bootstrap.ValueReturned {
		t.Fatalf("bootstrap policy should be visibly blocked without values: %#v", bootstrap)
	}
	for _, role := range AllRoles()[1:] {
		if !rolePolicyReadinessHasLane(bootstrap.Lanes, role, "missing") {
			t.Fatalf("bootstrap policy should show %s lane missing: %#v", role, bootstrap.Lanes)
		}
	}

	partialPolicy := RolePolicy{
		SecurityAdminSubjects: map[string]bool{"security-subject": true},
		AuditorGroups:         map[string]bool{"auditor-group": true},
		BootstrapOwner:        true,
	}
	partial := RolePolicyReadinessFor(partialPolicy, AccessPostureFor(partialPolicy))
	if partial.Ready || partial.Status != "blocked" || partial.BootstrapOwnerState != "blocked_legacy" || !partial.BootstrapOwnerBlocked || partial.ReadyLanes != 2 || partial.MissingLanes != 6 {
		t.Fatalf("partial explicit policy should show missing lanes and blocked bootstrap: %#v", partial)
	}
	if !rolePolicyReadinessHasLane(partial.Lanes, RoleSecurityAdmin, "ready") || !rolePolicyReadinessHasLane(partial.Lanes, RoleAuditor, "ready") || !rolePolicyReadinessHasLane(partial.Lanes, RoleOperator, "missing") {
		t.Fatalf("partial policy should distinguish ready and missing lanes: %#v", partial.Lanes)
	}

	explicitPolicy := RolePolicy{
		OperatorSubjects:        map[string]bool{"operator-subject": true},
		OwnerSubjects:           map[string]bool{"owner-subject": true},
		ApproverSubjects:        map[string]bool{"approver-subject": true},
		AuditorGroups:           map[string]bool{"auditor-group": true},
		SecurityAdminSubjects:   map[string]bool{"security-subject": true},
		BreakGlassAdminSubjects: map[string]bool{"break-glass-subject": true},
		ServiceAdminGroups:      map[string]bool{"service-group": true},
		WorkloadAdminGroups:     map[string]bool{"workload-group": true},
	}
	explicit := RolePolicyReadinessFor(explicitPolicy, AccessPostureFor(explicitPolicy))
	if !explicit.Ready || explicit.Status != "ready" || explicit.BootstrapOwnerState != "off" || explicit.ReadyLanes != 8 || explicit.MissingLanes != 0 || explicit.TotalLanes != 8 || explicit.SubjectValuesReturned || explicit.GroupValuesReturned || explicit.ClaimValuesReturned || explicit.TokenReturned || explicit.EnvValuesReturned || explicit.BackendPathReturned || explicit.ValueReturned {
		t.Fatalf("explicit policy should be ready and value-free: %#v", explicit)
	}
	for _, role := range AllRoles()[1:] {
		if !rolePolicyReadinessHasLane(explicit.Lanes, role, "ready") {
			t.Fatalf("explicit policy should show %s lane ready: %#v", role, explicit.Lanes)
		}
	}
}

func TestBuildProvenanceReceiptDistinguishesBoundAndUnknownBuilds(t *testing.T) {
	bound := buildProvenanceFor("golang:1.26.3-alpine", "barta.cm/janus", "go1.26.3", "c3384ed9abc123456", "2026-05-31T15:42:00Z")
	if bound.Status != "bound" || !bound.CommitBound || !bound.BuildTimeBound || bound.CommitShort != "c3384ed9abc1" {
		t.Fatalf("bound build receipt should expose copy-safe build identity: %#v", bound)
	}
	if bound.Builder != "golang:1.26.3-alpine" || bound.ModulePath != "barta.cm/janus" || bound.GoVersion != "go1.26.3" || bound.EvidenceSignal != "copy_safe_build_provenance_receipt" {
		t.Fatalf("bound build receipt should include builder/module/runtime evidence: %#v", bound)
	}
	if bound.ArtifactReturned || bound.SBOMReturned || bound.ScannerOutputReturned || bound.EnvReturned || bound.BackendPathReturned || bound.SecretValueReturned || bound.ValueReturned {
		t.Fatalf("bound build receipt should remain value-free: %#v", bound)
	}
	if !supplyChainItemHasState(bound.Checks, "commit_binding", "bound") || !supplyChainItemHasState(bound.Checks, "build_time_binding", "bound") || !supplyChainItemHasState(bound.Checks, "artifact_boundary", "withheld") {
		t.Fatalf("bound build receipt should include expected checks: %#v", bound.Checks)
	}

	unknown := buildProvenanceFor("", "", "", "", "")
	if unknown.Status != "incomplete" || unknown.CommitBound || unknown.BuildTimeBound || unknown.Commit != "unknown" || unknown.BuildTime != "unknown" || unknown.CommitShort != "unknown" {
		t.Fatalf("unknown build receipt should be honest about missing bindings: %#v", unknown)
	}
	if unknown.ArtifactReturned || unknown.SBOMReturned || unknown.ScannerOutputReturned || unknown.EnvReturned || unknown.BackendPathReturned || unknown.SecretValueReturned || unknown.ValueReturned {
		t.Fatalf("unknown build receipt should remain value-free: %#v", unknown)
	}
	if !supplyChainItemHasState(unknown.Checks, "commit_binding", "unknown") || !supplyChainItemHasState(unknown.Checks, "build_time_binding", "unknown") {
		t.Fatalf("unknown build receipt should show missing binding checks: %#v", unknown.Checks)
	}
}

func TestProductModePostureDistinguishesClaims(t *testing.T) {
	policy := RolePolicy{
		SecurityAdminSubjects: map[string]bool{"security-subject": true},
		AuditorSubjects:       map[string]bool{"auditor-subject": true},
		OperatorSubjects:      map[string]bool{"operator-subject": true},
	}
	access := AccessPostureFor(policy)
	audit := AuditPosture{ChainVerified: true, SinkWritable: true}

	selfHosted := ProductModePostureFor(Config{ProductMode: "self_hosted", RolePolicy: policy}, true, nil, access, audit, 0)
	if selfHosted.Current != "Self-hosted" || selfHosted.Baseline != "ready" || selfHosted.Enterprise != "not_claimed" || selfHosted.ValueReturned {
		t.Fatalf("self-hosted mode should be healthy without claiming enterprise: %#v", selfHosted)
	}

	dev := ProductModePostureFor(Config{ProductMode: "dev", RolePolicy: policy}, true, nil, access, audit, 0)
	if dev.Current != "Dev" || dev.Baseline != "dev_only" || dev.Enterprise != "not_claimed" {
		t.Fatalf("dev mode should stay clearly non-enterprise: %#v", dev)
	}

	enterpriseBlocked := ProductModePostureFor(Config{ProductMode: "enterprise", RolePolicy: policy}, true, []string{"remote audit missing"}, access, audit, 0)
	if enterpriseBlocked.Current != "Enterprise" || enterpriseBlocked.Enterprise != "blocked" {
		t.Fatalf("enterprise mode with gates should be blocked: %#v", enterpriseBlocked)
	}

	enterpriseCandidate := ProductModePostureFor(Config{ProductMode: "enterprise", RolePolicy: policy}, true, nil, access, audit, 0)
	if enterpriseCandidate.Enterprise != "candidate" || enterpriseCandidate.Baseline != "ready" {
		t.Fatalf("enterprise mode with clear gates should be a candidate: %#v", enterpriseCandidate)
	}
}

func TestPrivacyPostureKeepsEvidenceUsefulAndValueFree(t *testing.T) {
	posture := PrivacyPostureFor(EvidenceBoundaryFor(true, true), AuditPosture{ChainVerified: true, SinkWritable: true})
	if posture.Redaction != "metadata_only" || posture.ValueReturned {
		t.Fatalf("privacy posture should be metadata-only and value-free: %#v", posture)
	}
	for _, key := range []string{"audit_events", "evidence_export", "request_bodies", "prompt_command_env", "raw_metadata", "auth_cookie_secrets"} {
		if !privacySurfaceHasKey(posture.Surfaces, key) {
			t.Fatalf("privacy posture should cover %q: %#v", key, posture)
		}
	}
	for _, excluded := range []string{"secret_values", "request_bodies", "prompt_text", "command_output", "env_dumps", "backend_source_paths", "cookie_secrets"} {
		if !stringSliceHas(posture.Excluded, excluded) {
			t.Fatalf("privacy posture should exclude %q: %#v", excluded, posture)
		}
	}

	restricted := PrivacyPostureFor(EvidenceBoundaryFor(false, false), AuditPosture{})
	if restricted.ReviewCount == 0 || !privacySurfaceHasState(restricted.Surfaces, "evidence_export", "role gated") {
		t.Fatalf("restricted privacy posture should call out review items: %#v", restricted)
	}
}

func TestAssuranceSummaryDistinguishesProofAndReview(t *testing.T) {
	access := AccessPosture{ExplicitBindings: true}
	audit := AuditPosture{ChainVerified: true}
	boundary := EvidenceBoundaryFor(true, true)

	ready := AssuranceSummaryFor("self_hosted", true, 0, 0, access, audit, boundary)
	if ready.Verdict != "self_hosted_ready" || ready.ValueReturned || len(ready.Review) != 0 {
		t.Fatalf("expected ready self-hosted summary without review: %#v", ready)
	}
	for _, want := range []string{"Readiness", "Open gates", "Value boundary", "Browser and API boundary", "Role gates", "Audit evidence", "Evidence export", "Enterprise claim"} {
		if !assuranceHasLabel(ready.Proven, want) {
			t.Fatalf("ready summary should prove %q: %#v", want, ready)
		}
	}

	review := AssuranceSummaryFor("self_hosted", false, 1, 0, AccessPosture{}, AuditPosture{}, EvidenceBoundaryFor(false, false))
	if review.Verdict != "review_needed" || len(review.Review) == 0 {
		t.Fatalf("expected review summary: %#v", review)
	}
	for _, want := range []string{"Readiness", "Open gates", "Role gates", "Audit evidence", "Evidence export"} {
		if !assuranceHasLabel(review.Review, want) {
			t.Fatalf("review summary should call out %q: %#v", want, review)
		}
	}

	roleGated := AssuranceSummaryFor("self_hosted", true, 0, 0, access, audit, EvidenceBoundaryFor(false, false))
	if roleGated.Verdict != "review_needed" || !assuranceHasLabel(roleGated.Review, "Evidence export") {
		t.Fatalf("role-gated evidence export should stay in review: %#v", roleGated)
	}

	enterprise := AssuranceSummaryFor("enterprise", true, 0, 0, access, audit, boundary)
	if enterprise.Verdict != "enterprise_review_needed" || !assuranceHasLabel(enterprise.Review, "Enterprise claim") {
		t.Fatalf("enterprise mode should require review before stronger claims: %#v", enterprise)
	}
}

func assuranceHasLabel(items []AssuranceItem, label string) bool {
	for _, item := range items {
		if item.Label == label {
			return true
		}
	}
	return false
}

func assuranceGateHasKey(items []AssuranceGateItem, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}

func negativePathHasKey(items []NegativePathCase, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}

func negativePathHasState(items []NegativePathCase, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state {
			return true
		}
	}
	return false
}

func actionReadinessHasState(items []ActionReadinessItem, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state && !item.ValueReturned {
			return true
		}
	}
	return false
}

func degradedGuidanceHasState(items []DegradedGuidanceItem, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state {
			return true
		}
	}
	return false
}

func degradedGuidanceHasAction(items []DegradedGuidanceItem, key, action string) bool {
	for _, item := range items {
		if item.Key == key && strings.Contains(item.Action, action) {
			return true
		}
	}
	return false
}

func auditDrillHasKey(items []AuditFailureDrillItem, key string) bool {
	for _, item := range items {
		if item.Key == key && !item.ValueReturned {
			return true
		}
	}
	return false
}

func auditDrillHasState(items []AuditFailureDrillItem, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state && !item.ValueReturned {
			return true
		}
	}
	return false
}

func auditDrillHasNext(items []AuditFailureDrillItem, key, next string) bool {
	for _, item := range items {
		if item.Key == key && strings.Contains(item.Next, next) && !item.ValueReturned {
			return true
		}
	}
	return false
}

func catalogGateHasCode(items []CatalogGate, code string) bool {
	for _, item := range items {
		if item.Code == code {
			return true
		}
	}
	return false
}

func authFailurePostureHasReason(posture AuthFailurePosture, key string) bool {
	for _, reason := range posture.Reasons {
		if reason.Key == key && !reason.RawQueryReturned && !reason.ProviderDetailReturned && !reason.TokenReturned && !reason.ValueReturned {
			return true
		}
	}
	return false
}

func accessSourceHasState(items []RoleBindingSource, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state && !item.ValueReturned {
			return true
		}
	}
	return false
}

func rolePolicyReadinessHasLane(items []RolePolicyLane, role, state string) bool {
	for _, item := range items {
		if item.Role == role && item.State == state && !item.ValueReturned && !item.SubjectValuesReturned && !item.GroupValuesReturned && !item.ClaimValuesReturned {
			return true
		}
	}
	return false
}

func supplyChainItemHasState(items []SupplyChainPostureItem, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state && !item.ValueReturned {
			return true
		}
	}
	return false
}

func sessionRoleEvidenceHasRole(items []SessionRoleSignal, role, state string) bool {
	for _, item := range items {
		if item.Role == role && item.State == state && !item.ValueReturned {
			return true
		}
	}
	return false
}

func sessionRoleEvidenceHasGate(items []SessionRoleGateSignal, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state && !item.ValueReturned {
			return true
		}
	}
	return false
}

func authenticatedBrowserGateHasState(items []AuthenticatedBrowserGate, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state && !item.ValueReturned {
			return true
		}
	}
	return false
}

func privacySurfaceHasKey(items []PrivacySurface, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}

func privacySurfaceHasState(items []PrivacySurface, key, state string) bool {
	for _, item := range items {
		if item.Key == key && item.State == state {
			return true
		}
	}
	return false
}

func stringSliceHas(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestDockerComposePinsExplicitJanusRoleBindings(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docker-compose.yml"))
	if os.IsNotExist(err) {
		t.Skip("docker-compose.yml is the nixcfg deployment compose, not part of the standalone app repo")
	}
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		"JANUS_UNSAFE_BOOTSTRAP_OWNER=false",
		"JANUS_SECURITY_ADMIN_SUBJECTS=markus@barta.com",
		"JANUS_AUDITOR_SUBJECTS=markus@barta.com",
		"JANUS_OPERATOR_SUBJECTS=markus@barta.com",
		"JANUS_SECURITY_ADMIN_GROUPS=janus:security_admin",
		"JANUS_AUDITOR_GROUPS=janus:auditor",
		"JANUS_OPERATOR_GROUPS=janus:operator",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("compose should pin explicit Janus role binding %q", want)
		}
	}
}

func TestSecurityHeadersAcrossCoreRoutes(t *testing.T) {
	cases := []struct {
		name            string
		method          string
		path            string
		status          int
		setup           func(*App, *http.Request)
		expectBodyNonce bool
	}{
		{name: "health", method: http.MethodGet, path: "/healthz", status: http.StatusOK},
		{name: "ready", method: http.MethodGet, path: "/readyz", status: http.StatusOK},
		{name: "login", method: http.MethodGet, path: "/login", status: http.StatusFound, setup: func(app *App, _ *http.Request) {
			app.oauth = testOAuthConfig()
		}},
		{name: "auth reset", method: http.MethodGet, path: "/auth/reset", status: http.StatusOK, expectBodyNonce: true, setup: func(app *App, _ *http.Request) {
			app.oauth = testOAuthConfig()
		}},
		{name: "auth callback failure", method: http.MethodGet, path: "/oidc/callback?state=bad", status: http.StatusBadRequest, setup: func(app *App, req *http.Request) {
			app.oauth = testOAuthConfig()
			app.verifier = &oidc.IDTokenVerifier{}
			req.AddCookie(&http.Cookie{Name: hostStateCookie, Value: "state-cookie-secret"})
			req.AddCookie(&http.Cookie{Name: hostNonceCookie, Value: "nonce-cookie-secret"})
			req.AddCookie(&http.Cookie{Name: hostPKCECookie, Value: "pkce-cookie-secret"})
		}},
		{name: "browser safe error", method: http.MethodGet, path: "/missing", status: http.StatusNotFound},
		{name: "api safe error", method: http.MethodGet, path: "/api/missing", status: http.StatusNotFound},
		{name: "api auth error", method: http.MethodGet, path: "/api/posture", status: http.StatusUnauthorized},
		{name: "dashboard", method: http.MethodGet, path: "/", status: http.StatusOK, expectBodyNonce: true, setup: func(app *App, _ *http.Request) {
			app.cfg.RequireAuth = false
		}},
		{name: "auth smoke", method: http.MethodGet, path: "/auth/smoke", status: http.StatusOK, expectBodyNonce: true, setup: func(app *App, _ *http.Request) {
			app.cfg.RequireAuth = false
		}},
		{name: "session witness text", method: http.MethodGet, path: "/session-witness.txt", status: http.StatusOK, setup: func(app *App, _ *http.Request) {
			app.cfg.RequireAuth = false
		}},
		{name: "session witness page", method: http.MethodGet, path: "/session-witness", status: http.StatusOK, expectBodyNonce: true, setup: func(app *App, _ *http.Request) {
			app.cfg.RequireAuth = false
		}},
		{name: "session witness verifier", method: http.MethodGet, path: "/session-witness/verify", status: http.StatusOK, expectBodyNonce: true, setup: func(app *App, _ *http.Request) {
			app.cfg.RequireAuth = false
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := newTestApp(t)
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Origin", "https://evil.example")
			req.Header.Set("X-Request-Id", "security-headers-"+strings.ReplaceAll(tc.name, " ", "-"))
			if tc.setup != nil {
				tc.setup(app, req)
			}
			out := httptest.NewRecorder()
			app.routes().ServeHTTP(out, req)
			if out.Code != tc.status {
				t.Fatalf("expected %d, got %d body=%s", tc.status, out.Code, out.Body.String())
			}
			assertCoreSecurityHeaders(t, tc.name, out)
			if tc.expectBodyNonce {
				assertStyleNonceMatchesCSP(t, out)
			}
		})
	}
}

func assertCoreSecurityHeaders(t *testing.T, name string, out *httptest.ResponseRecorder) {
	t.Helper()
	headers := out.Header()
	for header, want := range map[string]string{
		"Cache-Control":                     "no-store",
		"Cross-Origin-Embedder-Policy":      "credentialless",
		"Cross-Origin-Opener-Policy":        "same-origin",
		"Cross-Origin-Resource-Policy":      "same-origin",
		"Expires":                           "0",
		"Origin-Agent-Cluster":              "?1",
		"Permissions-Policy":                "camera=(), geolocation=(), microphone=()",
		"Pragma":                            "no-cache",
		"Referrer-Policy":                   "no-referrer",
		"Strict-Transport-Security":         "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":            "nosniff",
		"X-DNS-Prefetch-Control":            "off",
		"X-Frame-Options":                   "DENY",
		"X-Permitted-Cross-Domain-Policies": "none",
	} {
		if got := headers.Get(header); got != want {
			t.Fatalf("%s: expected %s %q, got %q", name, header, want, got)
		}
	}
	csp := headers.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "script-src 'none'", "object-src 'none'", "worker-src 'none'", "base-uri 'self'", "frame-ancestors 'none'", "form-action 'self'", "connect-src 'self'", "font-src 'self'", "img-src 'self' data:", "manifest-src 'self'", "style-src 'self' 'nonce-", "upgrade-insecure-requests"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("%s: CSP should include %q: %s", name, want, csp)
		}
	}
	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval"} {
		if strings.Contains(csp, forbidden) {
			t.Fatalf("%s: CSP should not include %q: %s", name, forbidden, csp)
		}
	}
	for _, header := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Headers", "Access-Control-Allow-Methods"} {
		if got := headers.Get(header); got != "" {
			t.Fatalf("%s: expected no %s header, got %q", name, header, got)
		}
	}
}

func assertStyleNonceMatchesCSP(t *testing.T, out *httptest.ResponseRecorder) {
	t.Helper()
	csp := out.Header().Get("Content-Security-Policy")
	parts := strings.SplitN(out.Body.String(), `<style nonce="`, 2)
	if len(parts) != 2 {
		t.Fatalf("dashboard style tag should include nonce: %s", out.Body.String())
	}
	nonce := strings.SplitN(parts[1], `"`, 2)[0]
	if nonce == "" || !strings.Contains(csp, "'nonce-"+nonce+"'") {
		t.Fatalf("CSP nonce should match style nonce: csp=%s nonce=%q", csp, nonce)
	}
}

func TestSafeBrowserBoundaryFailurePage(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	req.Header.Set("X-Request-Id", "edge-browser-404")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("browser boundary failure should be HTML, got %q", got)
	}
	body := out.Body.String()
	for _, want := range []string{"Janus stopped at the edge", "Safe boundary", "route_not_found", "value_returned=false", "request_id=edge-browser-404"} {
		if !strings.Contains(body, want) {
			t.Fatalf("safe boundary page should render %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"plaintext", "secret-cookie-secret", "nonce-cookie-secret", "pkce-cookie-secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("safe boundary page leaked %q: %s", forbidden, body)
		}
	}
	if got := out.Header().Get("Content-Security-Policy"); !strings.Contains(got, "script-src 'none'") {
		t.Fatalf("safe boundary page should keep no-script CSP, got %q", got)
	}
}

func TestSafeAPIBoundaryFailureJSON(t *testing.T) {
	app := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/api/missing", nil)
	req.Header.Set("X-Request-Id", "edge-api-404")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{`"error":"route_not_found"`, `"request_id":"edge-api-404"`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("API boundary failure should include %s: %s", want, body)
		}
	}
	if strings.Contains(body, "<!doctype") || strings.Contains(body, "plaintext") {
		t.Fatalf("API boundary failure should stay JSON and value-free: %s", body)
	}
}

func TestSafeMethodBoundaryFailureJSON(t *testing.T) {
	app := newTestApp(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/posture", nil)
	req.Header.Set("X-Request-Id", "edge-api-405")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("expected Allow GET, HEAD, got %q", got)
	}
	body := out.Body.String()
	for _, want := range []string{`"error":"method_not_allowed"`, `"allowed_methods":["GET","HEAD"]`, `"request_id":"edge-api-405"`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("method boundary failure should include %s: %s", want, body)
		}
	}
	if strings.Contains(body, "Method Not Allowed") || strings.Contains(body, "plaintext") {
		t.Fatalf("method boundary failure should not use default plain response: %s", body)
	}
}

func TestCORSDeniedByDefault(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	cases := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/readyz", http.StatusOK},
		{http.MethodGet, "/buildz", http.StatusOK},
		{http.MethodGet, "/api/posture", http.StatusOK},
		{http.MethodGet, "/missing", http.StatusNotFound},
		{http.MethodOptions, "/api/posture", http.StatusMethodNotAllowed},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Origin", "https://evil.example")
		req.Header.Set("Access-Control-Request-Method", "GET")
		out := httptest.NewRecorder()
		app.routes().ServeHTTP(out, req)
		if out.Code != tc.status {
			t.Fatalf("%s %s: expected %d, got %d body=%s", tc.method, tc.path, tc.status, out.Code, out.Body.String())
		}
		for _, header := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Headers", "Access-Control-Allow-Methods"} {
			if got := out.Header().Get(header); got != "" {
				t.Fatalf("%s %s: expected no %s header, got %q", tc.method, tc.path, header, got)
			}
		}
		if strings.Contains(out.Body.String(), "plaintext") || strings.Contains(out.Body.String(), "secret-cookie-secret") {
			t.Fatalf("%s %s: CORS denial path should remain value-free: %s", tc.method, tc.path, out.Body.String())
		}
	}
}

func TestAPIPreflightUsesSafeMethodBoundary(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodOptions, "/api/posture", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("X-Request-Id", "cors-preflight-1")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("expected Allow GET, HEAD, got %q", got)
	}
	body := out.Body.String()
	for _, want := range []string{`"error":"method_not_allowed"`, `"request_id":"cors-preflight-1"`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("preflight denial should include %s: %s", want, body)
		}
	}
	if out.Header().Get("Access-Control-Allow-Origin") != "" || strings.Contains(body, "plaintext") {
		t.Fatalf("preflight denial should not open CORS or leak values: headers=%#v body=%s", out.Header(), body)
	}
}

func TestRouteValueLeakSentinelCoversPublicAPIAndUI(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.oauth = testOAuthConfig()
	app.verifier = &oidc.IDTokenVerifier{}
	app.store.AppendAudit(AuditEntry{
		Action:  "minimization.proof",
		Outcome: "denied",
		Method:  http.MethodPost,
		Path:    "/JANUS_BACKEND_PATH_CANARY_296/JANUS_IDENTITY_CLAIM_CANARY_296",
		Reason:  "JANUS_PROMPT_MODEL_CANARY_296 JANUS_STDOUT_CANARY_296 JANUS_STDERR_CANARY_296 JANUS_ENV_DUMP_CANARY_296",
	})

	cases := []struct {
		name        string
		pattern     string
		method      string
		path        string
		body        string
		contentType string
		status      int
		setup       func(*http.Request)
	}{
		{name: "health", pattern: "GET /healthz", method: http.MethodGet, path: "/healthz", status: http.StatusOK},
		{name: "ready", pattern: "GET /readyz", method: http.MethodGet, path: "/readyz", status: http.StatusOK},
		{name: "build receipt", pattern: "GET /buildz", method: http.MethodGet, path: "/buildz", status: http.StatusOK},
		{name: "favicon", pattern: "GET /favicon.ico", method: http.MethodGet, path: "/favicon.ico", status: http.StatusNoContent},
		{name: "login", pattern: "GET /login", method: http.MethodGet, path: "/login", status: http.StatusFound},
		{name: "auth reset", pattern: "GET /auth/reset", method: http.MethodGet, path: "/auth/reset", status: http.StatusOK},
		{
			name:    "bad callback",
			pattern: "GET /oidc/callback",
			method:  http.MethodGet,
			path:    "/oidc/callback?state=wrong&code=JANUS_SECRET_CANARY_296",
			status:  http.StatusBadRequest,
			setup: func(req *http.Request) {
				req.AddCookie(&http.Cookie{Name: hostStateCookie, Value: "state-cookie-secret"})
				req.AddCookie(&http.Cookie{Name: hostNonceCookie, Value: "nonce-cookie-secret"})
				req.AddCookie(&http.Cookie{Name: hostPKCECookie, Value: "JANUS_AUTH_COOKIE_CANARY_296"})
			},
		},
		{name: "browser missing", method: http.MethodGet, path: "/missing?ref=secret-cookie-secret", status: http.StatusNotFound},
		{name: "api missing", method: http.MethodGet, path: "/api/missing?ref=raw-secret-value", status: http.StatusNotFound},
		{name: "api method", method: http.MethodDelete, path: "/api/posture", status: http.StatusMethodNotAllowed},
		{name: "logout", pattern: "POST /logout", method: http.MethodPost, path: "/logout", status: http.StatusFound},
		{name: "posture", pattern: "GET /api/posture", method: http.MethodGet, path: "/api/posture", status: http.StatusOK},
		{name: "auth witness", pattern: "GET /api/auth/session-witness", method: http.MethodGet, path: "/api/auth/session-witness", status: http.StatusOK},
		{name: "auth smoke", pattern: "GET /auth/smoke", method: http.MethodGet, path: "/auth/smoke", status: http.StatusOK},
		{name: "session witness page", pattern: "GET /session-witness", method: http.MethodGet, path: "/session-witness", status: http.StatusOK},
		{name: "session witness text", pattern: "GET /session-witness.txt", method: http.MethodGet, path: "/session-witness.txt", status: http.StatusOK},
		{name: "session witness verifier", pattern: "GET /session-witness/verify", method: http.MethodGet, path: "/session-witness/verify", status: http.StatusOK},
		{name: "session witness verifier bad post", pattern: "POST /session-witness/verify", method: http.MethodPost, path: "/session-witness/verify", body: "proof_line=secret-cookie-secret&proof_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", contentType: "application/x-www-form-urlencoded", status: http.StatusUnprocessableEntity},
		{name: "session witness verify current", pattern: "POST /session-witness/verify-current", method: http.MethodPost, path: "/session-witness/verify-current", status: http.StatusOK},
		{name: "auth witness verifier bad post", pattern: "POST /api/auth/session-witness/verify", method: http.MethodPost, path: "/api/auth/session-witness/verify", body: `{"proof_line":"secret-cookie-secret","proof_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, contentType: "application/json", status: http.StatusUnprocessableEntity},
		{name: "descriptors", pattern: "GET /api/warden/descriptors", method: http.MethodGet, path: "/api/warden/descriptors", status: http.StatusOK},
		{name: "audit", pattern: "GET /api/audit/recent", method: http.MethodGet, path: "/api/audit/recent", status: http.StatusOK},
		{name: "evidence", pattern: "GET /api/evidence", method: http.MethodGet, path: "/api/evidence", status: http.StatusOK},
		{name: "resolve", pattern: "POST /api/warden/resolve", method: http.MethodPost, path: "/api/warden/resolve", body: `{"ref":"zitadel-janus-oidc","reason":"local smoke"}`, contentType: "application/json", status: http.StatusOK},
		{name: "resolve bad json", method: http.MethodPost, path: "/api/warden/resolve", body: `{"ref":"JANUS_REQUEST_BODY_CANARY_296"`, contentType: "application/json", status: http.StatusBadRequest},
		{name: "permit", pattern: "POST /api/permits", method: http.MethodPost, path: "/api/permits", body: `{"ref":"zitadel-janus-oidc","action":"metadata_use","destination":"dashboard","reason":"local smoke"}`, contentType: "application/json", status: http.StatusCreated},
		{name: "permit missing run", pattern: "POST /api/permits/{permitID}/run", method: http.MethodPost, path: "/api/permits/missing/run", status: http.StatusNotFound},
		{name: "dashboard", pattern: "GET /", method: http.MethodGet, path: "/", status: http.StatusOK},
		{name: "access", pattern: "GET /access", method: http.MethodGet, path: "/access", status: http.StatusOK},
		{name: "requests", pattern: "GET /requests", method: http.MethodGet, path: "/requests", status: http.StatusOK},
		{name: "ledger", pattern: "GET /ledger", method: http.MethodGet, path: "/ledger", status: http.StatusOK},
		{name: "assurance", pattern: "GET /assurance", method: http.MethodGet, path: "/assurance", status: http.StatusOK},
		{name: "settings", pattern: "GET /settings", method: http.MethodGet, path: "/settings", status: http.StatusOK},
		{name: "new secret", pattern: "GET /vault/new", method: http.MethodGet, path: "/vault/new", status: http.StatusOK},
		{name: "new secret script denial", pattern: "GET /vault/new/plan.sh", method: http.MethodGet, path: "/vault/new/plan.sh", status: http.StatusBadRequest},
		{name: "static asset", pattern: "GET /static/", method: http.MethodGet, path: "/static/janus.css", status: http.StatusOK},
		{name: "ui resolve", pattern: "POST /ui/warden/resolve", method: http.MethodPost, path: "/ui/warden/resolve", body: "ref=zitadel-janus-oidc&reason=local+smoke", contentType: "application/x-www-form-urlencoded", status: http.StatusOK},
		{name: "ui permit", pattern: "POST /ui/permits", method: http.MethodPost, path: "/ui/permits", body: "ref=zitadel-janus-oidc&action=metadata_use&destination=dashboard&reason=local+smoke", contentType: "application/x-www-form-urlencoded", status: http.StatusOK},
		{name: "ui permit missing run", pattern: "POST /ui/permits/{permitID}/run", method: http.MethodPost, path: "/ui/permits/missing/run", status: http.StatusNotFound},
	}

	registered := make(map[string]bool, len(app.routeSpecs()))
	for _, route := range app.routeSpecs() {
		if registered[route.pattern] {
			t.Fatal(minimizationDiagnostic("route_inventory"))
		}
		registered[route.pattern] = true
	}
	covered := make(map[string]bool, len(registered))
	for _, tc := range cases {
		if tc.pattern == "" {
			continue
		}
		if covered[tc.pattern] {
			t.Fatal(minimizationDiagnostic("route_inventory"))
		}
		covered[tc.pattern] = true
	}
	if len(covered) != len(registered) {
		t.Fatal(minimizationDiagnostic("route_inventory"))
	}
	for pattern := range registered {
		if !covered[pattern] {
			t.Fatal(minimizationDiagnostic("route_inventory"))
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqID := "route-sentinel-" + strings.NewReplacer(" ", "-", "/", "-").Replace(tc.name)
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("X-Request-Id", reqID)
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			if tc.setup != nil {
				tc.setup(req)
			}
			out := httptest.NewRecorder()
			app.routes().ServeHTTP(out, req)
			if out.Code != tc.status {
				t.Fatal(minimizationDiagnostic("unexpected_status"))
			}
			assertRouteResponseValueFree(t, tc.name, out)
			assertJSONErrorRequestCorrelated(t, tc.name, reqID, out)
		})
	}
}

func TestJSONErrorResponsesAreRequestCorrelated(t *testing.T) {
	app := newTestApp(t)

	for _, tc := range []struct {
		name   string
		method string
		path   string
		status int
	}{
		{name: "auth required posture", method: http.MethodGet, path: "/api/posture", status: http.StatusUnauthorized},
		{name: "auth required browser witness", method: http.MethodGet, path: "/api/auth/session-witness", status: http.StatusUnauthorized},
		{name: "auth required witness verifier", method: http.MethodPost, path: "/api/auth/session-witness/verify", status: http.StatusUnauthorized},
		{name: "auth required resolve", method: http.MethodPost, path: "/api/warden/resolve", status: http.StatusUnauthorized},
		{name: "auth required evidence", method: http.MethodGet, path: "/api/evidence", status: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reqID := "json-error-" + strings.NewReplacer(" ", "-", "/", "-").Replace(tc.name)
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("X-Request-Id", reqID)
			out := httptest.NewRecorder()
			app.routes().ServeHTTP(out, req)
			if out.Code != tc.status {
				t.Fatalf("expected %d, got %d body=%s", tc.status, out.Code, out.Body.String())
			}
			assertRouteResponseValueFree(t, tc.name, out)
			assertJSONErrorRequestCorrelated(t, tc.name, reqID, out)
		})
	}

	setupApp := newTestApp(t)
	setupApp.cfg.OIDCSecret = ""
	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	req.Header.Set("X-Request-Id", "json-error-setup")
	out := httptest.NewRecorder()
	setupApp.routes().ServeHTTP(out, req)
	if out.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", out.Code, out.Body.String())
	}
	assertRouteResponseValueFree(t, "auth setup", out)
	assertJSONErrorRequestCorrelated(t, "auth setup", "json-error-setup", out)
}

func assertRouteResponseValueFree(t *testing.T, name string, out *httptest.ResponseRecorder) {
	t.Helper()
	_ = name
	var haystack strings.Builder
	haystack.WriteString(out.Body.String())
	for key, values := range out.Result().Header {
		haystack.WriteString("\n")
		haystack.WriteString(key)
		haystack.WriteString(":")
		haystack.WriteString(strings.Join(values, "\n"))
	}
	body := strings.ToLower(haystack.String())
	for _, marker := range []string{
		"janus_secret_canary_296",
		"janus_prompt_model_canary_296",
		"janus_stdout_canary_296",
		"janus_stderr_canary_296",
		"janus_env_dump_canary_296",
		"janus_request_body_canary_296",
		"janus_backend_path_canary_296",
		"janus_auth_cookie_canary_296",
		"janus_identity_claim_canary_296",
		"plaintext",
		"raw-secret-value",
		"state-cookie-secret",
		"nonce-cookie-secret",
		"pkce-cookie-secret",
		"secret-cookie-secret",
		"cookie_key",
		"oidc_secret",
		"oidcsecret",
		"client_secret",
		"/run/agenix",
		"secrets/",
		".age\"",
		"\"source\"",
		"\"value_returned\":true",
		"value_returned=true",
	} {
		if strings.Contains(body, marker) {
			t.Fatal(minimizationDiagnostic("forbidden_literal"))
		}
	}
}

func assertJSONErrorRequestCorrelated(t *testing.T, name, reqID string, out *httptest.ResponseRecorder) {
	t.Helper()
	_ = name
	if out.Code < http.StatusBadRequest || !strings.Contains(out.Header().Get("Content-Type"), "application/json") {
		return
	}
	body := out.Body.String()
	for _, want := range []string{`"request_id":"` + reqID + `"`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatal(minimizationDiagnostic("request_correlation"))
		}
	}
}

func minimizationDiagnostic(reason string) string {
	switch reason {
	case "evidence_shape", "forbidden_literal", "request_correlation", "route_inventory", "unexpected_status":
		return "minimization boundary failed: " + reason
	default:
		return "minimization boundary failed: unknown"
	}
}

func TestMinimizationDiagnosticsNeverEchoUntrustedContent(t *testing.T) {
	canary := "JANUS_SECRET_CANARY_296"
	if got := minimizationDiagnostic(canary); strings.Contains(got, canary) || got != "minimization boundary failed: unknown" {
		t.Fatal("minimization diagnostic sanitization failed")
	}
}

func TestRandomNonceIsTemplateSafe(t *testing.T) {
	nonce := randomNonce(64)
	if nonce == "" || strings.ContainsAny(nonce, "+/=") {
		t.Fatalf("CSP nonce should be URL-safe and unpadded, got %q", nonce)
	}
}

func TestRequestIDHeaderAndAuditCorrelation(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	req.Header.Set("X-Request-Id", "req-test_123")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	if got := out.Header().Get("X-Request-Id"); got != "req-test_123" {
		t.Fatalf("expected request id response header, got %q", got)
	}
	recent := app.store.RecentAudit(1)
	if len(recent) != 1 || recent[0].RequestID != "req-test_123" {
		t.Fatalf("expected audit event to reuse request id: %#v", recent)
	}
}

func TestRequestIDRejectsUnsafeInboundValue(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	req.Header.Set("X-Request-Id", "bad\r\nInjected: yes")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	got := out.Header().Get("X-Request-Id")
	if got == "" || strings.Contains(got, "Injected") || got == "bad\r\nInjected: yes" {
		t.Fatalf("unsafe request id should be replaced, got %q", got)
	}
}

func TestActionReadinessDistinguishesRoleAndReadinessGates(t *testing.T) {
	viewer := ActionReadinessFor(Session{Roles: []string{RoleViewer}}, true)
	if viewer.ValueReturned || viewer.Available != 2 || viewer.Gated != 5 || viewer.Blocked != 0 {
		t.Fatalf("viewer readiness should show two safe review actions and five role gates: %#v", viewer)
	}
	for _, key := range []string{"evidence_export", "handle_issue", "permit_create", "permit_run_check", "service_setup_download"} {
		if !actionReadinessHasState(viewer.Actions, key, "role_gated") {
			t.Fatalf("viewer readiness should role-gate %s: %#v", key, viewer)
		}
	}
	for _, key := range []string{"posture_view", "policy_posture"} {
		if !actionReadinessHasState(viewer.Actions, key, "available") {
			t.Fatalf("viewer readiness should allow safe review action %s: %#v", key, viewer)
		}
	}

	allRoles := ActionReadinessFor(Session{Roles: AllRoles()}, true)
	if allRoles.Available != 7 || allRoles.Gated != 0 || allRoles.Blocked != 0 || allRoles.ValueReturned {
		t.Fatalf("full-role readiness should make all actions available: %#v", allRoles)
	}
	for _, key := range []string{"evidence_export", "handle_issue", "permit_create", "permit_run_check", "service_setup_download", "policy_posture"} {
		if !actionReadinessHasState(allRoles.Actions, key, "available") {
			t.Fatalf("full-role readiness should allow %s: %#v", key, allRoles)
		}
	}

	degraded := ActionReadinessFor(Session{Roles: AllRoles()}, false)
	if degraded.Available != 3 || degraded.Blocked != 4 || degraded.Gated != 0 {
		t.Fatalf("degraded readiness should block sensitive actions while leaving safe views: %#v", degraded)
	}
	for _, key := range []string{"evidence_export", "handle_issue", "permit_create", "permit_run_check"} {
		if !actionReadinessHasState(degraded.Actions, key, "readiness_blocked") {
			t.Fatalf("degraded readiness should block %s: %#v", key, degraded)
		}
	}
	if !actionReadinessHasState(degraded.Actions, "posture_view", "available") || !actionReadinessHasState(degraded.Actions, "policy_posture", "available") || !actionReadinessHasState(degraded.Actions, "service_setup_download", "available") {
		t.Fatalf("degraded readiness should leave safe review actions available: %#v", degraded)
	}
}

func TestRouteGateViewsAreOrderedAndSessionAware(t *testing.T) {
	access := AccessPostureFor(RolePolicy{})

	viewer := RouteGateViewsFor(Session{Roles: []string{RoleViewer}}, access, true)
	if len(viewer) != len(access.RequiredRoles) {
		t.Fatalf("expected one view per required route: %#v", viewer)
	}
	wantOrder := []string{
		"POST /api/warden/resolve",
		"POST /api/permits",
		"POST /api/permits/{permitID}/run",
		"GET /vault/new/plan.sh",
		"GET /api/audit/recent",
		"GET /api/evidence",
	}
	for i, want := range wantOrder {
		if viewer[i].Route != want {
			t.Fatalf("route gate views should follow the operator workflow, index %d got %q want %q: %#v", i, viewer[i].Route, want, viewer)
		}
	}
	for _, gate := range viewer {
		if gate.State != "Role-gated" || gate.SessionState != "Missing" || gate.Tone != "warn" {
			t.Fatalf("viewer session should not pass elevated route %s: %#v", gate.Route, viewer)
		}
	}

	operator := RouteGateViewsFor(Session{Roles: []string{RoleOperator, RoleViewer}}, access, true)
	for _, gate := range operator {
		if gate.RequiredRole == RoleOperator && gate.State != "Allowed" {
			t.Fatalf("operator route should be allowed: %#v", gate)
		}
		if gate.RequiredRole == RoleAuditor && gate.State != "Role-gated" {
			t.Fatalf("auditor route should stay role gated for operator session: %#v", gate)
		}
	}

	degraded := RouteGateViewsFor(Session{Roles: AllRoles()}, access, false)
	for _, gate := range degraded {
		if gate.ReadinessGated && (gate.State != "Blocked" || gate.Tone != "warn") {
			t.Fatalf("readiness degradation should block readiness-gated route %s: %#v", gate.Route, degraded)
		}
		if !gate.ReadinessGated && (gate.State != "Allowed" || gate.Tone != "ok") {
			t.Fatalf("readiness degradation should leave the role-only audit view available: %#v", degraded)
		}
	}
}

func TestWardenResolveUIReturnsValueFreeHandle(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodPost, "/ui/warden/resolve", strings.NewReader("ref=zitadel-janus-oidc&reason=local+smoke"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	app.withAuth(app.handleResolveHandleUI)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Metadata reference ready", "Action receipt", "Role", "CSRF", "Readiness", "Audit", "Proof", "hash locked", "ar_", "sha256-json-v1", "janus-action-receipt-v1", "Copy-safe action receipt fields", "Receipt id", "Receipt hash", "Request id", "Verify receipt", "Recompute the SHA-256 hash", "copy-safe", "Covered checks", "role_checked=true", "csrf_checked=true", "readiness_checked=true", "audit_recorded=true", "tamper_evident=true", "covers", "request_id=", "metadata_only", "secret_value_returned=false", "request_body_returned=false", "value_returned=false", "zitadel-janus-oidc"} {
		if !strings.Contains(body, want) {
			t.Fatalf("UI handle response should render %q: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") {
		t.Fatalf("UI handle response should remain value-free: %s", body)
	}
}

func TestSensitiveUIFailsClosedWhenReadinessDegraded(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.permits = nil

	req := httptest.NewRequest(http.MethodPost, "/ui/warden/resolve", strings.NewReader("ref=zitadel-janus-oidc&reason=local+smoke"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Request-Id", "degraded-ui-1")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Metadata reference blocked", "system_degraded", "request_id=degraded-ui-1", "sensitive action blocked", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("degraded UI denial should render %q: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") || strings.Contains(body, "secret-cookie-secret") {
		t.Fatalf("degraded UI denial should remain value-free: %s", body)
	}
}

func TestWardenResolveUIRequiresReason(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodPost, "/ui/warden/resolve", strings.NewReader("ref=zitadel-janus-oidc"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	app.withAuth(app.handleResolveHandleUI)(out, req)
	if out.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", out.Code, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), "Reason required") || strings.Contains(out.Body.String(), "plaintext") {
		t.Fatalf("UI denial should be clear and value-free: %s", out.Body.String())
	}
}

func TestWardenResolveUIRequiresOperatorRole(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	form := "ref=zitadel-janus-oidc&reason=local+smoke&csrf_token=" + app.csrfToken(session)
	req := httptest.NewRequest(http.MethodPost, "/ui/warden/resolve", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.withAuth(app.handleResolveHandleUI)(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", out.Code, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), "Operator role required") || strings.Contains(out.Body.String(), "plaintext") {
		t.Fatalf("operator UI denial should be clear and value-free: %s", out.Body.String())
	}
}

func TestPermitCreateUIReturnsValueFreePermit(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodPost, "/ui/permits", strings.NewReader("ref=zitadel-janus-oidc&action=metadata_use&destination=dashboard&reason=local+smoke"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	app.withAuth(app.handleCreatePermitUI)(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Metadata authorization recorded", "Action receipt", "Role", "CSRF", "Readiness", "Audit", "Proof", "hash locked", "ar_", "sha256-json-v1", "janus-action-receipt-v1", "Copy-safe action receipt fields", "Receipt id", "Receipt hash", "Request id", "Verify receipt", "Recompute the SHA-256 hash", "copy-safe", "Covered checks", "role_checked=true", "csrf_checked=true", "readiness_checked=true", "audit_recorded=true", "tamper_evident=true", "covers", "request_id=", "metadata_only", "secret_value_returned=false", "request_body_returned=false", "Authorization safety verdict", "Metadata only", "No connector", "Audited", "Recorded · metadata only", "Verify that execution is disabled", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("permit UI response should render %q: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") {
		t.Fatalf("permit UI response should remain value-free: %s", body)
	}
}

func TestPermitCreateUIRequiresReason(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodPost, "/ui/permits", strings.NewReader("ref=zitadel-janus-oidc&action=metadata_use"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	app.withAuth(app.handleCreatePermitUI)(out, req)
	if out.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", out.Code, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), "Reason required") || strings.Contains(out.Body.String(), "plaintext") {
		t.Fatalf("permit UI denial should be clear and value-free: %s", out.Body.String())
	}
}

func TestPermitRunUIReturnsNoExecutionValueFreeResult(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	permit, err := app.broker.CreatePermit(principalFromSession(Session{Subject: "user-1"}), PermitRequest{
		Ref:    "zitadel-janus-oidc",
		Action: "metadata_use",
		Reason: "local smoke",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.permits.Put(permit); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/ui/permits/"+permit.ID+"/run", nil)
	req.SetPathValue("permitID", permit.ID)
	out := httptest.NewRecorder()
	app.withAuth(app.handleRunPermitUI)(out, req)
	if out.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"Safety check complete", "Action receipt", "Role", "CSRF", "Readiness", "Audit", "Proof", "hash locked", "ar_", "sha256-json-v1", "janus-action-receipt-v1", "Copy-safe action receipt fields", "Receipt id", "Receipt hash", "Request id", "Verify receipt", "Recompute the SHA-256 hash", "copy-safe", "Covered checks", "role_checked=true", "csrf_checked=true", "readiness_checked=true", "audit_recorded=true", "tamper_evident=true", "covers", "request_id=", "metadata_only", "secret_value_returned=false", "request_body_returned=false", "Authorization safety-check result", "Execution verdict", "Run denial reason", "Safety-check evidence", "Execution remained disabled", "run_reason_returned=true", "connector_execution=false", "connector_output_returned=false", "permit_payload_returned=false", "backend_path_returned=false", "source_path_returned=false", "env_returned=false", "Authorization safety verdict", "Metadata only", "No connector", "Scrubbed output", "Execution disabled", "output_scrubbed=true", "value_returned=false"} {
		if !strings.Contains(body, want) {
			t.Fatalf("permit run UI response should render %q: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") || strings.Contains(body, "connector_output=secret") {
		t.Fatalf("permit run UI response should remain value-free: %s", body)
	}
}

func TestScopePolicyFiltersDescriptorsAndDeniesResolve(t *testing.T) {
	dataDir := t.TempDir()
	catalogPath := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(catalogPath, []byte(`[{
		"id":"in-scope",
		"display_name":"In scope",
		"provider":"agenix",
		"classification":"high",
		"owner":"platform",
		"scope":"csb1",
		"source":"secrets/in-scope.age",
		"consumer_count":1
	},{
		"id":"out-of-scope",
		"display_name":"Out of scope",
		"provider":"agenix",
		"classification":"high",
		"owner":"platform",
		"scope":"csb2",
		"source":"secrets/out-of-scope.age",
		"consumer_count":1
	}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dataDir, catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	broker := NewBroker(store).WithScopePolicy(ScopePolicy{AllowedScopes: map[string]bool{"csb1": true}, Strict: true})
	descriptors := broker.Descriptors(PrincipalChain{HumanSubject: "user-1"})
	if len(descriptors) != 1 || descriptors[0].ID != "in-scope" {
		t.Fatalf("expected only in-scope descriptor, got %#v", descriptors)
	}
	_, err = broker.ResolveHandle(PrincipalChain{HumanSubject: "user-1"}, HandleRequest{Ref: "out-of-scope"})
	if !errors.Is(err, ErrPolicyDenied) {
		t.Fatalf("expected out-of-scope denial, got %v", err)
	}
	posture := ScopePostureFor(broker.scopePolicy, store.Descriptors())
	if posture.OutOfScopeCount != 1 || posture.GateCount != 1 || posture.ValueReturned {
		t.Fatalf("unexpected scope posture: %#v", posture)
	}
}

func TestLifecycleBlocksUnsafeDescriptorUse(t *testing.T) {
	dataDir := t.TempDir()
	catalogPath := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(catalogPath, []byte(`[{
		"id":"disabled-secret",
		"display_name":"Disabled secret",
		"provider":"agenix",
		"classification":"high",
		"owner":"platform",
		"scope":"csb1",
		"source":"secrets/disabled-secret.age",
		"lifecycle":"disabled",
		"consumer_count":1,
		"use_enabled":true
	}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dataDir, catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	broker := NewBroker(store)
	principal := PrincipalChain{HumanSubject: "user-1"}

	_, err = broker.ResolveHandle(principal, HandleRequest{Ref: "disabled-secret", Reason: "test"})
	if !errors.Is(err, ErrPolicyDenied) || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected lifecycle policy denial, got %v", err)
	}
	_, err = broker.CreatePermit(principal, PermitRequest{Ref: "disabled-secret", Action: "metadata_use", Reason: "test"})
	if !errors.Is(err, ErrPolicyDenied) || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected lifecycle permit denial, got %v", err)
	}

	posture := LifecyclePostureFor(store.Descriptors(), time.Now().UTC())
	if posture.BlockedCount != 1 || posture.GateCount != 1 || posture.ValueReturned {
		t.Fatalf("unexpected lifecycle posture: %#v", posture)
	}
}

func TestBrokerRequiresApprovedMetadataUseProfile(t *testing.T) {
	dataDir := t.TempDir()
	catalogPath := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(catalogPath, []byte(`[{
		"id":"unprofiled-secret",
		"display_name":"Unprofiled secret",
		"provider":"agenix",
		"classification":"high",
		"owner":"platform",
		"scope":"csb1",
		"source":"secrets/unprofiled-secret.age",
		"lifecycle":"active",
		"consumer_count":1,
		"use_enabled":false
	}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dataDir, catalogPath)
	if err != nil {
		t.Fatal(err)
	}
	broker := NewBroker(store)
	principal := PrincipalChain{HumanSubject: "user-1"}

	_, err = broker.ResolveHandle(principal, HandleRequest{Ref: "unprofiled-secret", Reason: "test"})
	if !errors.Is(err, ErrPolicyDenied) || !strings.Contains(err.Error(), "approved metadata-only use profile") {
		t.Fatalf("expected approved-use policy denial, got %v", err)
	}
	_, err = broker.CreatePermit(principal, PermitRequest{Ref: "unprofiled-secret", Action: "metadata_use", Reason: "test"})
	if !errors.Is(err, ErrPolicyDenied) || !strings.Contains(err.Error(), "approved metadata-only use profile") {
		t.Fatalf("expected approved-use permit denial, got %v", err)
	}

	focus := focusDescriptor(store.Descriptors(), "unprofiled-secret")
	if !focus.NormalUseBlocked || focus.NormalUseReason == "" || focus.LifecycleBlocked {
		t.Fatalf("focus should show approved-use block without lifecycle block: %#v", focus)
	}
	posture := ApprovedUsePostureFor(store.Descriptors())
	if posture.Profile != "metadata_only" || !posture.Enforced || posture.ProfiledCount != 0 || posture.BlockedCount != 1 || posture.SecretValuesAllowed || posture.ValueReturned {
		t.Fatalf("unexpected approved-use posture: %#v", posture)
	}
}

func TestEvidenceIntegrityIsValueFreeAndStableShape(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	pack := app.evidencePack(Session{Roles: AllRoles()})
	if pack.Integrity == nil {
		t.Fatal("expected evidence integrity metadata")
	}
	if pack.Integrity.Algorithm != "sha256-json-v1" || len(pack.Integrity.PackHash) != 64 {
		t.Fatalf("unexpected integrity metadata: %#v", pack.Integrity)
	}
	if pack.Integrity.ValueReturned || pack.Integrity.GeneratedAt.IsZero() {
		t.Fatalf("integrity metadata should be value-free and timestamped: %#v", pack.Integrity)
	}
	if pack.Receipt == nil || pack.Receipt.PackHash != pack.Integrity.PackHash || !pack.Receipt.HashAvailable || pack.Receipt.HashHeader != "X-Janus-Evidence-Hash" || pack.Receipt.BodyField != "integrity.pack_hash" || pack.Receipt.ValueReturned {
		t.Fatalf("receipt should mirror integrity hash without values: %#v", pack.Receipt)
	}
}

func TestCatalogGovernanceFlagsDisabledUseProfiles(t *testing.T) {
	gates := ValidateCatalog([]SecretDescriptor{{
		ID:             "example",
		DisplayName:    "Example",
		Provider:       "agenix",
		Classification: "high",
		Owner:          "platform",
		Scope:          "csb1",
		Source:         "secrets/example.age",
		ConsumerCount:  1,
		UseEnabled:     false,
	}})
	if len(gates) != 1 || gates[0].Code != "no_approved_use_profile" {
		t.Fatalf("unexpected gates: %#v", gates)
	}
}

func hasTestRole(roles []string, want string) bool {
	for _, role := range roles {
		if role == want {
			return true
		}
	}
	return false
}

func TestRateLimiterBlocksBurst(t *testing.T) {
	limiter := NewRateLimiter(2, time.Minute)
	if !limiter.Allow("test") {
		t.Fatal("expected first request to pass")
	}
	if !limiter.Allow("test") {
		t.Fatal("expected second request to pass")
	}
	if limiter.Allow("test") {
		t.Fatal("expected third request to be limited")
	}
}

func TestRateLimitDenialIsOperationalAndValueFree(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.limiter = NewRateLimiter(1, time.Minute)

	first := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	first.RemoteAddr = "192.0.2.8:1234"
	firstOut := httptest.NewRecorder()
	app.routes().ServeHTTP(firstOut, first)
	if firstOut.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d body=%s", firstOut.Code, firstOut.Body.String())
	}

	second := httptest.NewRequest(http.MethodGet, "/api/posture", nil)
	second.RemoteAddr = "192.0.2.8:1234"
	second.Header.Set("X-Request-Id", "rate-limit-2")
	secondOut := httptest.NewRecorder()
	app.routes().ServeHTTP(secondOut, second)
	if secondOut.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d body=%s", secondOut.Code, secondOut.Body.String())
	}
	if got := secondOut.Header().Get("Retry-After"); got != "60" {
		t.Fatalf("expected Retry-After 60, got %q", got)
	}
	body := secondOut.Body.String()
	for _, want := range []string{`"error":"rate_limited"`, `"request_id":"rate-limit-2"`, `"retry_after_seconds":60`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("rate-limit denial should include %s: %s", want, body)
		}
	}
	if strings.Contains(body, "plaintext") || strings.Contains(body, "secret-cookie-secret") {
		t.Fatalf("rate-limit denial should remain value-free: %s", body)
	}
}

func TestPermitRunIsNoopAndValueFree(t *testing.T) {
	app := newTestApp(t)
	permit, err := app.broker.CreatePermit(principalFromSession(Session{Subject: "user-1"}), PermitRequest{
		Ref:    "zitadel-janus-oidc",
		Action: "metadata_use",
		Reason: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	result := RunPermit(permit)
	if result.ValueReturned || !result.OutputScrubbed || result.Status != "not_executed" {
		t.Fatalf("unexpected permit run result: %#v", result)
	}
}

func TestPermitStorePersistsAndReloadsValueFreeRecords(t *testing.T) {
	dataDir := t.TempDir()
	store, err := NewPermitStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	permit := Permit{
		ID:            "p_test",
		SecretRef:     "zitadel-janus-oidc",
		Action:        "metadata_use",
		Reason:        "audit trail",
		Status:        "approved_metadata_only",
		ValueReturned: true,
		PrincipalHash: "actor-hash",
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(time.Minute),
	}
	if err := store.Put(permit); err != nil {
		t.Fatal(err)
	}
	permitFile := filepath.Join(dataDir, "permits.json")
	info, err := os.Stat(permitFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permit file mode should be 0600, got %o", info.Mode().Perm())
	}
	raw, err := os.ReadFile(permitFile)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if !strings.Contains(body, `"value_returned": false`) || strings.Contains(body, "plaintext") {
		t.Fatalf("permit store should be value-free: %s", body)
	}

	reloaded, err := NewPermitStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.Get("p_test")
	if !ok || got.SecretRef != permit.SecretRef || got.ValueReturned {
		t.Fatalf("unexpected reloaded permit: %#v ok=%t", got, ok)
	}
	posture := reloaded.Posture()
	if posture.Count != 1 || !posture.Persisted || posture.ValueReturned {
		t.Fatalf("unexpected permit posture: %#v", posture)
	}
}

func TestPermitStoreRejectsCorruptPersistenceFile(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "permits.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPermitStore(dataDir); err == nil {
		t.Fatal("expected corrupt permit store to fail closed")
	}
}

func TestHealthzIsRedactedLivenessOnly(t *testing.T) {
	app := newTestApp(t)

	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{`"status":"ok"`, `"service":"janus"`, `"mode":"self_hosted"`, `"redacted":true`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("healthz should include %s: %s", want, body)
		}
	}
	for _, forbidden := range []string{"oidc_configured", "auth_required", "descriptor_count", "audit_entries", "secret_count", "plaintext", "secret-cookie-secret"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("healthz should not expose %q: %s", forbidden, body)
		}
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("healthz should keep no-store header, got %q", got)
	}
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("healthz should keep nosniff header, got %q", got)
	}
}

func TestBuildzExposesValueFreeBuildReceipt(t *testing.T) {
	oldCommit, oldBuildTime := buildCommit, buildTime
	buildCommit = "bed42fa782289d71f4dcde74c0594a8e398b60cc"
	buildTime = "2026-06-25T07:25:00Z"
	defer func() {
		buildCommit, buildTime = oldCommit, oldBuildTime
	}()
	app := newTestApp(t)

	rr := httptest.NewRecorder()
	app.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/buildz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		`"schema":"janus-runtime-build-receipt-v1"`,
		`"status":"ok"`,
		`"service":"janus"`,
		`"mode":"self_hosted"`,
		`"serving_binary":"go-envelope"`,
		`"engine_state":"rust_engine_in_repo_transitional"`,
		`"build_provenance"`,
		`"commit":"bed42fa782289d71f4dcde74c0594a8e398b60cc"`,
		`"commit_short":"bed42fa78228"`,
		`"build_time":"2026-06-25T07:25:00Z"`,
		`"commit_bound":true`,
		`"build_time_bound":true`,
		`"signed_image_expected":true`,
		`"sbom_expected":true`,
		`"provenance_expected":true`,
		`"digest_pinned_expected":true`,
		`"redacted":true`,
		`"artifact_returned":false`,
		`"sbom_returned":false`,
		`"scanner_output_returned":false`,
		`"env_returned":false`,
		`"backend_path_returned":false`,
		`"secret_value_returned":false`,
		`"value_returned":false`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("buildz should include %s: %s", want, body)
		}
	}
	for _, forbidden := range []string{"oidc_configured", "auth_required", "descriptor_count", "audit_entries", "secret_count", "OIDC_SECRET", "JANUS_CATALOG_FILE", "secret-cookie-secret", "/run/agenix"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("buildz should not expose %q: %s", forbidden, body)
		}
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("buildz should keep no-store header, got %q", got)
	}
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("buildz should keep nosniff header, got %q", got)
	}
	assertRouteResponseValueFree(t, "buildz", rr)
}

func TestReadyzLockedWhenAuthMissing(t *testing.T) {
	tTempDir = t.TempDir()
	store, err := NewStore(tTempDir, "")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{cfg: Config{PublicURL: "https://vault.barta.cm", RequireAuth: true}, store: store}

	rr := httptest.NewRecorder()
	app.handleReady(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"auth":false`) || !strings.Contains(rr.Body.String(), `"value_returned":false`) {
		t.Fatalf("readyz should explain value-free failed checks: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"redacted":true`) || strings.Contains(rr.Body.String(), "descriptor_count") || strings.Contains(rr.Body.String(), "oidc_configured") || strings.Contains(rr.Body.String(), "auth_required") {
		t.Fatalf("readyz should stay public-redacted: %s", rr.Body.String())
	}
}

func TestReadyzReportsValueFreeChecks(t *testing.T) {
	app := newTestApp(t)

	rr := httptest.NewRecorder()
	app.handleReady(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{`"ready":true`, `"mode":"self_hosted"`, `"auth":true`, `"descriptor_store":true`, `"audit_sink":true`, `"audit_chain":true`, `"permit_store":true`, `"redacted":true`, `"value_returned":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("readyz should include %s: %s", want, body)
		}
	}
	for _, forbidden := range []string{"descriptor_count", "audit_entries", "secret_count", "oidc_configured", "auth_required"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("readyz should not expose inventory count %q: %s", forbidden, body)
		}
	}
}

func TestReadyzRequiresPermitStore(t *testing.T) {
	app := newTestApp(t)
	app.permits = nil

	rr := httptest.NewRecorder()
	app.handleReady(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"permit_store":false`) {
		t.Fatalf("readyz should fail when permit store is unavailable: %s", rr.Body.String())
	}
}

func TestDockerfileHealthcheckUsesReadyz(t *testing.T) {
	raw, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{"HEALTHCHECK", "/readyz", `"ready":true`} {
		if !strings.Contains(body, want) {
			t.Fatalf("Dockerfile healthcheck should include %q: %s", want, body)
		}
	}
}

func TestSetupPageRendersWhenAuthMissing(t *testing.T) {
	tTempDir = t.TempDir()
	store, err := NewStore(tTempDir, "")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{
		cfg:       Config{PublicURL: "https://vault.barta.cm", ProductMode: "self_hosted", RequireAuth: true},
		store:     store,
		templates: mustTemplates(),
	}

	rr := httptest.NewRecorder()
	app.withAuth(app.handleDashboard)(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected setup 503, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Janus is locked") {
		t.Fatalf("setup page did not render expected body: %s", rr.Body.String())
	}
}
