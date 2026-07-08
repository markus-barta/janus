package main

// JANUS-271: invariants of the doorkeeper vault page (the new "/" dashboard).
// The exhaustive legacy witness suite keeps running against /legacy in main_test.go.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVaultPageRendersCardsTilesAndBrand(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"JANUS", "every secret, accounted for", "/static/janus.css", "/static/janus-logo.svg", "Secrets", "Need attention", "value_returned=false", `href="/legacy"`, "rotates every"} {
		if !strings.Contains(body, want) {
			t.Fatalf("vault page should render %q: %s", want, body)
		}
	}
	assertRouteResponseValueFree(t, "vault page", out)
}

func TestVaultPageRendersFocusWithOperatorActions(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/?ref=csb1-age-identity", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"csb1-age-identity", `action="/ui/warden/resolve"`, `action="/ui/permits"`, "Issue handle", "Create permit"} {
		if !strings.Contains(body, want) {
			t.Fatalf("vault focus should render %q: %s", want, body)
		}
	}
}

func TestVaultPageHidesOperatorFormsForViewer(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)

	req := httptest.NewRequest(http.MethodGet, "/?ref=csb1-age-identity", nil)
	req.AddCookie(rr.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	if !strings.Contains(body, "No access yet") {
		t.Fatalf("viewer should get the friendly no-access state: %s", body)
	}
	for _, forbidden := range []string{`action="/ui/warden/resolve"`, `action="/ui/permits"`, "Issue handle", "Create permit"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("viewer vault page rendered operator form %q: %s", forbidden, body)
		}
	}
}

func TestVaultPageGatesLedgerByRole(t *testing.T) {
	app := newTestApp(t)
	app.store.AppendAudit(AuditEntry{
		Action:    "secret.review",
		Outcome:   "allowed",
		Method:    http.MethodPost,
		Path:      "/api/example",
		SecretRef: "private-ref",
	})

	viewer := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	viewerCookie := httptest.NewRecorder()
	app.writeSession(viewerCookie, viewer)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(viewerCookie.Result().Cookies()[0])
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	viewerBody := out.Body.String()
	if !strings.Contains(viewerBody, "needs the auditor role") {
		t.Fatalf("viewer should see the ledger role gate: %s", viewerBody)
	}
	if strings.Contains(viewerBody, "private-ref") {
		t.Fatalf("viewer vault page leaked audit ref: %s", viewerBody)
	}

	auditor := Session{Subject: "auditor", Roles: []string{RoleAuditor, RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	auditorCookie := httptest.NewRecorder()
	app.writeSession(auditorCookie, auditor)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(auditorCookie.Result().Cookies()[0])
	out = httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	auditorBody := out.Body.String()
	if !strings.Contains(auditorBody, "private-ref") || !strings.Contains(auditorBody, "secret.review") {
		t.Fatalf("auditor should see ledger rows: %s", auditorBody)
	}
}

func TestAccessPageRendersLanesWithoutIdentityValues(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	app.cfg.RolePolicy = RolePolicy{
		AdminSubjects:   map[string]bool{"markus@barta.com": true},
		AuditorSubjects: map[string]bool{"markus@barta.com": true},
		AdminGroups:     map[string]bool{"janus-admins": true},
	}

	req := httptest.NewRequest(http.MethodGet, "/access", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"who may open which door", "Admin lane", "Auditor lane", "Operator lane", "Policy and ownership", "/api/audit/recent", "deny-by-default", "value_returned=false", "Zitadel"} {
		if !strings.Contains(body, want) {
			t.Fatalf("access page should render %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"markus@barta.com", "janus-admins"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("access page leaked binding identity %q: %s", forbidden, body)
		}
	}
}

func TestVaultSidebarLinksAccessPage(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if !strings.Contains(out.Body.String(), `href="/access"`) {
		t.Fatalf("vault sidebar should link the access page: %s", out.Body.String())
	}
}

func TestVaultFiltersNarrowCardsButKeepTiles(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/?q=zitadel", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	body := out.Body.String()
	if !strings.Contains(body, "zitadel-janus-oidc") {
		t.Fatalf("filtered vault should keep matching secret: %s", body)
	}
	if strings.Contains(body, `href="/?ref=csb1-age-identity#focus"`) {
		t.Fatalf("filtered vault should hide non-matching secret: %s", body)
	}
	if !strings.Contains(body, "1 of 2 secrets shown") {
		t.Fatalf("filtered vault should show the filter note: %s", body)
	}

	req = httptest.NewRequest(http.MethodGet, "/?q=no-such-thing", nil)
	out = httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if !strings.Contains(out.Body.String(), "Nothing matches these filters") {
		t.Fatalf("empty filter result should render the friendly state: %s", out.Body.String())
	}
}

func TestVaultListViewRendersTable(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/?view=list", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	body := out.Body.String()
	for _, want := range []string{"<table class=\"ledger\">", "last checked", "csb1-age-identity", "zitadel-janus-oidc"} {
		if !strings.Contains(body, want) {
			t.Fatalf("list view should render %q: %s", want, body)
		}
	}
}

func TestNewSecretPlanGeneratesDeclarativeSteps(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/vault/new?service=xyz&host=csb1&rotation=90&tags=app-env", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	body := out.Body.String()
	for _, want := range []string{"csb1-xyz-env", "agenix -e secrets/csb1-xyz-env.age", "publicKeys = markus &#43;&#43; csb1", "age.secrets.csb1-xyz-env", "/run/agenix/csb1-xyz-env", "agenix-catalog.json", "1Password", "value never enters Janus", "rotation_days&#34;: 90"} {
		if !strings.Contains(body, want) {
			t.Fatalf("new-secret plan should include %q: %s", want, body)
		}
	}
	if strings.Contains(body, `name="value"`) || strings.Contains(body, "type=\"password\"") {
		t.Fatalf("new-secret flow must never ask for the secret value: %s", body)
	}
}

func TestNewSecretPlanRejectsUnusableNames(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/vault/new?service=Bad_Name!", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if !strings.Contains(out.Body.String(), "Plan not ready") {
		t.Fatalf("invalid service name should block the plan: %s", out.Body.String())
	}
	if strings.Contains(out.Body.String(), "agenix -e secrets/") {
		t.Fatalf("invalid plan should not emit commands: %s", out.Body.String())
	}
}

func TestVaultStaticAssetsServed(t *testing.T) {
	app := newTestApp(t)
	cases := []struct {
		path        string
		contentType string
	}{
		{path: "/static/janus.css", contentType: "text/css; charset=utf-8"},
		{path: "/static/janus-logo.svg", contentType: "image/svg+xml"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		out := httptest.NewRecorder()
		app.routes().ServeHTTP(out, req)
		if out.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", tc.path, out.Code)
		}
		if got := out.Header().Get("Content-Type"); got != tc.contentType {
			t.Fatalf("%s: expected content type %q, got %q", tc.path, tc.contentType, got)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/static/nope.js", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusNotFound {
		t.Fatalf("unknown static asset should 404, got %d", out.Code)
	}
}

func TestLegacyConsoleStillReachable(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	req := httptest.NewRequest(http.MethodGet, "/legacy", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", out.Code, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), "Command center") {
		t.Fatalf("legacy console should render the old dashboard: %s", out.Body.String())
	}
}
