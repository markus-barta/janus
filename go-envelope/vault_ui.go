package main

// JANUS-271: doorkeeper vault UI — first strangler slice. The embedded
// "dashboard" template (ui/vault.html) replaced the inline legacy page at /;
// the legacy console was removed in the JANUS-269 cull.

import (
	"embed"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed ui/janus.css ui/janus-logo.svg
var uiStaticFS embed.FS

//go:embed ui/*.html
var vaultTemplateFS embed.FS

type VaultTiles struct {
	Secrets   int
	Active    int
	Attention int
	Permits   int
}

func vaultTilesFor(descriptors []SecretDescriptor, lifecycle LifecyclePosture, permits PermitPosture) VaultTiles {
	return VaultTiles{
		Secrets:   len(descriptors),
		Active:    lifecycle.ActiveCount,
		Attention: lifecycle.BlockedCount + lifecycle.StaleCount,
		Permits:   permits.Count,
	}
}

func descriptorProviders(descriptors []SecretDescriptor) []string {
	seen := map[string]bool{}
	for _, d := range descriptors {
		if d.Provider != "" {
			seen[d.Provider] = true
		}
	}
	providers := make([]string, 0, len(seen))
	for p := range seen {
		providers = append(providers, p)
	}
	sort.Strings(providers)
	return providers
}

func humanSince(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Until(t)
	future := d > 0
	if !future {
		d = -d
	}
	var span string
	switch {
	case d < time.Minute:
		span = fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		span = fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		span = fmt.Sprintf("%dh", int(d.Hours()))
	default:
		span = fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	if future {
		return "in " + span
	}
	return span + " ago"
}

func (app *App) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	var contentType string
	switch name {
	case "janus.css":
		contentType = "text/css; charset=utf-8"
	case "janus-logo.svg":
		contentType = "image/svg+xml"
	default:
		app.renderSafeFailure(w, r, http.StatusNotFound, "route_not_found", "Janus does not expose that route.", nil)
		return
	}
	data, err := uiStaticFS.ReadFile("ui/" + name)
	if err != nil {
		app.renderSafeFailure(w, r, http.StatusNotFound, "route_not_found", "Janus does not expose that route.", nil)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(data)
}

// applyVaultFilters narrows the descriptor list for GET / according to the
// filter bar (q, provider, state, view). Tiles keep global counts; only the
// card/list rendering shrinks. Action re-renders never pass filters.
func applyVaultFilters(data map[string]any, r *http.Request) {
	query := r.URL.Query()
	q := strings.ToLower(strings.TrimSpace(query.Get("q")))
	provider := strings.TrimSpace(query.Get("provider"))
	state := strings.TrimSpace(query.Get("state"))
	if view := query.Get("view"); view == "list" {
		data["View"] = "list"
	}
	descriptors, _ := data["Descriptors"].([]SecretDescriptor)
	filtered := make([]SecretDescriptor, 0, len(descriptors))
	for _, d := range descriptors {
		if provider != "" && d.Provider != provider {
			continue
		}
		lifecycle := DescriptorLifecycle(d)
		if state == "active" && lifecycle != LifecycleActive {
			continue
		}
		if state == "attention" && lifecycle == LifecycleActive {
			continue
		}
		if q != "" {
			haystack := strings.ToLower(d.ID + " " + d.DisplayName + " " + d.Owner + " " + d.Scope + " " + strings.Join(d.Tags, " "))
			if !strings.Contains(haystack, q) {
				continue
			}
		}
		filtered = append(filtered, d)
	}
	data["Descriptors"] = filtered
	data["Query"] = query.Get("q")
	data["FilterProvider"] = provider
	data["FilterState"] = state
}

var secretNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

var (
	slugInvalidChars = regexp.MustCompile(`[^a-z0-9-]+`)
	slugDashRuns     = regexp.MustCompile(`-{2,}`)
)

// normalizeSlug turns free-form input into a usable name part instead of
// rejecting it: "Home Assistant" → "home-assistant".
func normalizeSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "_", "-")
	s = slugInvalidChars.ReplaceAllString(s, "")
	s = slugDashRuns.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

// NewSecretPlan is the guided "server needs a new secret" flow: Janus never
// touches the value — it generates the declarative steps (1Password → agenix
// → nixcfg wiring → catalog descriptor) as copy-paste artifacts.
type NewSecretPlan struct {
	Name           string
	DisplayName    string
	Host           string
	Service        string
	NormalizedNote string
	Classification string
	RotationDays   int
	Tags           []string
	Problems       []string
	AgenixEdit     string
	SecretsNix     string
	HostNix        string
	Compose        string
	Catalog        string
}

func newSecretPlanFromQuery(query url.Values) *NewSecretPlan {
	rawService := strings.TrimSpace(query.Get("service"))
	if rawService == "" {
		return nil
	}
	rawHost := strings.TrimSpace(query.Get("host"))
	service := normalizeSlug(rawService)
	host := normalizeSlug(rawHost)
	if host == "" {
		host = "csb1"
	}
	if service == "" {
		return &NewSecretPlan{
			Service:  rawService,
			Host:     host,
			Problems: []string{"could not derive a usable name from '" + rawService + "' — use letters, digits, spaces, or dashes."},
		}
	}
	var normalizedNote string
	if service != rawService || (rawHost != "" && host != rawHost) {
		normalizedNote = rawService
		if rawHost != "" && host != rawHost {
			normalizedNote = rawService + " @ " + rawHost
		}
		normalizedNote += " → " + host + "-" + service + "-env"
	}
	classification := query.Get("classification")
	switch classification {
	case "medium", "high", "critical":
	default:
		classification = "high"
	}
	rotation, err := strconv.Atoi(query.Get("rotation"))
	if err != nil || rotation < 1 || rotation > 3650 {
		rotation = 180
	}
	display := strings.TrimSpace(query.Get("display"))
	if display == "" {
		display = strings.ToUpper(service[:1]) + service[1:] + " environment"
	}
	var tags []string
	for _, tag := range strings.Split(query.Get("tags"), ",") {
		if tag = strings.ToLower(strings.TrimSpace(tag)); tag != "" {
			tags = append(tags, tag)
		}
	}
	if len(tags) == 0 {
		tags = []string{service}
	}
	plan := &NewSecretPlan{
		Name:           host + "-" + service + "-env",
		DisplayName:    display,
		Host:           host,
		Service:        service,
		NormalizedNote: normalizedNote,
		Classification: classification,
		RotationDays:   rotation,
		Tags:           tags,
	}
	if !secretNamePattern.MatchString(plan.Name) {
		plan.Problems = append(plan.Problems, "service and host must be lowercase letters, digits, or dashes — the derived name '"+plan.Name+"' is not usable yet.")
		return plan
	}
	tagList := `"` + strings.Join(plan.Tags, `", "`) + `"`
	plan.AgenixEdit = fmt.Sprintf(`cd ~/Code/nixcfg
agenix -e secrets/%s.age
# paste KEY=VALUE lines — take the values from 1Password (canonical store)`, plan.Name)
	plan.SecretsNix = fmt.Sprintf(`  # %s env for %s.
  # Format: KEY=VALUE lines
  # Edit: agenix -e secrets/%s.age
  "%s.age".publicKeys = markus ++ %s;`, plan.Service, plan.Host, plan.Name, plan.Name, plan.Host)
	plan.HostNix = fmt.Sprintf(`  age.secrets.%s = {
    file = ../../secrets/%s.age;
    path = "/run/agenix/%s";
  };`, plan.Name, plan.Name, plan.Name)
	plan.Compose = fmt.Sprintf(`  %s:
    # ...
    env_file:
      - /run/agenix/%s`, plan.Service, plan.Name)
	plan.Catalog = fmt.Sprintf(` {
  "id": "%s",
  "display_name": "%s",
  "provider": "agenix",
  "classification": "%s",
  "owner": "platform",
  "scope": "%s",
  "source": "secrets/%s.age",
  "rotation_days": %d,
  "lifecycle": "active",
  "status": "managed",
  "use_enabled": true,
  "consumer_count": 1,
  "egress_mode": "none",
  "tags": [%s]
 }`, plan.Name, plan.DisplayName, plan.Classification, plan.Host, plan.Name, plan.RotationDays, tagList)
	return plan
}

// newSecretScript renders the plan as an executable, additive-only,
// idempotent bash script (JANUS-273). It performs the repo edits that are
// safe to automate and prints the ones that are not; the secret VALUE never
// appears — encrypting it stays a human step (agenix -e).
func newSecretScript(plan *NewSecretPlan) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
# janus apply-plan for %[1]s — generated by the Janus vault (JANUS-273).
# Run from the root of your nixcfg checkout. Additive and idempotent; review
# with git diff afterwards. The secret VALUE is never part of this file.
set -euo pipefail

NAME=%[1]s
HOST=%[2]s

if [ ! -f secrets/secrets.nix ] || [ ! -d "hosts/$HOST" ]; then
  echo "error: run this from the nixcfg repo root (needs secrets/secrets.nix and hosts/$HOST)" >&2
  exit 1
fi

# --- 1) recipients in secrets/secrets.nix ------------------------------------
if grep -q "\"$NAME.age\"" secrets/secrets.nix; then
  echo "= secrets/secrets.nix already declares $NAME.age"
else
  python3 - secrets/secrets.nix <<'PY'
import sys
path = sys.argv[1]
lines = open(path).read().splitlines(keepends=True)
block = '''
  # %[3]s env for %[2]s.
  # Format: KEY=VALUE lines
  # Edit: agenix -e secrets/%[1]s.age
  "%[1]s.age".publicKeys = markus ++ %[2]s;
'''
for i in range(len(lines) - 1, -1, -1):
    if lines[i].strip() == '}':
        lines.insert(i, block)
        break
else:
    sys.exit('could not find a closing brace in ' + path)
open(path, 'w').write(''.join(lines))
PY
  echo "+ secrets/secrets.nix: recipients declared for $NAME.age"
fi

# --- 2) materialization in hosts/$HOST/configuration.nix ---------------------
CONF="hosts/$HOST/configuration.nix"
if grep -q "age.secrets.$NAME" "$CONF"; then
  echo "= $CONF already wires $NAME"
else
  python3 - "$CONF" <<'PY'
import sys
path = sys.argv[1]
lines = open(path).read().splitlines(keepends=True)
block = '''
  age.secrets.%[1]s = {
    file = ../../secrets/%[1]s.age;
    path = "/run/agenix/%[1]s";
  };
'''
for i in range(len(lines) - 1, -1, -1):
    if lines[i].strip() == '}':
        lines.insert(i, block)
        break
else:
    sys.exit('could not find a closing brace in ' + path)
open(path, 'w').write(''.join(lines))
PY
  echo "+ $CONF: age.secrets.$NAME wired"
fi

# --- 3) janus catalog descriptor ---------------------------------------------
CATALOG="hosts/$HOST/docker/janus/catalog/agenix-catalog.json"
if [ ! -f "$CATALOG" ]; then
  echo "! no janus catalog at $CATALOG — skipped (this host runs no janus)"
else
  python3 - "$CATALOG" <<'PY'
import json, sys
path = sys.argv[1]
data = json.load(open(path))
if any(d.get('id') == '%[1]s' for d in data):
    print('= catalog already lists %[1]s')
else:
    data.append(json.loads('''%[4]s'''))
    open(path, 'w').write(json.dumps(data, indent=1) + '\n')
    print('+ catalog: descriptor added for %[1]s')
PY
fi

# --- what stays human ---------------------------------------------------------
cat <<'HUMAN'

next steps (manual, in order):
1) point the service at the secret in hosts/%[2]s/docker/docker-compose.yml:
%[5]s

2) encrypt the value — human-only, take it from 1Password (canonical store):
   agenix -e secrets/%[1]s.age

3) review and commit:
   git diff
4) deploy the host as usual, then recreate the janus container so it reloads
   the catalog. The secret appears in the Vault with rotation tracking.
HUMAN
git status --short || true
`, plan.Name, plan.Host, plan.Service, plan.Catalog, plan.Compose)
}

func (app *App) handleNewSecretScript(w http.ResponseWriter, r *http.Request) {
	plan := newSecretPlanFromQuery(r.URL.Query())
	if plan == nil || len(plan.Problems) > 0 {
		app.audit(r, "vault.new.plan", "denied", actorFromContext(r.Context()), "invalid plan")
		app.renderSafeFailure(w, r, http.StatusBadRequest, "plan_invalid", "The plan parameters are incomplete or unusable; generate the plan in the vault first.", nil)
		return
	}
	app.audit(r, "vault.new.plan", "allowed", actorFromContext(r.Context()), "")
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=janus-plan-"+plan.Name+".sh")
	_, _ = w.Write([]byte(newSecretScript(plan)))
}

func (app *App) handleNewSecretPage(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "vault.new.view", "allowed", actorFromContext(r.Context()), "")
	session := currentSession(r.Context())
	data := app.dashboardData(r, session, nil, "")
	data["ActivePage"] = "vault"
	data["Plan"] = newSecretPlanFromQuery(r.URL.Query())
	renderTemplate(w, app.templates, "new_secret_page", data)
}

func (app *App) handleAccessPage(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "access.view", "allowed", actorFromContext(r.Context()), "")
	session := currentSession(r.Context())
	data := app.dashboardData(r, session, nil, "")
	data["ActivePage"] = "access"
	renderTemplate(w, app.templates, "access_page", data)
}

func splitPermits(permits []Permit, now time.Time) (pending, past []Permit) {
	for _, p := range permits {
		if p.ExpiresAt.After(now) {
			pending = append(pending, p)
		} else {
			past = append(past, p)
		}
	}
	return pending, past
}

func (app *App) handleRequestsPage(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "requests.view", "allowed", actorFromContext(r.Context()), "")
	session := currentSession(r.Context())
	data := app.dashboardData(r, session, nil, "")
	data["ActivePage"] = "requests"
	permits, _ := data["Permits"].([]Permit)
	pending, past := splitPermits(permits, time.Now().UTC())
	data["PendingPermits"] = pending
	data["PastPermits"] = past
	renderTemplate(w, app.templates, "requests_page", data)
}

func (app *App) handleLedgerPage(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "ledger.view", "allowed", actorFromContext(r.Context()), "")
	session := currentSession(r.Context())
	data := app.dashboardData(r, session, nil, "")
	data["ActivePage"] = "ledger"
	if canView, _ := data["CanViewAudit"].(bool); canView {
		data["Audit"] = app.store.RecentAudit(50)
	}
	renderTemplate(w, app.templates, "ledger_page", data)
}

func (app *App) handleAssurancePage(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "assurance.view", "allowed", actorFromContext(r.Context()), "")
	session := currentSession(r.Context())
	data := app.dashboardData(r, session, nil, "")
	data["ActivePage"] = "assurance"
	renderTemplate(w, app.templates, "assurance_page", data)
}
