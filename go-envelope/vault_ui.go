package main

// JANUS-271: doorkeeper vault UI — first strangler slice. The embedded
// "dashboard" template (ui/vault.html) replaced the inline legacy page at /;
// the legacy console stays reachable at /legacy until the JANUS-269 cull.

import (
	"embed"
	"fmt"
	"net/http"
	"strings"
	"time"
)

//go:embed ui/janus.css ui/janus-logo.svg
var uiStaticFS embed.FS

//go:embed ui/vault.html
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

func (app *App) handleLegacyDashboard(w http.ResponseWriter, r *http.Request) {
	app.audit(r, "dashboard.view", "allowed", actorFromContext(r.Context()), "legacy console")
	session := currentSession(r.Context())
	renderTemplate(w, app.templates, "legacy_dashboard", app.dashboardData(r, session, nil, r.URL.Query().Get("ref")))
}
