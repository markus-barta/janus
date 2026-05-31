package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
	"time"
)

type AuditPosture struct {
	Entries              int                  `json:"entries"`
	ChainedEntries       int                  `json:"chained_entries"`
	LegacyEntries        int                  `json:"legacy_entries"`
	ChainVerified        bool                 `json:"chain_verified"`
	LastHash             string               `json:"last_hash,omitempty"`
	LastEventAt          time.Time            `json:"last_event_at,omitempty"`
	SinkWritable         bool                 `json:"sink_writable"`
	SeverityCounts       []AuditSeverityCount `json:"severity_counts"`
	WarningCount         int                  `json:"warning_count"`
	CriticalCount        int                  `json:"critical_count"`
	UnknownSeverityCount int                  `json:"unknown_severity_count"`
}

type AuditSeverityCount struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type AuditTrailWitness struct {
	EntryCount                 int             `json:"entry_count"`
	VisibleCount               int             `json:"visible_count"`
	ChainState                 string          `json:"chain_state"`
	ChainTone                  string          `json:"chain_tone"`
	Summary                    string          `json:"summary"`
	LastHashShort              string          `json:"last_hash_short"`
	Rows                       []AuditTrailRow `json:"rows"`
	ChronologicalHistory       bool            `json:"chronological_history"`
	ReceiptHashLinkage         bool            `json:"receipt_hash_linkage"`
	RawPathReturned            bool            `json:"raw_path_returned"`
	RawReasonReturned          bool            `json:"raw_reason_returned"`
	SubjectReturned            bool            `json:"subject_returned"`
	EmailReturned              bool            `json:"email_returned"`
	NameReturned               bool            `json:"name_returned"`
	GroupClaimReturned         bool            `json:"group_claim_returned"`
	TokenReturned              bool            `json:"token_returned"`
	CookieValueReturned        bool            `json:"cookie_value_returned"`
	RequestBodyReturned        bool            `json:"request_body_returned"`
	EnvReturned                bool            `json:"env_returned"`
	BackendPathReturned        bool            `json:"backend_path_returned"`
	SourcePathReturned         bool            `json:"source_path_returned"`
	ConnectorOutputReturned    bool            `json:"connector_output_returned"`
	PermitPayloadValueReturned bool            `json:"permit_payload_value_returned"`
	SecretValueReturned        bool            `json:"secret_value_returned"`
	ValueReturned              bool            `json:"value_returned"`
}

type AuditTrailRow struct {
	Step           int    `json:"step"`
	TimeLabel      string `json:"time_label"`
	Severity       string `json:"severity"`
	SeverityTone   string `json:"severity_tone"`
	Action         string `json:"action"`
	Outcome        string `json:"outcome"`
	OutcomeTone    string `json:"outcome_tone"`
	Channel        string `json:"channel"`
	Scope          string `json:"scope"`
	ReasonClass    string `json:"reason_class"`
	RequestID      string `json:"request_id"`
	EventHashShort string `json:"event_hash_short"`
	PrevHashShort  string `json:"prev_hash_short"`
	ChainLink      string `json:"chain_link"`
	HashLocked     bool   `json:"hash_locked"`
}

func (s *Store) AppendAudit(entry AuditEntry) (AuditEntry, bool) {
	entry.Time = time.Now().UTC()
	entry.Severity = normalizeAuditSeverity(entry.Severity)
	if entry.Severity == "" {
		entry.Severity = auditSeverityFor(entry.Action, entry.Outcome, entry.Reason)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry.PrevHash = s.lastAuditHashLocked()
	entry.EventHash = hashAuditEntry(entry)

	f, err := os.OpenFile(s.auditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("audit open failed: %v", err)
		return entry, false
	}
	defer f.Close()

	raw, err := json.Marshal(entry)
	if err != nil {
		log.Printf("audit encode failed: %v", err)
		return entry, false
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		log.Printf("audit write failed: %v", err)
		return entry, false
	}
	if err := f.Sync(); err != nil {
		log.Printf("audit sync failed: %v", err)
		return entry, false
	}
	return entry, true
}

func (s *Store) RecentAudit(limit int) []AuditEntry {
	if limit <= 0 || limit > 100 {
		limit = 25
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := s.readAuditLocked()
	if len(entries) <= limit {
		return entries
	}
	return entries[len(entries)-limit:]
}

func (s *Store) AuditPosture() AuditPosture {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := s.readAuditLocked()
	posture := AuditPosture{
		Entries:       len(entries),
		ChainVerified: true,
		SinkWritable:  s.auditSinkWritableLocked(),
	}

	var prev string
	severities := map[string]int{}
	for _, entry := range entries {
		if !entry.Time.IsZero() {
			posture.LastEventAt = entry.Time
		}
		severity := strings.ToLower(strings.TrimSpace(entry.Severity))
		if severity == "" {
			severity = "unknown"
			posture.UnknownSeverityCount++
		}
		severities[severity]++
		if severity == "warning" {
			posture.WarningCount++
		}
		if severity == "critical" {
			posture.CriticalCount++
		}
		if entry.EventHash == "" {
			posture.LegacyEntries++
			continue
		}
		posture.ChainedEntries++
		want := hashAuditEntry(entry)
		if entry.EventHash != want || entry.PrevHash != prev {
			posture.ChainVerified = false
		}
		prev = entry.EventHash
		posture.LastHash = entry.EventHash
	}
	posture.SeverityCounts = auditSeverityCounts(severities)
	return posture
}

func (s *Store) readAuditLocked() []AuditEntry {
	file, err := os.Open(s.auditFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return nil
	}
	defer file.Close()

	var entries []AuditEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries
}

func (s *Store) lastAuditHashLocked() string {
	entries := s.readAuditLocked()
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].EventHash != "" {
			return entries[i].EventHash
		}
	}
	return ""
}

func (s *Store) auditSinkWritableLocked() bool {
	f, err := os.OpenFile(s.auditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func hashAuditEntry(entry AuditEntry) string {
	entry.EventHash = ""
	raw, _ := json.Marshal(entry)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func normalizeAuditSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "info", "notice", "warning", "critical":
		return strings.ToLower(strings.TrimSpace(severity))
	default:
		return ""
	}
}

func auditSeverityFor(action, outcome, reason string) string {
	action = strings.ToLower(strings.TrimSpace(action))
	outcome = strings.ToLower(strings.TrimSpace(outcome))
	reason = strings.ToLower(strings.TrimSpace(reason))
	if outcome == "denied" || strings.Contains(outcome, "failed") || strings.Contains(reason, "failed") {
		return "warning"
	}
	if strings.Contains(action, "permit.") || strings.Contains(action, "warden.resolve") || strings.HasPrefix(action, "evidence.") || strings.Contains(action, ".evidence.") {
		return "notice"
	}
	return "info"
}

func auditSeverityCounts(counts map[string]int) []AuditSeverityCount {
	order := []string{"critical", "warning", "notice", "info", "unknown"}
	out := make([]AuditSeverityCount, 0, len(counts))
	for _, severity := range order {
		if count := counts[severity]; count > 0 {
			out = append(out, AuditSeverityCount{Severity: severity, Count: count})
		}
	}
	return out
}

func AuditTrailFor(entries []AuditEntry, posture AuditPosture, canView bool) AuditTrailWitness {
	entryCount := posture.Entries
	if entryCount == 0 && len(entries) > 0 {
		entryCount = len(entries)
	}
	trail := AuditTrailWitness{
		EntryCount:           entryCount,
		ChainState:           "restricted",
		ChainTone:            "warn",
		Summary:              "Auditor role required before recent audit rows or hash receipts are rendered.",
		LastHashShort:        "restricted",
		ChronologicalHistory: true,
		ReceiptHashLinkage:   true,
		ValueReturned:        false,
	}
	if !canView {
		return trail
	}

	trail.ChainState = "verified"
	trail.ChainTone = "ok"
	trail.Summary = "Recent audit events are shown as safe labels with request ids and hash links."
	trail.LastHashShort = shortAuditHash(posture.LastHash, "pending")
	if !posture.ChainVerified {
		trail.ChainState = "review"
		trail.ChainTone = "warn"
		trail.Summary = "Recent audit events are visible, but the local hash chain needs review."
	}
	if posture.LegacyEntries > 0 {
		trail.ChainState = "partial"
		trail.ChainTone = "warn"
		trail.Summary = "Recent audit events are visible; older legacy events still need hash-chain migration."
	}
	if !posture.SinkWritable {
		trail.ChainState = "sink blocked"
		trail.ChainTone = "warn"
		trail.Summary = "Audit storage is not writable, so stronger audit claims are blocked."
	}
	if len(entries) == 0 && trail.ChainTone != "warn" {
		trail.Summary = "Audit sink is ready; no recent action rows are present yet."
	}

	for i, entry := range entries {
		trail.Rows = append(trail.Rows, auditTrailRow(entry, i+1))
	}
	trail.VisibleCount = len(trail.Rows)
	return trail
}

func auditTrailRow(entry AuditEntry, step int) AuditTrailRow {
	timeLabel := "pending"
	if !entry.Time.IsZero() {
		timeLabel = entry.Time.UTC().Format("15:04:05")
	}
	severity := strings.ToLower(strings.TrimSpace(entry.Severity))
	if severity == "" {
		severity = "unknown"
	}
	requestID := strings.TrimSpace(entry.RequestID)
	if requestID == "" {
		requestID = "generated"
	}
	scope := strings.TrimSpace(entry.SecretRef)
	if scope == "" {
		scope = "none"
	}
	eventHash := shortAuditHash(entry.EventHash, "legacy")
	prevHash := shortAuditHash(entry.PrevHash, "genesis")
	return AuditTrailRow{
		Step:           step,
		TimeLabel:      timeLabel,
		Severity:       severity,
		SeverityTone:   auditSeverityTone(severity),
		Action:         safeAuditToken(entry.Action, "event"),
		Outcome:        safeAuditToken(entry.Outcome, "recorded"),
		OutcomeTone:    auditOutcomeTone(entry.Outcome),
		Channel:        auditChannelLabel(entry.Method, entry.Path),
		Scope:          scope,
		ReasonClass:    auditReasonClass(entry),
		RequestID:      requestID,
		EventHashShort: eventHash,
		PrevHashShort:  prevHash,
		ChainLink:      prevHash + " -> " + eventHash,
		HashLocked:     entry.EventHash != "",
	}
}

func shortAuditHash(hash, fallback string) string {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return fallback
	}
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

func safeAuditToken(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func auditSeverityTone(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "warning", "unknown":
		return "warn"
	default:
		return "info"
	}
}

func auditOutcomeTone(outcome string) string {
	outcome = strings.ToLower(strings.TrimSpace(outcome))
	if outcome == "allowed" || strings.HasPrefix(outcome, "approved") {
		return "ok"
	}
	if outcome == "denied" || strings.Contains(outcome, "failed") {
		return "warn"
	}
	return "info"
}

func auditChannelLabel(method, path string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "EVENT"
	}
	path = strings.TrimSpace(path)
	channel := "http route"
	switch {
	case path == "":
		channel = "internal event"
	case path == "/":
		channel = "dashboard view"
	case path == "/login" || path == "/logout" || strings.HasPrefix(path, "/oidc/"):
		channel = "auth flow"
	case strings.HasPrefix(path, "/ui/"):
		channel = "browser action"
	case strings.HasPrefix(path, "/api/evidence"):
		channel = "evidence api"
	case strings.HasPrefix(path, "/api/audit"):
		channel = "audit api"
	case strings.HasPrefix(path, "/api/permits"):
		channel = "permit api"
	case strings.HasPrefix(path, "/api/warden"):
		channel = "warden api"
	case strings.HasPrefix(path, "/api/"):
		channel = "api request"
	}
	return method + " " + channel
}

func auditReasonClass(entry AuditEntry) string {
	reason := strings.ToLower(strings.TrimSpace(entry.Reason))
	outcome := strings.ToLower(strings.TrimSpace(entry.Outcome))
	action := strings.ToLower(strings.TrimSpace(entry.Action))
	switch {
	case strings.Contains(reason, "csrf"):
		return "csrf_guard"
	case strings.Contains(reason, "system degraded") || strings.Contains(reason, "readiness"):
		return "readiness_guard"
	case strings.Contains(reason, "role") && strings.Contains(reason, "required"):
		return "role_guard"
	case strings.Contains(reason, "auth") || strings.Contains(action, "auth."):
		return "auth_guard"
	case strings.Contains(reason, "not found"):
		return "lookup_guard"
	case strings.Contains(reason, "broker"):
		return "broker_guard"
	case strings.Contains(reason, "persistence") || strings.Contains(reason, "store"):
		return "persistence_guard"
	case strings.Contains(outcome, "not_executed") || (strings.Contains(action, "permit.run") && strings.Contains(reason, "no execution connector")):
		return "no_connector"
	case strings.Contains(outcome, "approved"):
		return "metadata_approved"
	case strings.Contains(reason, "no execution connector"):
		return "no_connector"
	case outcome == "denied" || strings.Contains(outcome, "failed"):
		return "denial_recorded"
	case outcome == "allowed":
		return "allowed_recorded"
	default:
		return "recorded"
	}
}
