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

func (s *Store) AppendAudit(entry AuditEntry) {
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
		return
	}
	defer f.Close()

	raw, err := json.Marshal(entry)
	if err != nil {
		log.Printf("audit encode failed: %v", err)
		return
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		log.Printf("audit write failed: %v", err)
		return
	}
	if err := f.Sync(); err != nil {
		log.Printf("audit sync failed: %v", err)
	}
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
	if strings.Contains(action, "permit.") || strings.Contains(action, "warden.resolve") || strings.HasPrefix(action, "evidence.") {
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
