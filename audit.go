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
	Entries        int       `json:"entries"`
	ChainedEntries int       `json:"chained_entries"`
	LegacyEntries  int       `json:"legacy_entries"`
	ChainVerified  bool      `json:"chain_verified"`
	LastHash       string    `json:"last_hash,omitempty"`
	LastEventAt    time.Time `json:"last_event_at,omitempty"`
	SinkWritable   bool      `json:"sink_writable"`
}

func (s *Store) AppendAudit(entry AuditEntry) {
	entry.Time = time.Now().UTC()

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
	for _, entry := range entries {
		if !entry.Time.IsZero() {
			posture.LastEventAt = entry.Time
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
