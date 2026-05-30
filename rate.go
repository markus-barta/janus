package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type RateLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	limit   int
	buckets map[string]rateBucket
}

type rateBucket struct {
	Start time.Time
	Count int
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		window:  window,
		limit:   limit,
		buckets: make(map[string]rateBucket),
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	if rl == nil || rl.limit <= 0 {
		return true
	}

	now := time.Now().UTC()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket := rl.buckets[key]
	if bucket.Start.IsZero() || now.Sub(bucket.Start) > rl.window {
		rl.buckets[key] = rateBucket{Start: now, Count: 1}
		return true
	}
	if bucket.Count >= rl.limit {
		return false
	}
	bucket.Count++
	rl.buckets[key] = bucket
	return true
}

func clientKey(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("Cf-Connecting-Ip")); ip != "" {
		return ip
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		if i := strings.IndexByte(forwarded, ','); i >= 0 {
			return strings.TrimSpace(forwarded[:i])
		}
		return forwarded
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}
