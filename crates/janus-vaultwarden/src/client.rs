//! Bitwarden REST client — auth, token refresh, transport.
//!
//! TODO (JANUS-1):
//!   - OAuth2 client_credentials flow against `/identity/connect/token`.
//!   - Bearer token cache with proactive refresh on 60s-to-expiry.
//!   - Retry policy: 1 immediate retry on 5xx, then jittered exponential
//!     backoff up to N=3.
//!   - Per-request timeout: 5s connect, 10s total.
//!   - No redirect following on auth endpoints.
