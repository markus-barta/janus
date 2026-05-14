//! Bitwarden DTO → Janus-domain types.
//!
//! This is the seam that protects `janus-core` from leaking Bitwarden
//! concepts. **Keep it narrow.** If you find yourself adding a field to
//! [`janus_core::types`] solely to round-trip a Bitwarden field, stop
//! and reconsider — the Janus domain should describe what an LLM
//! consumer needs, not what Bitwarden happens to provide.
//!
//! TODO (architecture-v0):
//!   - `fn dto_to_overview(BwCipher) -> ItemOverview`
//!       * extract title, id
//!       * scan `fields[]` for the allowlist marker to set `allowlisted`
//!   - `fn dto_to_item(BwCipher) -> JanusItem`
//!       * map `login.password` / `login.username` / `notes` / etc. into
//!         `JanusField` with the correct `FieldKind`
//!       * pass custom fields through; the allowlist marker stays IN the
//!         field list (it is itself a `Text` field), so callers can
//!         re-verify
