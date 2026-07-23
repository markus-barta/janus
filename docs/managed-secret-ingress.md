# Managed-service secret web ingress

JANUS-357 adds Janus's only human value-bearing web boundary. It is a
first-party browser flow for a Pharos-issued, signed, declaration-bound setup
intent. It does not add a value-bearing API, Warden method, Pharos method, CLI
argument, JSON request, or agent tool.

## Route and trust boundary

The three UI-only routes are:

- `GET /managed-service/setup?intent=intent_…` — inspect the signed intent and
  render value-free context.
- `POST /managed-service/setup/step-up` — require the authenticated
  `lifecycle.entry` permission, exact `Origin`, same-origin Fetch Metadata,
  strict CSRF, and a body containing only the CSRF token, intent reference, and
  one source selected from the intent's signed declaration policy.
- `POST /managed-service/setup/execute` — require the same controls plus a
  fresh signed step-up proof, consume the intent, and only then read the
  value-bearing field.

The setup intent is kept across an ordinary login in a short-lived signed,
HttpOnly, SameSite=Lax cookie. It contains only the opaque intent reference and
timestamps. The normal login flow clears a stale setup cookie.

All managed setup responses are `no-store, no-transform` with identity content
encoding. The global Janus boundary also supplies a no-script, no-third-party
CSP, `no-referrer`, framing isolation, and same-origin resource policy.

## Passwordless step-up

Step-up starts a new authorization-code + PKCE flow with a new state, nonce,
`prompt=login`, and `max_age=0`. The pre-step-up browser session is bound through
a signed flow cookie containing only the intent reference, selected source, a
one-way human session reference, the state hash, and timestamps.

Janus accepts the callback only when:

- the signed flow, OIDC state, nonce, PKCE, issuer, audience, token signature,
  subject, and current role mapping are valid;
- the new subject hashes to the same human-session reference;
- `auth_time` is no more than two minutes old, allowing only the reviewed clock
  skew; and
- the ZITADEL `amr` set is exactly `user` plus `mfa`.

ZITADEL's OIDC implementation maps a passwordless passkey to `user` + `mfa`.
A password with U2F also contains `pwd`, so exact matching prevents that flow
from satisfying this passwordless gate. See the
[ZITADEL claims reference](https://zitadel.com/docs/apis/openidoauth/claims) and
the [ZITADEL AMR mapping](https://github.com/zitadel/zitadel/blob/ca6595f8c59299d1aa971b06d098b839b4edd959/internal/api/oidc/amr.go).

The resulting proof is signed, HttpOnly, SameSite=Strict, bound to the exact
intent, selected source, and human-session reference, and expires no later than
two minutes after the asserted authentication time. Changing Generate to Paste
or Paste to Generate after step-up fails before any value byte is read. Logout
and clean auth reset clear all flow, proof, and managed-login cookies.

## Simple managed-service UI

Pharos is the entry point. Its service detail renders only reviewed declarations
and gives a missing slot one primary action: **Add missing secret**. The browser
does not provide editable host, service, slot, path, command, callback, or
source fields to Pharos. Pharos signs the slot's complete reviewed source
policy and sends only the opaque intent reference to Janus.

Janus re-resolves that declaration and renders the safe service and slot labels
with the host/service/slot authority locked. It offers Generate and/or Paste
only when present in the signed source policy. The chosen option is then bound
to the fresh passkey flow described above. The ordinary Vault presents managed
records as **Service secret** with consumer, host, lifecycle, age, rotation,
and health metadata; it never renders reveal or copy actions. `/vault/new` is
labelled **Advanced manual setup** and remains a configuration-only fallback.

## One-time value path

The browser submits a regular HTML form in this exact field order:

1. `csrf_token`
2. `intent_ref`
3. `source`
4. `secret_value`

Janus reads only the bounded value-free prefix first. It checks the exact
content type, fixed content length, absence of transfer/content encoding,
same-origin headers, CSRF token, signed step-up proof, session binding, intent
reference, and proof-bound source. It then durably consumes the signed setup
intent and replay nonce before reading the first value byte.

For import, the remaining `application/x-www-form-urlencoded` bytes are decoded
in place in one owned byte buffer. Extra fields and malformed escapes fail
closed. That buffer is passed once to the typed local Rust transaction client
and zeroized on every return path. Generated mode requires an empty value field
and passes no value bytes.

The UI uses a masked, single-line, bounded input with autocomplete, spellcheck,
capitalization, and common password-manager capture disabled. It has no reveal
or copy action and no script. Completion clears first-party browser cache and
storage without clearing the authenticated session.

## Retry and failure semantics

- A malformed or unauthenticated request cannot consume an intent or read the
  value field.
- Once the intent is consumed, any incomplete body, disconnect, timeout, or
  downstream failure intentionally burns that intent. This is a
  security-over-availability choice: recovery starts with a new Pharos intent
  so no retry can replay a value after Janus has admitted it into memory.
- Refresh, back, resubmit, and network retry can reach the consumer again, but
  replay storage prevents a second typed transaction or second import.
- Successful completion redirects with HTTP 303 to the configured Pharos
  operation URL. The URL contains only the opaque operation reference.
- Responses and audit contain controlled reason classes, request/operation/
  secret references where appropriate, and `value_returned=false`; they never
  contain the submitted bytes.

The client boundary admits signed `create` and `replace` operation kinds.
JANUS-362 supplies the staged replacement/rollback executor; the current Rust
catalog remains fail-closed for replacement until that reviewed executor is
installed. The Go transport test proves a downstream denial stops before the
value frame; the Rust catalog resolver test independently proves `replace` is
currently rejected as `web_transaction_request_invalid`.
