#!/usr/bin/env bash
# Create or rotate the Janus OIDC web app in Zitadel and print a KEY=VALUE
# env file to stdout. Pipe stdout directly into age/agenix; logs go to stderr.

set -euo pipefail

ZITADEL_BASE="${ZITADEL_BASE:-https://auth.inspr.at}"
COMPOSE_DIR="${COMPOSE_DIR:-/home/mba/docker/inspr-at}"
PROJECT_NAME="${PROJECT_NAME:-Janus}"
APP_NAME="${APP_NAME:-janus-vault-barta-cm}"
REDIRECT_URI="${REDIRECT_URI:-https://vault.barta.cm/oidc/callback}"
POST_LOGOUT_URI="${POST_LOGOUT_URI:-https://vault.barta.cm/}"

log() { printf "[janus-zitadel] %s\n" "$*" >&2; }
die() {
  log "ERROR: $*"
  exit 1
}

require() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require curl
require jq
require python3

PAT_FILE="${COMPOSE_DIR}/.machinekey/pat.txt"
if [ ! -r "$PAT_FILE" ]; then
  die "Zitadel bootstrap PAT is not readable at ${PAT_FILE}"
fi

IFS= read -r PAT <"$PAT_FILE" || true
[ -n "$PAT" ] || die "Zitadel bootstrap PAT is empty"

AUTH=(-H "Authorization: Bearer $PAT" -H "Content-Type: application/json")

log "Waiting for ${ZITADEL_BASE}"
for i in $(seq 1 60); do
  if curl -fsS "${ZITADEL_BASE}/.well-known/openid-configuration" -o /dev/null; then
    break
  fi
  sleep 1
  [ "$i" = "60" ] && die "Zitadel not ready after 60s"
done

ORG_ME="$(curl -fsS "${AUTH[@]}" "${ZITADEL_BASE}/management/v1/orgs/me")"
ORG_ID="$(echo "$ORG_ME" | jq -r '.org.id')"
[ -n "$ORG_ID" ] && [ "$ORG_ID" != "null" ] || die "no Zitadel org found"
AUTH+=(-H "x-zitadel-orgid: $ORG_ID")
log "Using org id=${ORG_ID}"

PROJECTS="$(curl -fsS "${AUTH[@]}" "${ZITADEL_BASE}/management/v1/projects/_search" -d '{}')"
PROJECT_ID="$(echo "$PROJECTS" | jq -r --arg n "$PROJECT_NAME" '.result[]? | select(.name==$n) | .id' | head -1)"
if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" = "null" ]; then
  log "Creating project ${PROJECT_NAME}"
  PROJECT_ID="$(curl -fsS "${AUTH[@]}" -X POST "${ZITADEL_BASE}/management/v1/projects" \
    -d "$(jq -n --arg n "$PROJECT_NAME" '{
      name: $n,
      projectRoleAssertion: false,
      projectRoleCheck: false,
      hasProjectCheck: false,
      privateLabelingSetting: "PRIVATE_LABELING_SETTING_UNSPECIFIED"
    }')" | jq -r '.id')"
fi
[ -n "$PROJECT_ID" ] && [ "$PROJECT_ID" != "null" ] || die "project create failed"
log "Using project id=${PROJECT_ID}"

APP_PAYLOAD="$(jq -n \
  --arg n "$APP_NAME" \
  --arg ru "$REDIRECT_URI" \
  --arg pl "$POST_LOGOUT_URI" '{
    name: $n,
    redirectUris: [$ru],
    responseTypes: ["OIDC_RESPONSE_TYPE_CODE"],
    grantTypes: ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_REFRESH_TOKEN"],
    appType: "OIDC_APP_TYPE_WEB",
    authMethodType: "OIDC_AUTH_METHOD_TYPE_BASIC",
    postLogoutRedirectUris: [$pl],
    version: "OIDC_VERSION_1_0",
    devMode: false,
    accessTokenType: "OIDC_TOKEN_TYPE_BEARER",
    accessTokenRoleAssertion: false,
    idTokenRoleAssertion: false,
    idTokenUserinfoAssertion: true,
    clockSkew: "0s",
    additionalOrigins: []
  }')"

APPS="$(curl -fsS "${AUTH[@]}" "${ZITADEL_BASE}/management/v1/projects/${PROJECT_ID}/apps/_search" -d '{}')"
APP_ID="$(echo "$APPS" | jq -r --arg n "$APP_NAME" '.result[]? | select(.name==$n) | .id' | head -1)"
CLIENT_SECRET=""
if [ -z "$APP_ID" ] || [ "$APP_ID" = "null" ]; then
  log "Creating OIDC app ${APP_NAME}"
  APP_RESP="$(curl -fsS "${AUTH[@]}" -X POST "${ZITADEL_BASE}/management/v1/projects/${PROJECT_ID}/apps/oidc" -d "$APP_PAYLOAD")"
  APP_ID="$(echo "$APP_RESP" | jq -r '.appId')"
  CLIENT_ID="$(echo "$APP_RESP" | jq -r '.clientId')"
  CLIENT_SECRET="$(echo "$APP_RESP" | jq -r '.clientSecret')"
else
  log "Updating existing OIDC app ${APP_NAME} and rotating client secret"
  UPDATE_PAYLOAD="$(echo "$APP_PAYLOAD" | jq 'del(.name)')"
  UPDATE_CODE="$(curl -sS -o /tmp/janus-oidc-update.out -w '%{http_code}' "${AUTH[@]}" -X PUT \
    "${ZITADEL_BASE}/management/v1/projects/${PROJECT_ID}/apps/${APP_ID}/oidc_config" \
    -d "$UPDATE_PAYLOAD")"
  case "$UPDATE_CODE" in
  200 | 201 | 409) ;;
  400)
    if ! jq -e '.message? | test("No changes")' /tmp/janus-oidc-update.out >/dev/null 2>&1; then
      log "OIDC update returned HTTP 400"
      exit 1
    fi
    ;;
  *)
    log "OIDC update returned HTTP ${UPDATE_CODE}"
    exit 1
    ;;
  esac
  APP_DETAIL="$(curl -fsS "${AUTH[@]}" "${ZITADEL_BASE}/management/v1/projects/${PROJECT_ID}/apps/${APP_ID}")"
  CLIENT_ID="$(echo "$APP_DETAIL" | jq -r '.app.oidcConfig.clientId')"
  SECRET_RESP="$(curl -fsS "${AUTH[@]}" -X POST "${ZITADEL_BASE}/management/v1/projects/${PROJECT_ID}/apps/${APP_ID}/oidc_config/_generate_client_secret")"
  CLIENT_SECRET="$(echo "$SECRET_RESP" | jq -r '.clientSecret')"
fi

[ -n "$APP_ID" ] && [ "$APP_ID" != "null" ] || die "app create failed"
[ -n "$CLIENT_ID" ] && [ "$CLIENT_ID" != "null" ] || die "client id missing"
[ -n "$CLIENT_SECRET" ] && [ "$CLIENT_SECRET" != "null" ] || die "client secret missing"

COOKIE_KEY="$(
  python3 - <<'PY'
import base64
import secrets

print(base64.b64encode(secrets.token_bytes(32)).decode("ascii"))
PY
)"

log "Prepared env for app id=${APP_ID}; encrypt stdout immediately"
printf "OIDC_CLIENT_ID=%s\n" "$CLIENT_ID"
printf "OIDC_CLIENT_SECRET=%s\n" "$CLIENT_SECRET"
printf "COOKIE_KEY=%s\n" "$COOKIE_KEY"
