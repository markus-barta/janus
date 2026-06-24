# nixcfg cutover — repoint the live deploy at the published image

**Status: STAGED, not yet applied.** The Go envelope source was extracted from
`nixcfg/hosts/csb1/docker/janus` into this repo (`go-envelope/`, full history via
`git subtree split`, 2026-06-24). The live `vault.barta.cm` deploy still builds
from the local source in nixcfg. This file is the **ready-to-apply** cutover for
the implementation session.

> ⚠️ **Do not `git rm` the Go source from nixcfg until the published image
> exists and is verified.** Removing it first breaks the live `build:` deploy.
> The steps below are strictly ordered for that reason.

## Prerequisites (one-time)

1. ✅ **Done:** repo published at `github.com/markus-barta/janus` (public, AGPL-3.0).
   The `agenix-catalog.json` infra inventory was scrubbed from history — it stays
   nixcfg-only deploy data, mounted at runtime.
2. Push triggers `.github/workflows/go-envelope.yml` `build-test`. Confirm green.

## Step 1 — publish a signed envelope image

Cut a GitHub Release whose tag matches `go-envelope-v*` (mirror the live build
marker, e.g. `go-envelope-v1.144`):

```bash
cd ~/Code/janus
git tag go-envelope-v1.144      # match current x-janus-build / latest *.go state
git push origin go-envelope-v1.144
gh release create go-envelope-v1.144 --title "Go envelope v1.144" --notes "Extracted-as-is envelope; first signed image."
```

The `image` job builds `ghcr.io/<owner>/janus/janus-envelope`, **cosign-signs it
keyless**, attaches an **SPDX SBOM**, and pushes a **build-provenance
attestation**. Capture the published digest:

```bash
DIGEST=$(gh release view go-envelope-v1.144 --json ... )   # or read from the run log / ghcr
# verify before trusting it:
cosign verify ghcr.io/<owner>/janus/janus-envelope@${DIGEST} \
  --certificate-identity-regexp '.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/<owner>/janus/janus-envelope@${DIGEST} --owner <owner>
```

## Step 2 — repoint nixcfg docker-compose at the image

In `nixcfg/hosts/csb1/docker/docker-compose.yml`, the `janus:` service — replace
the `build:` block with a digest-pinned `image:` (everything else unchanged):

```diff
   janus:
-    build:
-      context: ./janus
-      args:
-        JANUS_BUILD_COMMIT: ${JANUS_BUILD_COMMIT:-unknown}
-        JANUS_BUILD_TIME: ${JANUS_BUILD_TIME:-unknown}
+    # source now lives in github.com/<owner>/janus (go-envelope/); image is
+    # cosign-signed + SBOM + provenance. Pin by digest for supply-chain trust.
+    image: ghcr.io/<owner>/janus/janus-envelope:go-envelope-v1.144@sha256:<DIGEST>
     container_name: janus
     restart: unless-stopped
     environment:
       - JANUS_PUBLIC_URL=https://vault.barta.cm
       ...
     env_file:
       - /run/agenix/csb1-janus-env
     volumes:
       - janus_data:/data
       - ./janus/catalog:/catalog:ro     # KEEP — runtime catalog stays in nixcfg
```

**Keep `./janus/catalog/`** in nixcfg: it is deploy-time runtime data (mounted
read-only, edited by FLEET tickets), not application source. Only the source is
removed in step 3.

## Step 3 — remove the source from nixcfg (catalog stays)

```bash
cd ~/Code/nixcfg/hosts/csb1/docker/janus
git rm $(git ls-files | grep -v '^catalog/')    # *.go, Dockerfile, go.mod/sum, bootstrap, .dockerignore, .gitignore
# result: hosts/csb1/docker/janus/ now contains only catalog/
git commit -m "janus: source extracted to github.com/<owner>/janus; deploy via signed ghcr image"
```

## Step 4 — redeploy + verify (must match pre-cutover)

```bash
# on csb1 (or via the existing deploy path):
docker compose -f hosts/csb1/docker/docker-compose.yml pull janus
docker compose -f hosts/csb1/docker/docker-compose.yml up -d janus

curl -s https://vault.barta.cm/healthz                 # {"status":"ok","mode":"self_hosted",...}
curl -sI https://vault.barta.cm | grep -i x-janus-build # build-commit should map to the tagged source
```

## Step 5 — update the three homes

- PPM `guideline/where-janus-lives`: change "Shipped code" row to point at the new
  repo; note the deploy is now a signed image, not a local build.
- PPM `guideline/architecture-v1` §0: update the reconciliation note location.
- `inspr/modules/janus/readme.md`: update the code pointer.

## Rollback

The `build:` block is in git history; `git revert` the compose commit and
`docker compose up -d --build janus` rebuilds from the (still-present in history)
local source. Keep one published image generation before deleting any nixcfg
history.
