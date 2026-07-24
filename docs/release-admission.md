# Trusted release admission

Production and enterprise Janus runtimes accept secret-bearing work only after
an external deployment admission step verifies the exact engine artifact. The
artifact does not verify itself: deployment automation verifies registry and
GitHub evidence, then mounts a policy-bound receipt read-only for runtime
enforcement and health reporting.

## Trust boundary

The versioned policy is [`config/release-channels/v1.json`](../config/release-channels/v1.json).
It owns the allowed image, tag prefix, source repository, signer workflow,
certificate identity prefix, OIDC issuer, provenance predicate, SBOM predicate,
required product modes, and revoked digests. Policy changes are normal reviewed
repository changes and increment `policy_version` when their meaning changes.

Admission runs outside the image being admitted:

```bash
JANUS_ENGINE_RELEASE_TAG="rust-engine-v0.1.11" # replace with the reviewed release
scripts/admit-engine-release.sh \
  --policy config/release-channels/v1.json \
  --channel stable \
  --mode enterprise \
  --previous-mode enterprise \
  --image ghcr.io/markus-barta/janus/janus-engine \
  --tag "${JANUS_ENGINE_RELEASE_TAG}" \
  --digest sha256:... \
  --output /run/janus/release-admission.json
```

The script verifies the exact digest with cosign, verifies GitHub provenance
and SPDX SBOM attestations against the policy, rejects development tags and
revoked digests, and writes the receipt atomically with read-only permissions.
The deployment layer must supply the digest independently to the runtime; a
receipt cannot authorize a different configured digest.

The release also carries `source-release.json` and
`source-release.sigstore.json`. The first deterministically binds the released
repository, tag, commit, workflow, image name, and exact image digest; the
second is its keyless GitHub OIDC Sigstore bundle. Release CI verifies the exact
issuer and workflow identity before publishing either asset. This policy covers
`rust-engine-v*` and `go-envelope-v*` releases, not every development commit or
merge. The exact `2026-07-22T14:00:17Z` cutoff and sole admissible unsigned
pre-policy release—`go-envelope-v1.162` at its exact tag, commit, and publication
time—are machine-checked against Git and GitHub. Earlier Go and Rust releases
remain published history but are superseded and outside the admissible policy;
date-only grandfathering is invalid. If GitHub workflow identity changes,
release signing pauses until the versioned source-signing policy is reviewed;
otherwise recovery reruns the unchanged tag and commit.

## Runtime configuration

Set these variables for `janus-warden`, `janusd-use`, `janusd-admin`, and
`janusd-web-transactiond`:

| Variable | Meaning |
| --- | --- |
| `JANUS_PRODUCT_MODE` | `dev`, `self_hosted`, `production`, or `enterprise` |
| `JANUS_RELEASE_CHANNEL_POLICY` | Read-only versioned policy path |
| `JANUS_RELEASE_ADMISSION_RECEIPT` | Read-only externally generated receipt path |
| `JANUS_RELEASE_ARTIFACT_DIGEST` | Independently configured `sha256:` image digest |
| `JANUS_RELEASE_AUDIT_FILE` | Durable JSONL release-admission audit path |
| `JANUS_RELEASE_EXECUTOR` | Optional audit principal id; defaults to the runtime |
| `JANUS_SCOPE_ORGANIZATION` | Required organization scope component |
| `JANUS_SCOPE_PROJECT` | Required project scope component |
| `JANUS_SCOPE_REPOSITORY` | Required repository scope component |
| `JANUS_SCOPE_ENVIRONMENT` | Required environment scope component |
| `JANUS_SCOPE_NAMESPACE` | Optional namespace scope component |
| `JANUS_SCOPE_WORKLOAD` | Optional workload component; requires namespace |

Set `JANUS_RUNTIME_AUDIT_FILE` to a private durable JSONL path for process-plane
denials. If the configured sink cannot be opened or persisted, a cross-plane
request remains denied with `audit_sink_unavailable`; Janus never falls through
to the requested command.

`self_hosted` is the default and reports `not_required` when no release
evidence is configured. `production` and `enterprise` fail closed before
backend or secret-bearing runtime initialization if evidence or durable audit
is missing, malformed, writable by group/world, symlinked, mismatched,
untrusted, revoked, or from a development channel. A policy cannot silently
remove the production or enterprise admission requirement. A receipt also
binds `previous_mode`, preventing an enterprise-to-production downgrade from
reusing stronger-mode evidence.

Warden `health` returns the mode, requirement flag, decision, reason code,
policy id/version, channel, and digest-pinned artifact id. Admission audit
events use the same safe identifiers and never contain registry credentials,
tokens, attestation payloads, or secret values.

## CI and incident response

`scripts/test-release-admission.sh` exercises trusted and rejected fixtures
with mocked cryptographic commands. Release CI performs real verification and
publishes the resulting receipt beside the engine release assets.

To revoke an artifact, add its exact digest to `revoked_digests`, increment the
policy version, review and deploy the policy, and regenerate admission receipts
for allowed artifacts. Existing receipts then fail policy-version or revocation
checks at the next runtime start.
