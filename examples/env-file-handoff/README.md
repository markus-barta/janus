# Janus env-file handoff example

This bundle is the checked nonprod fixture for `janusd-use env-file` service
handoff. It is intentionally small and local: no host deploy, no network
service, no production path.

Files:
- `secretspec.toml`: one manifest-declared canary secret.
- `metadata.toml`: owner/class/lifecycle overlay. The canary is `break_glass`
  so the smoke exercises the approval-required path.
- `approved-use.env-file.toml.in`: reviewed env-file profile template.
- `consumer-contract.md`: named nonprod consumer contract for the fixture
  service.

Run it from the repo root:

```bash
devenv shell -- ./scripts/smoke-janusd-env-file.sh
```

The smoke renders the template into a disposable runtime, issues an approval,
preflights the target without a permit or secret read, issues a single-use
permit, writes a private env file, and verifies a tiny fixture service can
consume it without printing the secret literal.
