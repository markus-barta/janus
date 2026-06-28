# Fixture Service Consumer Contract

Consumer ref: `consumer.fixture_service`
Owner: `janusd-smoke`
Environment: `test`
Kind: `service`
Secret: `CANARY` via opaque `SecretRef`
Approved profile: `profile.CANARY`
Executor: `janus-run@fixture`
Destination: `fixture-service`
Env binding: `SERVICE_TOKEN`
Validation probe: `fixture-service-env`
Reload: `none`
Blast radius: `fixture-service`

This consumer is nonprod and exists to prove the operator path before any real
host/service wiring. It may receive the literal through its reviewed private env
file, but the literal must not appear in CLI output, logs, audit records, MCP
responses, or model-facing text.

Rotation posture:
- `supports_dual_value = false`
- reload is `none`, so one-click rotation must treat this consumer as a manual
  fixture until a real reload/validation story exists.
- successful use records value-free `secret.use`, `consumer.observe`, and
  lifecycle evidence.
