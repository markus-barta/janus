# Claude Code approved-use hooks

The `janus-claude-hook` binary connects Claude Code tool events to the existing
permit-bound `janusd-use run` path. It never resolves or receives a secret value.

The guard applies to every `PreToolUse` event. It denies raw `sec_...`
references and `{{janus:...}}` handles in Bash and other tool arguments,
including common quoted, nested-shell, percent, hex, base64, and backslash
encodings. A copied `UsePermit` is also denied outside one exact foreground
command shape:

```text
janusd-use run --profile PROFILE --permit use_... -- REVIEWED_ARG...
```

The hook parses that command without running a shell expansion, validates its
fixed fields, and replaces it with a safely quoted command using the configured
absolute `janusd-use` path. `janusd-use` then rechecks the reviewed profile, permit
expiry, single-use claim, principal, executor, destination, and exact arguments
before any value exists. The hook cannot turn a stale or mismatched permit into
a valid one.

Successful and failed managed calls append value-free `PostToolUse` evidence.
The records contain a hashed Claude session/repository binding, profile, permit
id, outcome, and integrity chain. They never contain argv, cwd, tool output,
transcript content, or a secret value.

## Install

1. Build and install both binaries from the same reviewed Janus release:

   ```bash
   cargo build --release --locked --bin janusd-use --bin janus-claude-hook
   install -m 0755 target/release/janusd-use /opt/janus/bin/janusd-use
   install -m 0755 target/release/janus-claude-hook /opt/janus/bin/janus-claude-hook
   ```

2. Create a private audit directory. Existing group/world-accessible
   directories or files are rejected rather than silently repaired:

   ```bash
   install -d -m 0700 /var/lib/janus/audit
   ```

3. Merge
   [`contrib/claude-code/janus-hooks.settings.json`](../contrib/claude-code/janus-hooks.settings.json)
   into the appropriate Claude Code settings file. Replace all three
   `/absolute/path/to/...` placeholders. Do not replace an existing `hooks`
   object; add the Janus event entries alongside existing entries.

   Project settings live at `.claude/settings.json`; user settings live at
   `~/.claude/settings.json`. Managed enterprise settings should use the same
   reviewed commands and absolute paths.

4. Start Claude Code and use `/hooks` to verify one Janus command hook under
   `PreToolUse`, `PostToolUse`, and `PostToolUseFailure`. Exercise the guard
   with non-secret fixture references before enabling real profiles.

Claude Code sends command-hook JSON on stdin. Janus returns the current
`hookSpecificOutput.permissionDecision` schema for `PreToolUse`, so a deny is
enforced before Claude Code evaluates normal allow rules. See the official
[Claude Code hooks reference](https://code.claude.com/docs/en/hooks).

## Disable and rollback

For an emergency stop, set `"disableAllHooks": true` in the same settings
layer and restart the Claude Code session. This disables every hook in that
layer, not only Janus; secret-bearing automation must remain stopped while the
guard is disabled.

For a normal rollback, remove only the three Janus command entries and the two
`JANUS_HOOK_*` environment entries from the settings file, then verify their
absence with `/hooks`. Do not restore raw `sec_...` shell substitution. Revert
to reference-only Warden use until a reviewed hook release is installed.

The audit file is evidence and is not deleted during rollback. Preserve it
under the deployment retention policy.
