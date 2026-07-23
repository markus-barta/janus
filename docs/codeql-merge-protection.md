# CodeQL merge protection

Janus uses GitHub repository ruleset `19622624` (`CodeQL merge protection`) on
the default branch. It is active, names CodeQL as the required tool, and has no
bypass actors.

The ruleset is deliberately separate from the eight GitHub Actions status
checks required by branch protection. A successful CodeQL workflow proves that
analysis completed and uploaded results; this ruleset additionally evaluates
the findings in those results before a pull request can merge.

## Thresholds

| Finding class | Blocking threshold | Treatment |
|---|---|---|
| Security severity | `medium_or_higher` | Critical, high, and medium findings block. Low and note findings remain visible for triage. |
| General alert severity | `errors_and_warnings` | Errors and warnings block. Recommendations remain visible for triage. |

The reviewed baseline was zero open CodeQL alerts when enforcement became
active on 2026-07-23. A blocking result must be corrected or adjudicated
narrowly against the exact alert; repository-wide suppression is not an
acceptable merge workaround.

GitHub applies merge protection to findings whose identified code lines are in
the pull request diff. The required language-specific CodeQL checks remain the
fail-closed control for missing, cancelled, or failed analysis.

## Enforcement proof

Pull request `#14` introduced a temporary, never-executed Python command
injection on head `b69483cc03cefad555834ef866de76d84faa7435`. All eight
protected status checks passed, including all four language-specific CodeQL
analysis jobs. CodeQL alert `#18` identified the added line as critical
`py/command-line-injection`; the separate ruleset result failed and GitHub
reported the otherwise mergeable pull request as blocked.

The fixture was then removed from the same pull request and never merged.
Fresh analysis fixed the alert, the ruleset result passed, and GitHub reported
the corrected pull request as mergeable. The exact check and ruleset receipts
are retained in PPM ticket `JANUS-340`.

## Preserved branch policy

The ruleset does not replace or duplicate the protected status checks:

- `base-images`
- `gitleaks`
- `build-test`
- `check`
- `analyze (actions)`
- `analyze (go)`
- `analyze (python)`
- `analyze (rust)`

Each check remains bound to the GitHub Actions application. Strict status
checks and administrator enforcement remain enabled. This solo project
requires zero human approvals.

## Outage and break-glass recovery

First retry a failed or cancelled analysis. If GitHub code scanning is
unavailable and the outage blocks an urgent correction, an administrator may
temporarily set only ruleset `19622624` to disabled:

1. Record the outage, affected pull request, reason, and start time in PPM.
2. Confirm all eight protected status checks are still required and green.
3. Inspect the pull request diff and current open-alert baseline manually.
4. Disable only `CodeQL merge protection`; do not weaken branch protection.
5. Merge only the exact reviewed correction.
6. Restore the ruleset to active immediately and prove a clean analyzed pull
   request is mergeable.
7. Record restoration time and evidence in PPM.

There is no standing bypass actor. Ordinary feature work waits for CodeQL
rather than using this outage procedure.
