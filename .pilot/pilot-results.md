# SAST Phase 0 pilot — results

Tracking: **SRE-46** / **Airbnb 10.2.8**. Consolidates what the Phase 0 pilot
proved before the wider org rollout: the gate works, it's fast, and it
resolves the open assumptions from the design spec. See also
`.pilot/opengrep-smoke.md` (Opengrep engine smoke test) and
`.pilot/canary/README.md` (repeatable efficacy canary, this same PR).

## Per-pilot summary

Four code pilots, one per in-scope archetype, all now have the SAST caller
workflow (`.github/workflows/sast-caller.yml` → `seazone-tech/.github`'s
reusable `sast.yml`) merged to their default branch, checks green:

| Pilot repo | Archetype | Primary language | SAST check wall-time (caller PR) |
|---|---|---|---|
| `automation-aviso-vistorias` | arq1 | Python | **19s** |
| `automation-amenities-do-anuncio` | arq2 | Python | **23s** |
| `contextual-assistant` | arq3 | TypeScript/JavaScript | **21s** |
| `alvara-checker` | arq4 | TypeScript | **18s** |

(`terraform-governanca` / arq5, Trivy IaC caller, is a separate mini-cycle,
not yet run — see Known follow-ups.)

All four `sast / sast` checks are diff-aware (`--baseline-commit` scoped),
so ~18-21s is the steady-state cost **per PR**, not a full-repo scan — this
is the number that matters for developer-facing PR latency.

For contrast, `.pilot/opengrep-smoke.md` measured full (non-diff-aware)
scans on `automation-amenities-do-anuncio` directly with the CLI:
**2.96s** for `pr-blocking/` (45 rules, 16 Python files) and **24.9s** for
`deep-scan/` (669 rules, 24 files) — the deep-scan number sizes Phase 1's
central/scheduled scanner, not the PR gate.

## Gate efficacy — live test

The gate was validated against a real PR, not just unit-tested locally.
On `automation-amenities-do-anuncio` PR #3 (throwaway canary branch
`test/sast-canary-DELETE-ME`, closed immediately after):

- Commit `dd779a4c` seeded one intentional MD5 finding
  (`pr-blocking.python.pycryptodome.security.insecure-hash-algorithm-md5`,
  CWE-327) → `sast / sast` check **failed** (run
  [30119623426](https://github.com/seazone-tech/automation-amenities-do-anuncio/actions/runs/30119623426),
  "Ran 17 rules on 1 file: 1 finding", reviewdog installed and invoked against
  the SARIF output) — **RED**, 17s.
- Commit `3998af51` removed the seed → `sast / sast` check **passed**
  (run [30119681808](https://github.com/seazone-tech/automation-amenities-do-anuncio/actions/runs/30119681808))
  — **GREEN**, 18s.

This is the same rule id (`insecure-hash-algorithm-md5`) reused as the
Python fixture in `.pilot/canary/vuln_python.py`, so the canary in this PR
reproduces the exact live-tested trigger rather than a lookalike.

An earlier attempt at this same live test (PR #2, commit `d7ce4854`) also
failed, but for the wrong reason — a real bug caught by the test itself:
`sast.yml` called `cosign verify-blob` without ever installing `cosign`, so
every run exited 127 before reaching the scan step, RED unconditionally
regardless of vuln/clean state. Fixed by adding a pinned
`sigstore/cosign-installer` step before "Install Opengrep" (amendment to
`.github` PR #6); the RED/GREEN pair above is the *post-fix* re-run and is
the one that counts as gate validation.

## Resolved open assumptions (design spec §10)

| # | Assumption | Resolution |
|---|---|---|
| 1 | reviewdog ↔ opengrep format compatibility | Works via SARIF (`opengrep scan -f=sarif` / `--sarif`); reviewdog consumes it and posts inline PR comments. Caveat found in `.pilot/opengrep-smoke.md`: SARIF `result.level` is `null` on every result (never populated inline) — severity only exists in `tool.driver.rules[].defaultConfiguration.level`, joined by `ruleId`. The gate does **not** rely on reviewdog's severity handling to decide pass/fail — that's opengrep's own `--error` exit code — reviewdog is presentation-only (`\|\| true`). |
| 2 | Vendoring license | Rules are sourced from `opengrep-rules` (LGPL 2.1 + Commons Clause, restricts resale only, not internal use/vendoring) at a pinned commit — no Semgrep Cloud/registry rule had to be pulled, so there is no registry-license entanglement to track. |
| 3 | Per-repo ruleset enforcement | Deferred to the enforcement phase. Org-wide GitHub rulesets need a GitHub Enterprise plan we don't have; per-repo branch protection (enabling the `sast / sast` required check per repo as it onboards) is confirmed as the path for Phase 0/1. |
| 4 | Rules access from consuming repos | **Solved** by making `sast-rules` **public**. A plain `GITHUB_TOKEN` checkout (no PAT, no cross-repo secret) is enough to fetch `pr-blocking/`/`deep-scan/` at the pinned commit, which scales to all ~111 org repos without per-repo credential provisioning. |
| 5 | Opengrep runtime behavior | SARIF `result.level` is `null` (see #1); exit code is `0` by default regardless of findings and only becomes `1` with `--error` explicitly passed; the gate keys on `--error`'s exit code combined with `--baseline-commit` for diff-scoping. `cosign` is **not** bundled in any opengrep distribution and must be installed separately (`sigstore/cosign-installer`, pinned) — the live test caught this the hard way (see above). No Opengrep Docker image is published upstream; the reusable workflow installs the v1.25.0 binary via the official `install.sh`. |
| 6 | Cross-repo reusable-workflow call from a private `.github` repo | Confirmed working — the org already permits this pattern (precedent: `cd-ecs`), and all four pilot callers successfully invoke `seazone-tech/.github/.github/workflows/sast.yml@main` from their own (public or private) repos. |

## Known follow-ups

- **Central scanner + Grafana dashboard** (Phase 1) — not started; the
  `deep-scan/` timing above (24.9s / 24 files on a small repo) is the
  sizing input for how that scheduled/central job should be batched.
- **Trivy IaC caller** (arquétipo 5, `terraform-governanca`) — a separate,
  validated mini-cycle of its own; not yet run.
- **Three Minor findings on `sast.yml`** flagged in review, to close out
  before the final rollout review:
  1. the reusable workflow template is missing a header comment explaining
     its purpose/inputs;
  2. the caller workflow has no explicit `permissions:` block;
  3. the crash-vs-finding error message needs to distinguish "opengrep
     itself failed to run" from "opengrep ran and found something" — right
     now both can look like the same failure to someone reading the log.
