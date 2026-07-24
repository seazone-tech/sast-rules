# Opengrep efficacy canary

A repeatable, self-contained check that `pr-blocking/` still catches known
vulnerability classes. This is **not** a functional test of the CI gate
itself (see the Task 4 live-PR test for that) — it's a fast, local proof
that the *ruleset* still fires on representative fixtures, one per
`pr-blocking/`-covered language. Re-run this after any rule bump/vendoring
change, and reference it from the quarterly control-effectiveness review.

## ⚠️ These files are deliberate test fixtures — never real code

Every `vuln_*` file in this directory is **intentionally vulnerable**, on
purpose, to trigger a specific `pr-blocking/` rule. They are not example
code to copy, they are not accidentally-insecure, and they must never be
treated as a starting point for real application code. To prevent them from
polluting future scans of this repo itself, the repo-root
[`.semgrepignore`](../../.semgrepignore) excludes `.pilot/canary/` from any
opengrep scan of `sast-rules` itself.

## How to run

```bash
for f in .pilot/canary/vuln_*; do
  opengrep scan --config pr-blocking/ --error "$f"
done
```

Each invocation is expected to **exit non-zero (1)** and report **exactly
one finding**, matching the rule listed in that fixture's header comment.
`--error` is required — opengrep's default exit code is `0` regardless of
findings (see `.pilot/opengrep-smoke.md` §"Exit code caveat"); the gate and
this canary both rely on `--error` to turn a finding into a failing exit
status.

## Fixtures, expected rule, and observed result

Run on 2026-07-24, opengrep v1.25.0, against `pr-blocking/` at this branch's
tip (same 45-rule set validated in Task 1 / `.pilot/opengrep-smoke.md`).

| Fixture | Expected rule | CWE | Result |
|---|---|---|---|
| `vuln_python.py` | `pr-blocking.python.pycryptodome.security.insecure-hash-algorithm-md5` | CWE-327 (Broken/Risky Crypto Algorithm) | **PASS** — 1 finding, exit 1 |
| `vuln_javascript.js` | `pr-blocking.javascript.lang.security.audit.code-string-concat` | CWE-95 (Eval Injection) | **PASS** — 1 finding, exit 1 |
| `vuln_go.go` | `pr-blocking.go.lang.security.injection.tainted-sql-string` | CWE-89 (SQL Injection) | **PASS** — 1 finding, exit 1 |

**3/3 fixtures caught.** No coverage gap to document for this rollout's three
in-scope languages (Python, JavaScript, Go).

Raw evidence (abbreviated) from the run above:

```
=== .pilot/canary/vuln_python.py ===
Ran 17 rules on 1 file: 1 finding.
  ❯ pr-blocking.python.pycryptodome.security.insecure-hash-algorithm-md5
    16┆ h = Crypto.Hash.MD5.new()
exit_code=1

=== .pilot/canary/vuln_javascript.js ===
Ran 16 rules on 1 file: 1 finding.
  ❯❯ pr-blocking.javascript.lang.security.audit.code-string-concat
    16┆ eval(cmd);
exit_code=1

=== .pilot/canary/vuln_go.go ===
Ran 12 rules on 1 file: 1 finding.
  ❯❯ pr-blocking.go.lang.security.injection.tainted-sql-string
    20┆ query := "SELECT * FROM users WHERE name = '" + name + "'"
exit_code=1
```

## Design notes / why these specific fixtures

- **Python** — `Crypto.Hash.MD5.new(...)` (pycryptodome), not `hashlib.md5`.
  `pr-blocking/` only vendors the pycryptodome-specific MD5 rule; the
  `hashlib`-based MD5 rules (`insecure-hash-algorithms*`,
  `md5-used-as-password`) live in `deep-scan/` only, not `pr-blocking/` —
  see `.pilot/opengrep-smoke.md` §5, where a synthetic `hashlib.md5` line
  was scanned against `pr-blocking/` and did **not** fire. `insecure-hash-algorithm-md5`
  is the exact rule id the Task 4 live PR test seeded and confirmed turns
  the gate red, so the fixture here reproduces that literal trigger pattern
  (`Crypto.Hash.MD5.new(...)`) rather than a lookalike that wouldn't match.
- **JavaScript** — `code-string-concat` is a taint-mode rule: it requires an
  Express-style request handler (`app.get(..., function (req, res) {...})`)
  as the pattern-source scope and `req.query`/`req.body`/`req.params`/
  `req.cookies`/`req.headers` flowing into `eval(...)`. The fixture is a
  minimal Express route matching that shape exactly.
- **Go** — `tainted-sql-string` is also taint-mode: source is any
  `(*http.Request).FormValue`-style call (from a fixed allow-list of
  `net/http` request fields), sink is a `"<SELECT|INSERT|...>" + ...` string
  concatenation. The fixture uses `r.FormValue("name")` flowing into a
  `"SELECT ..." + name` concatenation passed to `db.Query`.

## When a language's vuln class isn't caught

If a future re-run finds `pr-blocking/` no longer catches one of these (a
rule was pruned/rewritten upstream, or the fixture pattern drifted), the
policy is: **fix the fixture first** (confirm it's still hitting the rule's
actual current pattern), and only if `pr-blocking/` genuinely has no rule
left for that vulnerability class, replace the PASS above with an explicit
**GAP** entry — rule removed/never existed, since when, and whether a
replacement rule should be vendored. Never silently mark a fixture as
passing without a real non-zero exit + finding from an actual `opengrep`
run.
