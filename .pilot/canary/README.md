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
| `vuln_python_hashlib_md5.py` | `pr-blocking.python.lang.security.insecure-hash-algorithm-md5-hashlib` | CWE-327 (Broken/Risky Crypto Algorithm) | **PASS** — 1 finding, exit 1 |
| `vuln_python_hashlib_sha1.py` | `pr-blocking.python.lang.security.insecure-hash-algorithm-sha1-hashlib` | CWE-327 (Broken/Risky Crypto Algorithm) | **PASS** — 1 finding, exit 1 |
| `vuln_python_hashlib_new_md5.py` | `pr-blocking.python.lang.security.insecure-hash-function` | CWE-327 (Broken/Risky Crypto Algorithm) | **PASS** — 1 finding, exit 1 |
| `vuln_python_md5_used_as_password.py` | `pr-blocking.python.lang.security.audit.md5-used-as-password` | CWE-327 (Broken/Risky Crypto Algorithm) | **PASS** — 1 finding, exit 1 |
| `vuln_javascript.js` | `pr-blocking.javascript.lang.security.audit.code-string-concat` | CWE-95 (Eval Injection) | **PASS** — 1 finding, exit 1 |
| `vuln_go.go` | `pr-blocking.go.lang.security.injection.tainted-sql-string` | CWE-89 (SQL Injection) | **PASS** — 1 finding, exit 1 |

**7/7 fixtures caught.** No coverage gap to document for this rollout's three
in-scope languages (Python, JavaScript, Go) — except the documented
`hashlib.new("sha1", ...)` upstream gap noted below, which deliberately has
**no** fixture (see "Rules promoted from `deep-scan/`"). Python has five
fixtures on purpose — one per distinct weak-hash call pattern now blocked
(pycryptodome MD5, hashlib MD5, hashlib SHA1, generic `hashlib.new`
MD4/MD5, and MD5-used-as-password), each in its own file to preserve the
"exactly one finding per fixture" invariant.

### Rules promoted from `deep-scan/`

**2026-07-24 — `insecure-hash-algorithm-md5-hashlib`.** The Design notes
section below (written at initial rollout) documented `hashlib.md5` as a
known coverage gap: `pr-blocking/` only caught the pycryptodome-specific
MD5 rule, not the far more common `hashlib.md5(...)` pattern. That gap is
now closed — `pr-blocking/python/lang/security/insecure-hash-algorithms-md5.yaml`
was promoted from
`deep-scan/python/lang/security/insecure-hash-algorithms-md5.yaml`
(same content, rule id suffixed `-hashlib` to avoid colliding with the
pre-existing pycryptodome rule of the same original id). This is a
deliberate, reviewed exception to the normal `confidence: HIGH` bar for
`pr-blocking/` (see main `README.md`) — the vendored rule's upstream
metadata says `confidence: MEDIUM`, but `hashlib.md5(...)` is a direct,
unambiguous call pattern (with `usedforsecurity=False` already excluded)
that carries negligible false-positive risk in practice, and it is the
most common Python weak-hash pattern seen in Seazone code. See the rule
file's own `metadata.seazone-promotion-rationale` for the full writeup.
`vuln_python_hashlib_md5.py` is the new fixture proving it fires.

**2026-07-24 (FU-C) — `insecure-hash-algorithm-sha1-hashlib`,
`insecure-hash-function`, `md5-used-as-password`.** Continuation of the
above: the remaining `hashlib`-family weak-hash siblings flagged in FU-B's
own "revisit separately" note are now promoted too.

- `insecure-hash-algorithm-sha1-hashlib` — `hashlib.sha1(...)`, promoted
  from `deep-scan/python/lang/security/insecure-hash-algorithms.yaml`. Id
  suffixed `-hashlib` because the bare id `insecure-hash-algorithm-sha1` is
  reused by three separate deep-scan rules (hashlib, `cryptography.hazmat`,
  pycryptodome); only the hashlib variant is promoted. Proven by
  `vuln_python_hashlib_sha1.py`.
- `insecure-hash-function` — `hashlib.new("md4"/"md5", ...)`, promoted
  from `deep-scan/python/lang/security/insecure-hash-function.yaml`
  unchanged (no id collision). Proven by `vuln_python_hashlib_new_md5.py`.
  **Documented gap:** this rule's upstream regex (`[M|m][D|d][4|5]`) only
  matches 3-character algorithm names, so `hashlib.new("sha1", ...)` is
  **not** matched by this or any other vendored `deep-scan/` rule — a
  local test (`import hashlib; hashlib.new("sha1", data)`) scores 0
  findings against `pr-blocking/` even after this promotion. This is a
  genuine upstream coverage gap (see the rule's own metadata for the full
  writeup), not something a rule-file edit here can responsibly fix
  without also editing/re-vendoring the upstream rule logic — deliberately
  left as a documented gap rather than a fixture, per policy below.
- `md5-used-as-password` — MD5 flowing into any `*password*`-named call,
  promoted from
  `deep-scan/python/lang/security/audit/md5-used-as-password.yaml`
  unchanged (no id collision). This is the **first taint-mode rule**
  promoted into `pr-blocking/` — flagged as a slightly higher-risk
  exception than its direct-pattern siblings for that reason (see the
  rule file's `metadata.seazone-promotion-rationale`). Proven in isolation
  by `vuln_python_md5_used_as_password.py`, which deliberately uses the
  bare `Crypto.Hash.MD5` source (not `hashlib.md5(...)`) so the fixture
  triggers *only* this rule, not also `insecure-hash-algorithm-md5-hashlib`
  — preserving the one-finding-per-fixture invariant. (A real-world
  `hashlib.md5(...)`-into-`store_password(...)` usage legitimately fires
  *both* rules at once; that combined-firing case was also verified
  locally — 2 findings, exit 1 — but is not used as a canary fixture here
  since it would break the invariant.)

Raw evidence (abbreviated) from the run above:

```
=== .pilot/canary/vuln_python.py ===
Ran 17 rules on 1 file: 1 finding.
  ❯ pr-blocking.python.pycryptodome.security.insecure-hash-algorithm-md5
    16┆ h = Crypto.Hash.MD5.new()
exit_code=1

=== .pilot/canary/vuln_python_hashlib_md5.py (added 2026-07-24, see promotion note above) ===
Ran 18 rules on 1 file: 1 finding.
  ❯ pr-blocking.python.lang.security.insecure-hash-algorithm-md5-hashlib
    22┆ return hashlib.md5(data).hexdigest()
exit_code=1

=== .pilot/canary/vuln_python_hashlib_sha1.py (added 2026-07-24, FU-C) ===
Ran 21 rules on 1 file: 1 finding.
  ❯ pr-blocking.python.lang.security.insecure-hash-algorithm-sha1-hashlib
    18┆ return hashlib.sha1(data).hexdigest()
exit_code=1

=== .pilot/canary/vuln_python_hashlib_new_md5.py (added 2026-07-24, FU-C) ===
Ran 21 rules on 1 file: 1 finding.
  ❯ pr-blocking.python.lang.security.insecure-hash-function
    18┆ return hashlib.new("md5", data).hexdigest()
exit_code=1

=== .pilot/canary/vuln_python_md5_used_as_password.py (added 2026-07-24, FU-C) ===
Ran 21 rules on 1 file: 1 finding.
  ❯ pr-blocking.python.lang.security.audit.md5-used-as-password
    22┆ store_password(digest)
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

- **Python** — `Crypto.Hash.MD5.new(...)` (pycryptodome). `insecure-hash-algorithm-md5`
  is the exact rule id the Task 4 live PR test seeded and confirmed turns
  the gate red, so `vuln_python.py` reproduces that literal trigger pattern
  (`Crypto.Hash.MD5.new(...)`) rather than a lookalike that wouldn't match.
  **Historical note (superseded 2026-07-24):** this bullet originally said
  `pr-blocking/` only vendors the pycryptodome-specific MD5 rule and that
  `hashlib`-based MD5 rules live in `deep-scan/` only — see
  `.pilot/opengrep-smoke.md` §5, where a synthetic `hashlib.md5` line was
  scanned against `pr-blocking/` and did **not** fire at the time. That gap
  is now closed (see "Rules promoted from `deep-scan/`" above);
  `hashlib.md5(...)` is covered by `insecure-hash-algorithm-md5-hashlib` and
  proven by the separate `vuln_python_hashlib_md5.py` fixture.
  **Update (2026-07-24, FU-C):** `md5-used-as-password` — deferred here as
  "revisit separately" — has now also been promoted, along with
  `hashlib.sha1(...)` (`insecure-hash-algorithm-sha1-hashlib`) and the
  generic `hashlib.new("md4"/"md5", ...)` constructor form
  (`insecure-hash-function`). See "Rules promoted from `deep-scan/`" above
  for the full writeup of all three, including the one documented
  remaining gap (`hashlib.new("sha1", ...)`, not caught by any vendored
  rule).
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
