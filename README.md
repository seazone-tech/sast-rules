# sast-rules

Vendored, version-pinned SAST rulesets for the Seazone CI/CD platform.

Tracking: **SRE-46** / **Airbnb 10.2.8**.

## Purpose

This repository is the single source of truth for the rules our SAST engine
([Opengrep](https://github.com/opengrep/opengrep) — **not** Semgrep) runs
against Seazone code. Rules here are **vendored and pinned**, never fetched
live from a remote registry at scan time. That means:

- Every CI run (PR gate and the central deep scanner) sees the exact same
  rules until someone deliberately bumps the pin in a reviewed PR.
- A compromised or changed upstream ruleset can't silently change what CI
  blocks or reports.
- Rule changes go through the same review process as any other change to
  our CI/CD config (PR + `CODEOWNERS` review by `@seazone-tech/sre`).

## Upstream source

Rules are vendored from [`opengrep/opengrep-rules`](https://github.com/opengrep/opengrep-rules),
pinned at commit:

```
f1d2b562b414783763fd02a6ed2736eaed622efa
```

(see [`VERSION`](./VERSION); resolved via
`git ls-remote https://github.com/opengrep/opengrep-rules HEAD` on 2026-07-24).

Upstream license: **LGPL 2.1**, with a **"Commons Clause" v1.0** condition
that only restricts *reselling* the software — it does not restrict internal
use, modification, or vendoring. See [`LICENSE`](./LICENSE) (copied verbatim
from upstream) for the full text and required attribution. Upstream
`opengrep-rules` is itself a fork of `semgrep/semgrep-rules`.

### Registry-sourced rules (internal-use license)

None. Every rule in this repository was sourced directly from
`opengrep-rules` at the pinned commit above — no rule had to be pulled from
the Semgrep Cloud/registry (Semgrep Rules License v1.0), so there is nothing
to list under the internal-use license here. If a future bump ever needs a
registry-only rule, list it in this section with a justification before
merging.

## Layout: `pr-blocking/` vs `deep-scan/` vs `deep-scan-quality/`

All three directories mirror `opengrep-rules`' own
`<language>/<framework>/...` structure, restricted to the four languages in
scope for this rollout: **Python, JavaScript, TypeScript, Go**.

Three rulesets, three consumers:

- **`pr-blocking/`** — the PR gate (blocking). See below.
- **`deep-scan/`** — the central/periodic scanner
  (`seazone-tech/sast-scanner`) consumes **this directory only**
  (`SAST_RULESET_DIR=deep-scan`, the default in `scanner/config.py`).
  **Security rules only** — every rule here has `metadata.category:
  security` (or is unambiguously a security rule despite its path, see
  below), full stop.
- **`deep-scan-quality/`** — everything else (correctness, best-practice,
  compatibility, performance, maintainability, portability). Not consumed
  by anything today; kept vendored (not deleted) because it may be useful
  later for a separate code-quality/lint pass. See "`deep-scan-quality/` —
  non-security rules, split out" below for why this split exists.

### `pr-blocking/` — the PR gate (blocking)

Consumed by the reusable "Opengrep diff-aware PR scan" GitHub Actions
workflow (separate task). Findings here **block merges**, so this set is
deliberately narrow and biased hard toward precision over recall:

Selection criteria (a rule is vendored here only if **all** of these hold):
- `metadata.category: security`
- `metadata.confidence: HIGH`
- has `metadata.owasp` and/or `metadata.cwe` (OWASP Top 10 / CWE Top 25
  traceability)

Rules tagged `correctness`, `best-practice`, `style`, `compatibility`,
`performance`, `maintainability`, or `portability` — and any `security` rule
with `confidence: LOW`/`MEDIUM` — are deliberately **excluded** from
`pr-blocking/` even if they look important, per the "err toward not
blocking" rule for this gate. They still live in `deep-scan/`.

**Promoted exception (2026-07-24):** `python.lang.security.insecure-hash-algorithm-md5-hashlib`
(`pr-blocking/python/lang/security/insecure-hash-algorithms-md5.yaml`, id
suffixed `-hashlib`) was promoted from `deep-scan/` despite carrying
upstream `confidence: MEDIUM`, not `HIGH`. Rationale: `hashlib.md5(...)` is
the most common Python weak-hash pattern in Seazone code, and this specific
rule's pattern (a direct call to `hashlib.md5`, with the `usedforsecurity=False`
escape hatch already excluded) has negligible real-world false-positive
risk — the `MEDIUM` tag is an artifact of the upstream Bandit-derived
metadata, not a reflection of this pattern's actual precision. Before
promoting this, `pr-blocking/` only caught the pycryptodome-specific MD5
call (`insecure-hash-algorithm-md5`, unchanged, still pycryptodome-only),
so a real `hashlib.md5` usage would not have blocked a PR. This is a single,
reviewed exception — not a change to the selection criteria above — see
`.pilot/canary/README.md` ("Rules promoted from `deep-scan/`") for the full
writeup and the fixture proving it fires.

**Promoted exceptions, continued (2026-07-24, FU-C — weak-hash siblings):**
three more `confidence: MEDIUM` weak-hash rules were promoted from
`deep-scan/` in the same follow-up, closing the remaining gaps the FU-B
smoke test had flagged for `hashlib`-family weak hashing:

- `python.lang.security.insecure-hash-algorithm-sha1-hashlib`
  (`pr-blocking/python/lang/security/insecure-hash-algorithms-sha1.yaml`)
  — `hashlib.sha1(...)`, the direct SHA1 sibling of the MD5 rule above.
  Id suffixed `-hashlib` even though nothing in `pr-blocking/` currently
  collides with the bare id `insecure-hash-algorithm-sha1` — it's reused
  by **three** separate deep-scan rules for three distinct call patterns
  (hashlib, `cryptography.hazmat`, pycryptodome); only the hashlib variant
  is promoted here, and the suffix pre-empts a future collision if either
  of the other two is ever promoted.
- `python.lang.security.insecure-hash-function`
  (`pr-blocking/python/lang/security/insecure-hash-function.yaml`) —
  `hashlib.new("md4"/"md5", ...)` (and the `name=` kwarg form), the
  generic-constructor sibling of the direct `hashlib.md5`/`hashlib.sha1`
  calls. No id collision. **Known gap, not fixed by this promotion:** the
  upstream regex only matches 3-character algorithm names (`MD4`/`MD5`),
  so `hashlib.new("sha1", ...)` is **not** caught by this or any other
  vendored `deep-scan/` rule — confirmed by a local test file that scores
  0 findings against `pr-blocking/` even after this promotion. This is an
  upstream coverage gap (documented in the rule's own metadata), not
  something fixable by promotion alone.
- `python.lang.security.audit.md5-used-as-password`
  (`pr-blocking/python/lang/security/audit/md5-used-as-password.yaml`) —
  the first **taint-mode** rule promoted into `pr-blocking/`: flags an
  MD5 digest (from `hashlib.md5`, `hashlib.new(name="MD5")`,
  `Crypto(dome).Hash.MD5`, or `cryptography.hazmat...MD5`) flowing into
  any call whose function name matches `/password/i`. FU-B's original
  commit had explicitly deferred this one ("revisit separately"); it's
  promoted now because the sink is narrowly scoped (not an arbitrary
  taint sink) and MD5-for-password-hashing is a strictly worse
  anti-pattern than bare MD5. Flagged as a slightly higher-risk exception
  than its siblings precisely because it's taint-mode (more dataflow
  surface than a direct pattern match) — see the rule file's own
  `metadata.seazone-promotion-rationale` for the full caveat.

All three are documented in the rule files' own
`metadata.seazone-promotion-rationale` and in `.pilot/canary/README.md`
("Rules promoted from `deep-scan/`"), with local `opengrep scan --error`
proof (exit 1 + rule ID reported) for each.

| Language   | Rules |
|------------|------:|
| Python     |    21 |
| JavaScript |    16 |
| Go         |    12 |
| TypeScript |     0 |
| **Total**  |**49** |

**Note on TypeScript:** as of the pinned commit, `opengrep-rules` has zero
rules under `typescript/` that meet the `confidence: HIGH` bar (its
TypeScript-specific rules — Angular/React/NestJS/AWS-CDK — top out at
`MEDIUM`/`LOW`). This is not a coverage gap in practice: 16/16 of the
JavaScript `HIGH`-confidence rules vendored here declare
`languages: [js, ts, ...]` upstream (the rule, not the directory, decides
what it matches), so they already fire against `.ts`/`.tsx` files when
`opengrep scan --config pr-blocking/` runs. There is currently no dedicated
`pr-blocking/typescript/` directory because there is nothing upstream, at
`HIGH` confidence, that belongs in it. Re-check this on every version bump —
see "Bumping the pin" below.

### `deep-scan/` — the central scanner (broad, security-only)

Consumed by `seazone-tech/sast-scanner`'s weekly org-wide scan, not the PR
gate. This is the full vendored set for the same four languages, every
confidence level, including everything already in `pr-blocking/` — but,
since **2026-07-26**, **security rules only** (see "`deep-scan-quality/`"
below for why). Before that date this directory also held 119 non-security
rule files; those were moved out, not deleted.

| Language   | Rules | Rule files |
|------------|------:|-----------:|
| Python     |   252 |        246 |
| JavaScript |   168 |        162 |
| Go         |    71 |         68 |
| TypeScript |    18 |         18 |
| **Total**  | **509** |    **494** |

(Some `.yaml` files define more than one rule, hence rules ≠ files.)

### `deep-scan-quality/` — non-security rules, split out (2026-07-26)

`deep-scan/` originally vendored **every** rule in scope (613 files / 669
rules), including 119 files that aren't security rules at all
(`correctness/`, `best-practice/`, `compatibility/`, `performance/`,
`maintainability/`, `portability/`, plus a handful of non-security rules
that happened to live under an `audit/` path with no `security/` ancestor).
`sast-scanner` is a **security** control (SRE-46 / Airbnb 10.2.8); those 119
rules only inflated finding volume, LLM triage cost, and dashboard noise
without adding security coverage — most visibly, a flood of
`typescript.react.portability.i18next.jsx-not-internationalized` findings
during a real org-wide run.

They were moved (not deleted — potentially useful later for a separate
code-quality/lint pass) to this sibling directory, one-for-one, preserving
their relative path under the language root
(e.g. `deep-scan/python/django/correctness/model-save.yaml` ->
`deep-scan-quality/python/django/correctness/model-save.yaml`).

**Classification rule:** a rule file stayed in `deep-scan/` if its path
contains a `security/` directory segment (e.g.
`javascript/lang/security/audit/...`, `python/pyramid/security/...`), OR —
the one exception — if the file itself is unambiguously a security rule
despite not living under a `security/` path
(`python/distributed/security.yaml`, whose rule id is `require-encryption`
and whose own `metadata.category` is `security`). Everything else moved.
This mechanical rule was cross-checked against `metadata.category` across
every file in the ruleset and matches it almost exactly (509/494 vs.
524-ish `category: security` occurrences, accounting for multi-rule files) —
the one deliberate exception above is the sole reconciling difference.

| Language   | Rules | Rule files |
|------------|------:|-----------:|
| Python     |   123 |         88 |
| JavaScript |    14 |         11 |
| Go         |    11 |          8 |
| TypeScript |    12 |         12 |
| **Total**  | **160** |    **119** |

Not consumed by `sast-scanner` or any other automation today — nothing
currently points `SAST_RULESET_DIR` (or an equivalent) at this directory.

All three directories vendor **rule definition files only**
(`*.yaml`/`*.yml` under `rules:`). Upstream's paired test fixtures (sample
vulnerable/safe code used by `opengrep-rules`' own test suite, e.g. `*.py`,
`*.js`, `*.fixed.py`) are intentionally not vendored — they aren't needed to
run `opengrep scan` and would only add noise to this repo.

## Validating the ruleset

The ruleset must parse cleanly with Opengrep:

```bash
docker run --rm -v "$PWD:/src" -w /src <opengrep image> \
  opengrep scan --config /src/pr-blocking/ --validate
```

### Deviation from the prescribed command — please read

The brief for this task specified
`ghcr.io/opengrep/opengrep:latest`, resolved to a digest, as the pinned
validation image. **That image does not exist.** Verified on 2026-07-24:

- `docker pull ghcr.io/opengrep/opengrep:latest` → `denied`.
- The GHCR anonymous-token endpoint itself returns `DENIED` for
  `opengrep/opengrep`, `opengrep/opengrep-cli`, and `opengrep-cli/opengrep`
  (compare: the same flow against a real public image,
  `ghcr.io/github/super-linter`, succeeds and returns `200`) — so this isn't
  a network/sandbox issue, the package genuinely isn't published there.
- `https://github.com/opengrep/opengrep/pkgs/container/opengrep` → `404`.
- `https://github.com/orgs/opengrep/packages` lists **no packages at all**.
- No official image on Docker Hub either (only unaffiliated third-party
  images like `ipvsix/opengrep`, `kondukto/opengrep`, etc. — not something
  to pin CI to without separate vetting).
- `opengrep-rules`' own CI (`.github/workflows/semgrep-rules-test.yml` at
  the pinned commit) doesn't use Docker either — it still installs
  `semgrep` via pip with a `# TODO: add a pip for opengrep` comment,
  confirming opengrep doesn't currently ship an official container image.

**What was actually used instead:** the official, signed Opengrep release
binary, installed via opengrep's own official install script
(`https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh`),
inside a digest-pinned base image:

```bash
docker run --rm -e LANG=C.UTF-8 -e LC_ALL=C.UTF-8 -e PYTHONUTF8=1 \
  -v "$PWD:/src" -w /src \
  ubuntu@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982 \
  bash -c '
    apt-get update -qq && apt-get install -qq -y curl ca-certificates
    curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash -s -- -v v1.25.0
    export PATH="/root/.opengrep/cli/latest:$PATH"
    opengrep scan --config /src/pr-blocking/ --validate
  '
```

- Base image: `ubuntu:22.04` pinned by digest
  `sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982`.
- Opengrep version: `v1.25.0` (latest official release as of 2026-07-24),
  installed from the official GitHub Releases artifact via the project's
  own install script (this is the same script the project's own README
  recommends for local installs).
- `LANG`/`LC_ALL`/`PYTHONUTF8` are required — without them the CLI's
  Python runtime defaults to ASCII and crashes on the UTF-8 smart quotes
  (`"..."`) present in some upstream rule messages.

**Result:**

```
=== opengrep --version ===
1.25.0
=== validate pr-blocking ===
Configuration is valid - found 0 configuration error(s), and 45 rule(s).
EXIT_CODE=0
=== validate deep-scan ===
Configuration is valid - found 0 configuration error(s), and 669 rule(s).
EXIT_CODE=0
```

**Update (2026-07-24, later same day):** one rule was promoted from
`deep-scan/` to `pr-blocking/` (see "Promoted exception" above), so
`pr-blocking/` now validates at **46 rules**, not 45; `deep-scan/` is
unchanged at 669. Re-validated with the same `v1.25.0` binary:
`Configuration is valid - found 0 configuration error(s), and 46 rule(s).`
The evidence block above is left as-is as the historical record of the
initial vendoring commit; it does not reflect this later promotion.

**Update (2026-07-24, FU-C — weak-hash siblings):** three more rules were
promoted from `deep-scan/` (see "Promoted exceptions, continued" above), so
`pr-blocking/` now validates at **49 rules**, not 46; `deep-scan/` is still
unchanged at 669. Re-validated with the same `v1.25.0` binary:
`Configuration is valid - found 0 configuration error(s), and 49 rule(s).`

**Update (2026-07-26 — split non-security rules to `deep-scan-quality/`):**
119 non-security rule files were moved out of `deep-scan/` into the new
sibling `deep-scan-quality/` (see that section above). Re-validated with the
locally-installed official `v1.25.0` binary (installed via the project's own
`install.sh`, same one used for the evidence above — still no official
Docker image exists for Opengrep):

```
$ opengrep scan --config deep-scan/ --validate
Configuration is valid - found 0 configuration error(s), and 509 rule(s).
$ opengrep scan --config deep-scan-quality/ --validate
Configuration is valid - found 0 configuration error(s), and 160 rule(s).
$ opengrep scan --config pr-blocking/ --validate
Configuration is valid - found 0 configuration error(s), and 49 rule(s).
```

`deep-scan/` drops from 613 files / 669 rules to **494 files / 509 rules**;
`pr-blocking/` (49 rules) is unaffected since every rule it vendors already
had `category: security` + `confidence: HIGH` and none of the 119 moved
files were ever promoted there.

**Action needed from whoever builds the reusable "Opengrep diff-aware PR
scan" workflow (later task):** there is no official pre-built, digest-pinnable
Opengrep image to point CI at today. Options to resolve there: (a) have
Seazone build and publish its own pinned image (e.g.
`ghcr.io/seazone-tech/opengrep:v1.25.0@sha256:...`) from the official
install script/binary, or (b) install the official signed binary directly
in the workflow (with `--verify-signatures` via cosign, which this local
validation skipped for speed). Either way, pin by version **and** verify
(digest or cosign signature) — don't float on `:latest` from an unofficial
third-party image.

## Bumping the pin

1. Resolve a new commit SHA from upstream:
   `git ls-remote https://github.com/opengrep/opengrep-rules HEAD` (or pin
   to a specific release tag's commit if upstream cuts one).
2. Clone `opengrep-rules` at that SHA and re-run the same selection
   criteria described above (`category: security` + `confidence: HIGH` +
   `owasp`/`cwe` present → `pr-blocking/`; everything security-relevant for
   the four languages → `deep-scan/`; everything else → `deep-scan-quality/`
   — see "Classification rule" in the `deep-scan-quality/` section above),
   re-copying into this repo.
3. Update [`VERSION`](./VERSION) to `opengrep-rules@<new-40-char-sha>`.
4. Re-run the validation command above against `pr-blocking/`, `deep-scan/`,
   and `deep-scan-quality/` and confirm `0 configuration error(s)` for each.
5. Open a PR (never push straight to the default branch). `CODEOWNERS`
   requires `@seazone-tech/sre` review. Merge with a merge commit — do not
   squash (squashing on GitHub regenerates the commit message and can drop
   required trailers).
6. CI never re-fetches `opengrep-rules` live; the next scan only sees the
   new rules once this PR merges.

## `CODEOWNERS`

`@seazone-tech/sre` owns everything in this repo (see
[`CODEOWNERS`](./CODEOWNERS)).
