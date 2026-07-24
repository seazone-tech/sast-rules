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

## Layout: `pr-blocking/` vs `deep-scan/`

Both directories mirror `opengrep-rules`' own `<language>/<framework>/...`
structure, restricted to the four languages in scope for this rollout:
**Python, JavaScript, TypeScript, Go**.

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

| Language   | Rules |
|------------|------:|
| Python     |    17 |
| JavaScript |    16 |
| Go         |    12 |
| TypeScript |     0 |
| **Total**  |**45** |

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

### `deep-scan/` — the central scanner (broad)

Used by a later-phase central/periodic scanner, not the PR gate. This is
the full, unfiltered vendored set for the same four languages — every rule
category and every confidence level, including everything already in
`pr-blocking/`.

| Language   | Rules | Rule files |
|------------|------:|-----------:|
| Python     |   375 |        334 |
| JavaScript |   182 |        173 |
| Go         |    82 |         76 |
| TypeScript |    30 |         30 |
| **Total**  | **669** |    **613** |

(Some upstream `.yaml` files define more than one rule, hence rules ≠ files.)

Both directories vendor **rule definition files only** (`*.yaml`/`*.yml`
under `rules:`). Upstream's paired test fixtures (sample vulnerable/safe code
used by `opengrep-rules`' own test suite, e.g. `*.py`, `*.js`, `*.fixed.py`)
are intentionally not vendored — they aren't needed to run `opengrep scan`
and would only add noise to this repo.

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
   `owasp`/`cwe` present → `pr-blocking/`; everything for the four
   languages → `deep-scan/`), re-copying into this repo.
3. Update [`VERSION`](./VERSION) to `opengrep-rules@<new-40-char-sha>`.
4. Re-run the validation command above against both `pr-blocking/` and
   `deep-scan/` and confirm `0 configuration error(s)`.
5. Open a PR (never push straight to the default branch). `CODEOWNERS`
   requires `@seazone-tech/sre` review. Merge with a merge commit — do not
   squash (squashing on GitHub regenerates the commit message and can drop
   required trailers).
6. CI never re-fetches `opengrep-rules` live; the next scan only sees the
   new rules once this PR merges.

## `CODEOWNERS`

`@seazone-tech/sre` owns everything in this repo (see
[`CODEOWNERS`](./CODEOWNERS)).
