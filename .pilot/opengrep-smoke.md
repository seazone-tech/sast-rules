# Opengrep smoke test — pilot repo `automation-amenities-do-anuncio`

Date: 2026-07-24
Engine: **Opengrep v1.25.0** (installed via official `install.sh -v v1.25.0`, no Docker image published upstream — binary install confirmed working, per Task 1).
Rules: this repo (`sast-rules`, branch `dev`), commit `fc91dcc43ce5a07798d0b4f152b338dcb7f05426` — `pr-blocking/` (45 rule files) and `deep-scan/` (613 rule files, 669 rules loaded by the engine — some files define more than one rule).

Target repo: `seazone-tech/automation-amenities-do-anuncio`, branch `main`, commit `772e9a67e2a003694fa5a7ccd725e0c65920c8df`. Small Python/FastAPI service, 21 `.py` files, ~132 KB, 6 commits total (history includes one merge commit, so first-parent depth is only 5).

## 1. Full scan, `pr-blocking/`

```
time opengrep scan --config <path>/sast-rules/pr-blocking/ --sarif --output /tmp/pb-full.sarif .
```

- Rules loaded: 45 (only 17 matched the repo's language — Python; the rest target Go/JS/etc. not present here)
- Files scanned: 16 Python files (of 29 tracked)
- Wall time: **2.964s** (`user 11.710s`, `sys 2.371s` — parallelized across cores)
- **Exit code: 0** — see "Exit code caveat" below, this does **not** mean "no findings" by itself
- **Findings: 0**

The pilot repo is small and clean; pr-blocking rules produced zero real findings against it. Because of that, the *actual* SARIF `results[]` array is empty, so there is no in-repo sample of finding-level severity to histogram directly. To still answer the "where does severity live and what does it look like" question precisely, a supplementary synthetic check was run (see §5).

## 2. SARIF severity ("level") — pr-blocking

```
jq -r '.runs[0].results[]?.level' /tmp/pb-full.sarif | sort | uniq -c
```
→ empty (0 results, consistent with §1).

Since there are no results to histogram in-repo, the **rule-level** severity assignments (`tool.driver.rules[].defaultConfiguration.level`, one entry per rule in the SARIF `run`) were pulled instead — this is the severity each rule *would* stamp if it fired:

```
jq -r '.runs[0].tool.driver.rules[].defaultConfiguration.level' /tmp/pb-full.sarif | sort | uniq -c
```
```
     17 error
      1 note
     27 warning
```

Out of 45 pr-blocking rules: **27 warning (60%), 17 error (38%), 1 note (2%)**. Most pr-blocking rules are NOT `error` severity.

**Critical detail (see §5): SARIF `result.level` is not populated on individual results at all** — it is `null` even for a rule whose own `defaultConfiguration.level` is `error`. Severity must be recovered by joining `result.ruleId` → `tool.driver.rules[].id` → `.defaultConfiguration.level`. `result.properties` is empty (`{}`) — severity does **not** live there either.

## 3. Diff-aware scan, `pr-blocking/`

Brief's recipe: if commit count ≥ 6, use `--baseline-commit HEAD~5`. `git rev-list --count HEAD` = 6, but `HEAD~5` was **ambiguous** (`fatal: ambiguous argument 'HEAD~5'`) because the target repo's history contains a merge commit (PR #1), so the first-parent chain is only 5 commits deep, not 6. Fell back to the documented alternative — the repo's actual root commit:

```
git rev-list --max-parents=0 HEAD   →  b4a2b1d529a28151a5d01af59903cd2b03273fbb
opengrep scan --config <path>/sast-rules/pr-blocking/ --baseline-commit b4a2b1d5... --sarif --output /tmp/pb-diff.sarif .
```

- Wall time: 2.966s
- Scan scoped to **2 files changed since baseline** (vs. 16 files in the full scan) — confirms diff-awareness narrows the file set correctly.
- "Current version has 0 findings. Skipping baseline scan" → **0 findings**, ≤ the full-scan count of 0 (trivially satisfied; the pilot repo has no findings at either commit, so this run proves diff-scoping mechanics but not finding-count reduction).

## 4. Deep-scan sizing (Phase 1 input)

```
time opengrep scan --config <path>/sast-rules/deep-scan/ --sarif --output /tmp/ds-full.sarif .
```

- Rules loaded: 669 (365 Python-specific + 4 multilang, per opengrep's own summary table)
- Files scanned: 24 of 29 tracked
- Wall time: **24.899s** (`user 2m41.231s`, `sys 34.093s`)
- **Findings: 0**

## 5. Supplementary sanity check (not part of the pilot-repo numbers)

Because both real scans returned 0 findings, a synthetic 8-line Python file was scanned in an isolated scratch git repo to confirm the engine and SARIF plumbing actually work end-to-end and to pin down exactly where severity lives:

```python
import jwt, hashlib
def make_token(payload):
    return jwt.encode(payload, "hardcoded-super-secret-key", algorithm="HS256")
def weak_hash(data):
    return hashlib.md5(data).hexdigest()
```

`opengrep scan --config pr-blocking/ --sarif --output ...` → **1 finding**: `python.jwt.security.jwt-python-hardcoded-secret` (rule severity `ERROR` per its YAML, and `defaultConfiguration.level: "error"` in the SARIF `tool.driver.rules[]` entry).

- `result.level` → **`null`** (absent from the result object)
- `result.properties` → `{}` (empty)
- Confirms: `.level` is **only** recoverable via the rule-definition join, never inline on the result.

**Exit code, checked explicitly with this real (non-zero) finding present:**
- Default `opengrep scan` (no extra flags): **exit 0**, even with 1 finding. Confirmed via `opengrep scan --help`: default exit status is `0` on "success" (i.e., the scan ran cleanly), regardless of finding count.
- `opengrep scan --error ...` (with the finding present): **exit 1**.
- `opengrep scan --error ...` re-run against the real pilot repo (0 findings): **exit 0**.

So the brief's assumption "exit code 1 = findings present" is only true when `--error` is passed explicitly — by default, findings do not affect the exit code at all.

## Implications

**(a) Is `-f=sarif` → reviewdog consumption feasible?** Partially, with a caveat. The SARIF is well-formed and reviewdog can parse it, but `result.level` is **not populated** on any individual result — it is `null`/absent across the board, confirmed both on a real finding and structurally by rule design. Per the SARIF spec, a missing `result.level` should be inherited from the matching `tool.driver.rules[].defaultConfiguration.level`, but this requires the consumer to actually perform that rule-id lookup rather than reading `result.level` naively. **Before wiring reviewdog in Phase 1, explicitly verify reviewdog's SARIF reader performs this defaultConfiguration fallback** — do not assume it does. If it doesn't, the pipeline will need a small transform step that copies `tool.driver.rules[].defaultConfiguration.level` onto each `result.level` before handing the SARIF to reviewdog.

**(b) What the severity distribution means for the Task 3 gate.** Two compounding risks were found, both of which make a naive "fail on error" or "fail on nonzero exit code" gate unsafe:

1. Of the 45 pr-blocking rules, only 17 (38%) are `error`-level; 27 (60%) are `warning`, 1 is `note`. A gate that only fails on SARIF `level=error` (or an equivalent `-fail-level=error` type flag) would silently let ~60% of pr-blocking rule categories through even when they fire.
2. `opengrep scan`'s exit code is **0 by default regardless of findings** — it only becomes 1 if `--error` is passed. A gate script that just checks `$?` without `--error` will never fail, no matter what severity fired.

**Recommendation for Task 3:** the gate criterion must be **"any pr-blocking finding on a changed line"** — i.e., a non-empty `results[]` array from a diff-aware pr-blocking scan — not a severity- or exit-code-based check. If the gate script invokes opengrep directly, it must either pass `--error` explicitly or (more robustly, since severity can't be trusted to gate on `level`) parse the SARIF/JSON output and fail on `len(results) > 0`, independent of `.level`.

## Raw commands & counts reference

| Step | Wall time | Exit code (default) | Findings |
|---|---|---|---|
| pr-blocking full scan | 2.964s | 0 | 0 |
| pr-blocking diff scan (baseline = root commit) | 2.966s | 0 | 0 |
| deep-scan full scan | 24.899s | 0 | 0 |
| sanity-check pr-blocking scan (synthetic vuln file) | n/a | 0 (1 with `--error`) | 1 |
