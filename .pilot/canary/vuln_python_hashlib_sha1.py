# CANARY FIXTURE — DELIBERATELY VULNERABLE. Never real code. See .pilot/canary/README.md.
#
# Expected: pr-blocking rule `insecure-hash-algorithm-sha1-hashlib`
# (pr-blocking/python/lang/security/insecure-hash-algorithms-sha1.yaml)
# CWE-327: Use of a Broken or Risky Cryptographic Algorithm (OWASP A02:2021 - Cryptographic Failures)
#
# Added 2026-07-24 (FU-C) when this rule was promoted from deep-scan/ to
# pr-blocking/ — see README.md "Promoted exception" and the promotion
# metadata in the rule file itself. Separate fixture from the MD5 ones on
# purpose: this triggers hashlib.sha1(...), the direct SHA1 sibling of the
# hashlib.md5(...) rule promoted earlier by FU-B. Kept in its own file to
# preserve the "exactly one finding per fixture" invariant this canary
# relies on.

import hashlib


def weak_hash(data: bytes) -> str:
    """Insecure: SHA1 is not collision-resistant and must not be used for
    any cryptographic signature purpose."""
    return hashlib.sha1(data).hexdigest()
