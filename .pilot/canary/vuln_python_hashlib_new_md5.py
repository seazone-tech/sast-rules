# CANARY FIXTURE — DELIBERATELY VULNERABLE. Never real code. See .pilot/canary/README.md.
#
# Expected: pr-blocking rule `insecure-hash-function`
# (pr-blocking/python/lang/security/insecure-hash-function.yaml)
# CWE-327: Use of a Broken or Risky Cryptographic Algorithm (OWASP A02:2021 - Cryptographic Failures)
#
# Added 2026-07-24 (FU-C) when this rule was promoted from deep-scan/ to
# pr-blocking/ — see README.md "Promoted exception" and the promotion
# metadata in the rule file itself. This triggers the generic
# hashlib.new("md5", ...) constructor form, distinct from the direct
# hashlib.md5(...) call covered by insecure-hash-algorithm-md5-hashlib.
# NOTE: hashlib.new("sha1", ...) is a documented gap — this same rule's
# regex does NOT match "sha1" (only 3-char MD4/MD5 names); see the rule
# file's metadata for the full writeup. Do not add a
# vuln_python_hashlib_new_sha1.py fixture — it would fail (0 findings),
# since no vendored deep-scan/ rule currently covers that pattern.

import hashlib


def weak_hash(data: bytes) -> str:
    """Insecure: MD5 (via the generic hashlib.new constructor) is not
    collision-resistant and must not be used for any cryptographic
    signature purpose."""
    return hashlib.new("md5", data).hexdigest()
