# CANARY FIXTURE — DELIBERATELY VULNERABLE. Never real code. See .pilot/canary/README.md.
#
# Expected: pr-blocking rule `insecure-hash-algorithm-md5-hashlib`
# (pr-blocking/python/lang/security/insecure-hash-algorithms-md5.yaml)
# CWE-327: Use of a Broken or Risky Cryptographic Algorithm (OWASP A02:2021 - Cryptographic Failures)
#
# Added 2026-07-24 when this rule was promoted from deep-scan/ to pr-blocking/
# (see README.md "Rules promoted from deep-scan/" and the promotion metadata
# in the rule file itself). Separate fixture from vuln_python.py on purpose:
# that fixture triggers the pycryptodome-specific `insecure-hash-algorithm-md5`
# rule (Crypto.Hash.MD5.new(...)); this one triggers the hashlib-specific
# rule (hashlib.md5(...)) added by this promotion. Keeping them in separate
# files preserves the "exactly one finding per fixture" invariant this canary
# relies on.

import hashlib


def weak_hash(data: bytes) -> str:
    """Insecure: MD5 is not collision-resistant and must not be used for
    password hashing or any cryptographic signature purpose."""
    return hashlib.md5(data).hexdigest()
