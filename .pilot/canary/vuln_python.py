# CANARY FIXTURE — DELIBERATELY VULNERABLE. Never real code. See .pilot/canary/README.md.
#
# Expected: pr-blocking rule `insecure-hash-algorithm-md5`
# (pr-blocking/python/pycryptodome/security/insecure-hash-algorithm-md5.yaml)
# CWE-327: Use of a Broken or Risky Cryptographic Algorithm (OWASP A02:2021 - Cryptographic Failures)
#
# This is the exact rule id confirmed by the live gate test in Task 4 (a seeded
# insecure-hash-algorithm-md5 vuln turned a real PR red; a clean PR stayed green).

import Crypto.Hash.MD5


def hash_password(password: str) -> bytes:
    """Insecure: MD5 is not collision-resistant and must not be used for
    password hashing or any cryptographic signature purpose."""
    h = Crypto.Hash.MD5.new()
    h.update(password.encode("utf-8"))
    return h.digest()
