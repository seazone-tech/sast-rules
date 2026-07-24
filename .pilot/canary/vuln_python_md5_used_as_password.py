# CANARY FIXTURE — DELIBERATELY VULNERABLE. Never real code. See .pilot/canary/README.md.
#
# Expected: pr-blocking rule `md5-used-as-password`
# (pr-blocking/python/lang/security/audit/md5-used-as-password.yaml)
# CWE-327: Use of a Broken or Risky Cryptographic Algorithm (OWASP A02:2021 - Cryptographic Failures)
#
# Added 2026-07-24 (FU-C) when this taint-mode rule was promoted from
# deep-scan/ to pr-blocking/ — see README.md "Promoted exception" and the
# promotion metadata in the rule file itself.
#
# Deliberately uses `Crypto.Hash.MD5` (a bare reference, not
# hashlib.md5(...)) as the taint source flowing into a `*password*`-named
# sink, specifically so this fixture triggers ONLY md5-used-as-password
# and not also insecure-hash-algorithm-md5-hashlib (which only matches
# hashlib.md5(...) calls) — preserving the "exactly one finding per
# fixture" invariant this canary relies on. A hashlib.md5(...)-based
# real-world example would legitimately fire both rules at once; that
# combined-firing case is proven separately in the FU-C report, not here.

import Crypto.Hash.MD5


def hash_password_for_storage(raw_password: bytes) -> None:
    digest = Crypto.Hash.MD5
    store_password(digest)


def store_password(hashed: object) -> None:
    """Pretend persistence layer — sink function name matches /password/i."""
