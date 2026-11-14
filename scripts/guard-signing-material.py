#!/usr/bin/env python3
"""SEC01 guard core: key-bound scan for production signing material.

Pure-stdlib RFC 8032 Ed25519 public-key derivation so that candidate seeds
found in tracked Go files can be checked against the production trust anchor
cryptographically (not just by literal match). Prints violations to stdout;
empty output means clean.
"""
import base64
import hashlib
import os
import re
import subprocess
import sys

# ---- RFC 8032 reference Ed25519 (public-key derivation only) --------------
p = 2**255 - 19
b = 256

def _h(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()

def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1

def _inv(x: int) -> int:
    return pow(x, p - 2, p)

_d = -121665 * _inv(121666) % p
_I = pow(2, (p - 1) // 4, p)

def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = (x * _I) % p
    if x % 2 != 0:
        x = p - x
    return x

_By = 4 * _inv(5) % p
_Bx = _xrecover(_By)
_B = [_Bx % p, _By % p]

def _edwards_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return [x3 % p, y3 % p]

def _scalarmult(P, e):
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q

def _encodepoint(P) -> bytes:
    x, y = P
    out = [(y >> i) & 255 for i in range(b // 8)]
    out[31] |= (x & 1) << 7
    return bytes(out)

def ed25519_public_key(seed: bytes) -> bytes:
    hh = _h(seed)
    a = 2 ** (b - 2) + sum(2 ** i * _bit(hh, i) for i in range(3, b - 2))
    return _encodepoint(_scalarmult(_B, a))

# ---- guard ----------------------------------------------------------------
RETIRED_SEED_PART1 = "d022346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533"
RETIRED_SEED_PART2 = "ad"

def main() -> int:
    pin_raw = base64.b64decode(os.environ["PIN_B64"])
    pin_pub = pin_raw[10:42]
    # Retired fixture seed, assembled from split parts so that this guard's
    # own tracked source never contains the contiguous literal it detects.
    retired = (RETIRED_SEED_PART1 + RETIRED_SEED_PART2).encode()
    sanctioned = [
        s
        for s in os.environ.get("SANCTIONED_PIN_FILES", "packages/engine/updater/verify.go").split(",")
        if s
    ]

    args = sys.argv[1:]
    if args and args[0] == "--scan-dir":
        root = os.path.abspath(args[1])
        files = []
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                files.append(os.path.join(dirpath, name))
        tracked_mode = False
    else:
        out = subprocess.run(["git", "ls-files"], capture_output=True, text=True)
        files = out.stdout.splitlines()
        tracked_mode = True

    violations = []

    # (5) trust-root consistency (tracked mode): the committed minisign.pub
    # must equal the compiled production pin constant. A partial swap
    # (one file changed, the other forgotten) is the realistic unauthorized
    # trust-root change; it must fail CI, not silently pass release
    # verification. (A fully-consistent swap is a review-visible event.)
    if tracked_mode:
        try:
            pub_lines = [
                l.strip()
                for l in open("minisign.pub", encoding="utf-8").read().splitlines()
                if l.strip() and not l.startswith("untrusted comment:")
            ]
            vsrc = open("packages/engine/updater/verify.go", encoding="utf-8").read()
            m = re.search(r'DefaultMinisignPublicKey\s*=\s*"([^"]+)"', vsrc)
            if pub_lines and m:
                if pub_lines[0] != m.group(1):
                    violations.append(
                        "trust-root mismatch: minisign.pub does not match "
                        "DefaultMinisignPublicKey in packages/engine/updater/verify.go "
                        "(unauthorized or partial trust-root change)"
                    )
        except OSError:
            pass

    hex64 = re.compile(rb"[0-9a-fA-F]{64}")
    for f in files:
        rel = os.path.relpath(f) if tracked_mode else f
        try:
            data = open(f, "rb").read()
        except OSError:
            continue
        # (1) retired seed literal: EVERY tracked file type
        if retired in data:
            violations.append(f"{f}: retired production-derived fixture seed literal")
            continue
        if not f.endswith(".go"):
            continue
        # (2) production pinned public key bound outside the sanctioned verifier
        if not any(f == s or f.endswith("/" + s) or rel == s for s in sanctioned):
            if os.environ["PIN_B64"].encode() in data:
                violations.append(
                    f"{f}: production pinned public key bound outside sanctioned files "
                    f"({','.join(sanctioned)}); test/tool keys must be independent"
                )
        # (2b) tests must not reference the production pin symbol at all
        if f.endswith("_test.go") and b"DefaultMinisignPublicKey" in data:
            violations.append(
                f"{f}: test file references DefaultMinisignPublicKey; "
                "tests must bind to independent disposable keys"
            )
        # (3) key-bound scan of every 64-hex literal in Go files
        for m in hex64.finditer(data):
            tok = m.group(0)
            if tok.lower() == retired.lower():
                continue  # already reported by (1)
            try:
                seed = bytes.fromhex(tok.decode())
            except ValueError:
                continue
            try:
                pub = ed25519_public_key(seed)
            except Exception:
                continue
            if pub == pin_pub:
                fp = hashlib.sha256(seed).hexdigest()
                violations.append(
                    f"{f}: 64-hex literal derives the PRODUCTION signing key "
                    f"(seed sha256 fingerprint {fp[:16]}...{fp[-16:]})"
                )
    sys.stdout.write("\n".join(violations))
    return 0

if __name__ == "__main__":
    sys.exit(main())
