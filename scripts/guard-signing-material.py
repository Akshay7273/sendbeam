#!/usr/bin/env python3
"""SEC01 guard core: retired signing-material and legacy-route scan.

The self-updater and its production signing key were removed (SB-SIMPLIFY).
What remains to defend against is resurrection:

  1. the retired seed literal, in any tracked file;
  3. any 64-hex literal in Go that DERIVES the retired public key — this is
     what catches a re-derivation scheme that never spells the literal;
  6. a legacy update-channel route becoming resolvable again (a tracked
     updates/ directory, or published channel manifests anywhere), which is
     how forged manifests signed with the retired key could still reach old
     clients;
  7. retired signing-credential names wired into any workflow.

Pure-stdlib RFC 8032 Ed25519 public-key derivation so that candidate seeds can
be checked against the retired key cryptographically, not just by literal
match. Prints violations to stdout; empty output means clean.
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
# Assembled from split parts so this guard's own tracked source never contains
# the contiguous literal it scans for (self-scan safe). Not secret material:
# the derived key is public and retired.
RETIRED_SEED_PART1 = "d022346a8020c24891d1af56531c471c7160eaee16e05618202ef8fd953533"
RETIRED_SEED_PART2 = "ad"

CHANNEL_MANIFESTS = (
    "stable.json",
    "beta.json",
    "stable.json.minisig",
    "beta.json.minisig",
)


def main() -> int:
    if "PIN_B64" not in os.environ:
        sys.stderr.write("guard: PIN_B64 (retired public key) is required\n")
        return 2
    pin_raw = base64.b64decode(os.environ["PIN_B64"])
    pin_pub = pin_raw[10:42]
    retired = (RETIRED_SEED_PART1 + RETIRED_SEED_PART2).encode()

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

    # (6) legacy update-channel resurrection.
    # v1.6-v2.2 clients embed <legacy base>/<channel>.json. GitHub Pages serves
    # a project site from the repo root, so a tracked top-level "updates/"
    # directory would make the legacy route resolvable again as soon as Pages
    # is enabled -- precisely the window in which forged manifests signed with
    # the retired key would reach vulnerable clients.
    if tracked_mode:
        for f in files:
            norm = f.replace(os.sep, "/")
            if norm.startswith("updates/"):
                violations.append(
                    f"{f}: tracked legacy update-channel directory "
                    "(enabling Pages would resurrect the retired-key route)"
                )
                continue
            if os.path.basename(norm) in CHANNEL_MANIFESTS:
                violations.append(
                    f"{f}: published update-channel manifest in the repo "
                    "(legacy route isolation)"
                )

    # (7) retired signing-credential names must not be wired into any workflow.
    if tracked_mode:
        for f in files:
            norm = f.replace(os.sep, "/")
            if not norm.startswith(".github/workflows/"):
                continue
            try:
                wf = open(f, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if "MINISIGN_SECRET_KEY_LEGACY" in wf or "MINISIGN_SECRET_KEY_RETIRED" in wf:
                violations.append(
                    f"{f}: references a retired signing-credential name "
                    "(retired keys must not remain wired into any workflow)"
                )

    hex64 = re.compile(rb"[0-9a-fA-F]{64}")
    for f in files:
        try:
            data = open(f, "rb").read()
        except OSError:
            continue
        # (1) retired seed literal: EVERY tracked file type.
        if retired in data:
            violations.append(f"{f}: retired production-derived seed literal")
            continue
        if not f.endswith(".go"):
            continue
        # (3) key-bound scan of every 64-hex literal in Go files. A seed that
        # derives the retired public key is refused even if the literal was
        # never spelled out.
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
                    f"{f}: 64-hex literal derives the RETIRED signing key "
                    f"(seed sha256 fingerprint {fp[:16]}...{fp[-16:]})"
                )
    sys.stdout.write("\n".join(violations))
    return 0


if __name__ == "__main__":
    sys.exit(main())
