#!/usr/bin/env python3
"""Fail if tracked SendBeam source carries a conflicting SPDX license."""
import subprocess
import sys

SOURCE_GLOBS = (
    "*.go",
    "*.ts",
    "*.tsx",
    "*.js",
    "*.svelte",
    "*.css",
    "*.html",
    "*.sh",
    "*.py",
)
EXPECTED = "MIT"


def main() -> int:
    files = subprocess.run(
        ["git", "ls-files", "-z", "--", *SOURCE_GLOBS],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout.decode().split("\0")
    conflicts = []
    checked = 0
    for path in filter(None, files):
        with open(path, encoding="utf-8", errors="replace") as source:
            for number, line in enumerate(source, start=1):
                marker = "SPDX-License-Identifier:"
                if marker not in line:
                    if number > 20:
                        break
                    continue
                checked += 1
                declared = line.split(marker, 1)[1].strip()
                if declared != EXPECTED:
                    conflicts.append((path, number, declared))
    if conflicts:
        for path, number, declared in conflicts:
            print(f"{path}:{number}: SPDX license {declared!r}; expected {EXPECTED}")
        return 1
    print(f"SPDX license check passed: {checked} declarations are {EXPECTED}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
