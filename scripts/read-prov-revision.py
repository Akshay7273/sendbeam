#!/usr/bin/env python3
"""Read org.opencontainers.image.revision from a buildx provenance JSON
(duck-typed: attestations nest it). Prints the revision or nothing."""
import json
import sys


def find_rev(obj):
    if isinstance(obj, dict):
        if obj.get("org.opencontainers.image.revision"):
            return obj["org.opencontainers.image.revision"]
        for v in obj.values():
            r = find_rev(v)
            if r:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_rev(v)
            if r:
                return r
    return ""


def main():
    raw = sys.stdin.read()
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(raw):
        while idx < len(raw) and raw[idx].isspace():
            idx += 1
        if idx >= len(raw):
            break
        try:
            data, consumed = decoder.raw_decode(raw, idx)
        except Exception:
            idx += 1
            continue
        idx += consumed
        rev = find_rev(data)
        if rev:
            print(rev)
            return


if __name__ == "__main__":
    main()
