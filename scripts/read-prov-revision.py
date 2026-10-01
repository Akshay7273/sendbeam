#!/usr/bin/env python3
"""Read org.opencontainers.image.revision from a buildx provenance JSON
(duck-typed: attestations nest it). Prints the revision or nothing."""
import json
import sys


def find_rev(obj):
    if isinstance(obj, dict):
        # image-config labels (imagetools inspect --format '{{json .Image}}')
        labels = obj.get("config", {})
        labels = labels.get("Labels") if isinstance(labels, dict) else None
        if isinstance(labels, dict):
            v = labels.get("org.opencontainers.image.revision")
            if v:
                return v
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
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return
        data = json.loads(raw)
    except Exception:
        return
    rev = find_rev(data)
    if rev:
        print(rev)


if __name__ == "__main__":
    main()
