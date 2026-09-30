#!/usr/bin/env python3
"""Deterministic desktop frontend assembler (V23-PR01).

Reconstructs dist/index.html byte-for-byte from the source files in src/.
No bundler, no minifier, no transformation: exact string substitution of the
marked source slots. A mismatch means a source file drifted from dist — run
this script to regenerate.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
DIST = ROOT / "dist" / "index.html"

MARK_CSS = "    <!-- @styles.css -->"
MARK_JS = "    <!-- @app.js -->"

template = (SRC / "index.template.html").read_text(encoding="utf-8")
css = (SRC / "styles.css").read_text(encoding="utf-8")
js = (SRC / "app.js").read_text(encoding="utf-8")

out = template.replace(MARK_CSS, "    <style>\n" + css + "    </style>")
out = out.replace(MARK_JS, "    <script>\n" + js + "    </script>")

if len(sys.argv) > 1 and sys.argv[1] == "--check":
    current = DIST.read_text(encoding="utf-8")
    if current != out:
        sys.stderr.write(
            "dist/index.html does not match sources — "
            "run: python3 tools/build.py\n"
        )
        sys.exit(1)
    print("dist/index.html matches sources (byte-for-byte)")
else:
    DIST.parent.mkdir(parents=True, exist_ok=True)
    DIST.write_text(out, encoding="utf-8")
    print(f"wrote {DIST} ({len(out)} bytes)")
