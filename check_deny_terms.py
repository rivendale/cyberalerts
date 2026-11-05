#!/usr/bin/env python3
"""Fail the build if any built output file contains a FEED_DENY_TERMS term.

Usage: python check_deny_terms.py <site-dir> [--require]

Terms come from the FEED_DENY_TERMS env var (comma or newline separated) and
are matched case-insensitively as plain substrings, against both the raw
and the HTML-unescaped text. Terms are never printed:
a hit reports only the file name and how many terms matched. With --require,
an empty or unset FEED_DENY_TERMS also fails (fail closed on main).
"""

from __future__ import annotations

import html
import os
import re
import sys
from pathlib import Path


def load_terms(raw: str | None) -> list[str]:
    terms: list[str] = []
    for line in (raw or "").replace("\r", "\n").split("\n"):
        for part in line.split(","):
            part = part.strip()
            if part:
                terms.append(part.lower())
    return terms


def _text_forms(raw: str) -> list[str]:
    """Raw, HTML-unescaped, and whitespace-collapsed forms (incl. U+00A0)."""
    once = html.unescape(raw)
    twice = html.unescape(once)
    forms = [raw, once, twice]
    out: list[str] = []
    for f in forms:
        low = f.lower()
        out.append(low)
        # Collapse any Unicode whitespace (including NBSP) so "fake\u00a0seat"
        # still matches deny term "fake seat".
        collapsed = re.sub(r"[\s\u00a0]+", " ", low)
        if collapsed not in out:
            out.append(collapsed)
    return out


def scan(site: Path, terms: list[str]) -> list[tuple[str, int]]:
    hits: list[tuple[str, int]] = []
    for path in sorted(p for p in site.rglob("*") if p.is_file()):
        raw = path.read_bytes().decode("utf-8", errors="replace")
        # Match the raw text and its HTML/XML-unescaped form, so a term with
        # & or an apostrophe can't slip past once escaped (twice, to catch
        # double-escaped feed text such as &amp;amp;). Also collapse
        # whitespace including U+00A0 so NBSP-separated terms still hit.
        forms = _text_forms(raw)
        n = sum(1 for t in terms if any(t in f for f in forms))
        if n:
            hits.append((str(path.relative_to(site)), n))
    return hits


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if a != "--require"]
    require = "--require" in argv[1:]
    if len(args) != 1:
        print("usage: check_deny_terms.py <site-dir> [--require]", file=sys.stderr)
        return 2
    site = Path(args[0])
    if not site.is_dir():
        print(f"not a directory: {site}", file=sys.stderr)
        return 2
    terms = load_terms(os.environ.get("FEED_DENY_TERMS"))
    if not terms:
        if require:
            print("FEED_DENY_TERMS is empty; FAIL CLOSED", file=sys.stderr)
            return 1
        print("FEED_DENY_TERMS not set; deny-term check skipped (non-main build)")
        return 0
    hits = scan(site, terms)
    if hits:
        for name, n in hits:
            print(f"deny term hit: {name} ({n} term(s); values not printed)", file=sys.stderr)
        return 1
    files = sum(1 for p in site.rglob("*") if p.is_file())
    print(f"deny-term check clean: {files} file(s), {len(terms)} term(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
