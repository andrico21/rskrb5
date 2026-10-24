#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/baseline_sources.py --self-test
"""Source evidence for baseline moves, anchored to the ratchet-base item."""

from __future__ import annotations

import difflib
import re
from collections import Counter
from pathlib import Path

import common
from baseline_moves import Entry, Move

MANIFEST = "scripts/lint-ratchet/baseline.toml"


def ratchet_base(root: Path) -> str | None:
    history = common.git(root, "log", "--format=%H %s", "--", MANIFEST)
    return next(
        (
            row.split(" ", 1)[0]
            for row in history.splitlines()
            if re.match(
                r"[0-9a-f]+ lint: (?:rebaseline for Rust |adopt the rmcp-server-kit strictest profile)",
                row,
            )
        ),
        None,
    )


def bodies(source: str) -> dict[str, tuple[str, ...]]:
    import scanner

    data = source.encode()
    result = {}
    duplicates = set()
    for item in scanner.scan_items(data):
        text = (
            data[item.body_start : item.end].decode()
            if item.body_start
            else data[item.start : item.end].decode()
        )
        text = common.blank_ranges(text, common.migration_ranges(text))
        text = common.strip_comments_and_strings(text, keep_literals=True)
        lines = tuple(
            "".join(line.split())
            for line in text.splitlines()
            if line.strip() not in ("", "{", "}")
        )
        if item.identity in result:
            duplicates.add(item.identity)
        result[item.identity] = lines
    return {key: value for key, value in result.items() if key not in duplicates}


def source_moves(base: str, current: str) -> frozenset[tuple[str, str]]:
    old, new = bodies(base), bodies(current)
    moves = set()
    for before in old.keys() - new.keys():
        for after in new.keys() - old.keys():
            is_use = before.startswith("use ") and after.startswith("use ")
            same_body = (
                difflib.SequenceMatcher(
                    None, old[before], new[after], autojunk=False
                ).ratio()
                >= 0.6
            )
            if is_use or same_body:
                moves.add((before, after))
    return frozenset(moves)


def prove(
    root: Path,
    entries: tuple[Counter[Entry], Counter[Entry]],
    revisions: tuple[str, str | None],
) -> frozenset[Move]:
    previous, current = entries
    base, revision = revisions
    files = {entry[0] for entry in current - previous}
    result = set()
    for file in files:
        if not any(e[0] == file for e in previous):
            continue
        base_source = common.git(root, "show", f"{base}:{file}")
        source = (
            common.git(root, "show", f"{revision}:{file}")
            if revision
            else (root / file).read_text()
        )
        result.update(
            ((file, old), (file, new)) for old, new in source_moves(base_source, source)
        )
    return frozenset(result)


def self_test() -> None:
    base = 'fn f() {\n let bytes = decode_hex(DATA);\n let key = parse(&bytes).expect("parses");\n assert_eq!(key.bytes(), bytes);\n}\n'
    wrap = "mod tests {\n" + base + "}\n"
    # Given the original body, when wrapped, then source proof succeeds.
    assert ("fn f", "mod tests::fn f") in source_moves(base, wrap)
    exploit = 'mod sneaky {\nfn f() {\nlet smuggled: Option<u8> = None;\nlet value = smuggled.expect("NEW fork code");\n}\n}\n'
    assert ("fn f", "mod sneaky::fn f") not in source_moves(base, exploit)
    assert not source_moves(base, base + wrap)
    print("baseline_sources self-test: ok (body identity, exploit, retained source)")


if __name__ == "__main__":
    self_test()
