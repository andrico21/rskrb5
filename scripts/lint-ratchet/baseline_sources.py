#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/baseline_sources.py --self-test
"""Ratchet-base evidence: same-name new-module wraps need 0.45 body similarity.

The original site must disappear and each source/destination must be unique.
Use re-keys retain their separate count-preserving check in baseline_moves.
"""

from __future__ import annotations

import difflib
import re
from collections import Counter
from pathlib import Path

import common
from baseline_moves import MODULE_PREFIX, Entry, Move

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
    """Prove only unambiguous moves into newly created module wrappers."""
    old, new = bodies(base), bodies(current)
    moves = set()
    for before in old.keys() - new.keys():
        for after in new.keys() - old.keys():
            is_use = before.startswith("use ") and after.startswith("use ")
            prefix = after[: -len(before)] if after.endswith(before) else ""
            wrapped = (
                not before.startswith("mod ")
                and bool(MODULE_PREFIX.fullmatch(prefix))
                and all(
                    prefix[: match.end() - 2] not in old
                    for match in re.finditer(r"mod (?:r#)?\w+::", prefix)
                )
            )
            same_body = (
                difflib.SequenceMatcher(
                    None, old[before], new[after], autojunk=False
                ).ratio()
                >= 0.45
            )
            if is_use or (wrapped and same_body):
                moves.add((before, after))
    sources = Counter(before for before, _ in moves)
    targets = Counter(after for _, after in moves)
    return frozenset(
        (before, after)
        for before, after in moves
        if (before.startswith("use ") and after.startswith("use "))
        or sources[before] == targets[after] == 1
    )


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
    base = 'fn roundtrips_gokrb5_keytab_fixture() {\n let bytes = decode_hex(KEYTAB_TESTUSER1_TEST_GOKRB5);\n let keytab = Keytab::parse(&bytes).expect("keytab fixture parses");\n assert_eq!(keytab.to_bytes().expect("keytab serializes"), bytes);\n}\n'
    wrap = "mod tests {\n" + base + "}\n"
    # Given the original body, when wrapped, then source proof succeeds.
    site = "fn roundtrips_gokrb5_keytab_fixture"
    assert (site, "mod tests::" + site) in source_moves(base, wrap)
    exploit = 'mod sneaky {\nfn roundtrips_gokrb5_keytab_fixture() {\nlet smuggled: Option<u8> = None;\nlet _value = smuggled.expect("NEW fork code hidden behind a moved baseline credit");\n}\n}\n'
    ratio = difflib.SequenceMatcher(
        None,
        bodies(base)[site],
        bodies(exploit)["mod sneaky::" + site],
        autojunk=False,
    ).ratio()
    assert ratio == 0.0
    assert (site, "mod sneaky::" + site) not in source_moves(base, exploit)
    assert not source_moves(base, base + wrap)
    assert not source_moves("mod tests {}\n" + base, wrap)
    assert not source_moves(base, wrap + wrap.replace("mod tests", "mod other"))
    assert not source_moves(
        base, wrap.replace("roundtrips_gokrb5_keytab_fixture", "other")
    )
    from baseline_sources_fixtures import self_test as fixture_test

    fixture_test()
    print(
        "baseline_sources self-test: ok (new wrappers, unique identity, exploit similarity 0.000)"
    )


if __name__ == "__main__":
    self_test()
