#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# ─── How to run ───
# python3 scripts/lint-ratchet/common.py --self-test (no installation needed)
"""Shared source helpers; parser API ported from rmcp-server-kit (MIT/Apache-2.0).

The item-scanner adapter imports todo 13's scanner explicitly.
Offsets here are Python character offsets, never compiler UTF-8 byte offsets.
"""

from __future__ import annotations

import fnmatch
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Iterator

ROOT: Final = Path(__file__).resolve().parents[2]
CORE_REL: Final = Path("docs/rust-guidelines/RUST_GUIDELINES.md")
ROOTS: Final = ("src", "tests", "examples", "benches", "fuzz/fuzz_targets")


from rust_lex import (
    AttributeCall,
    attribute_calls,
    iter_attributes,
    line_of,
    match_bracket,
    split_top_level,
    strip_comments_and_strings,
)


def iter_rust_files(root: Path) -> Iterator[Path]:
    for base in ROOTS:
        yield from sorted((root / base).rglob("*.rs"))


def read_source(path: Path) -> tuple[str, str]:
    text = path.read_bytes().decode("utf-8")
    return text, strip_comments_and_strings(text)


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["env", "GIT_MASTER=1", "flock", "/tmp/rskrb5-git.lock", "git", *args],
        cwd=root,
        check=True,
        text=True,
        capture_output=True,
    ).stdout


def selected(path: str, patterns: list[str] | None) -> bool:
    return not patterns or any(fnmatch.fnmatch(path, p) for p in patterns)


def blank_ranges(text: str, ranges: list[tuple[int, int]]) -> str:
    out = list(text)
    for a, b in ranges:
        out[a:b] = [c if c in "\r\n" else " " for c in text[a:b]]
    return "".join(out)


def migration_ranges(text: str) -> list[tuple[int, int]]:
    """Include generated doctest attributes, but not ordinary doc prose."""
    ranges = {
        (c.start, c.end)
        for c in attribute_calls(text)
        if c.reason.startswith("lint-migration:")
    }
    for match in re.finditer(r"(?m)^\s*///\s*#\s*(#!?\[.*lint-migration:.*)$", text):
        ranges.add((match.start(), match.end()))
    return sorted(ranges)


@dataclass(frozen=True, slots=True)
class Item:
    start: int
    end: int
    keyword: int
    kind: str
    name: str
    identity: str


def scan_items(source: str) -> list[Item]:
    """Adapt todo 13 scanner byte ranges to the gate parser character offsets."""
    import scanner

    data = source.encode()
    result = []
    for item in scanner.scan_items(data):
        start = len(data[: item.start].decode())
        end = len(data[: item.end].decode())
        clean = strip_comments_and_strings(source[start:end])
        clean = blank_ranges(clean, [(a, b) for a, b, _, _ in iter_attributes(clean)])
        match = re.search(r"\b" + re.escape(item.kind) + r"\b", clean)
        if match is None:
            continue
        name = item.identity.rsplit("::fn ", 1)[-1].removeprefix("fn ")
        result.append(
            Item(start, end, start + match.start(), item.kind, name, item.identity)
        )
    return result


def owner(items: list[Item], offset: int) -> Item | None:
    return min(
        (item for item in items if item.start <= offset < item.end),
        key=lambda item: item.end - item.start,
        default=None,
    )


def cfg_test_line_ranges(stripped: str) -> list[tuple[int, int]]:
    ranges = []
    items = scan_items(stripped)
    for a, b, _, body in iter_attributes(stripped):
        predicate = body.strip()
        if predicate == "cfg(test)" or re.match(r"cfg\(all\(\s*test\s*[,)]", predicate):
            item = owner(items, b)
            if item is not None:
                ranges.append((line_of(stripped, a), line_of(stripped, item.end)))
    return ranges


def in_ranges(line: int, ranges: list[tuple[int, int]]) -> bool:
    return any(a <= line <= b for a, b in ranges)


def self_test() -> int:
    source = "// #[allow(fake)]\nconst S: &str = r#\"{ /* }\"#;\n#[cfg_attr(test, allow(dead_code), derive(Debug))]\nfn f<'a>() { let c = '{'; }\n"
    calls = attribute_calls(source)
    assert len(calls) == 1 and calls[0].lints == ("dead_code",)
    assert calls[0].predicate == "test"
    assert len(strip_comments_and_strings(source)) == len(source)
    assert (
        attribute_calls(
            "#[cfg_attr(test, cfg_attr(unix, allow(x)), allow(y), derive(Debug))]"
        )[0].predicate
        == "all(test, unix)"
    )
    print("common self-test: ok (cfg_attr siblings, lexemes)")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else 2)
