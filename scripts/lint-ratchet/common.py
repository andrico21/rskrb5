#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# ─── How to run ───
# python3 scripts/lint-ratchet/common.py --self-test (no installation needed)
"""Shared provenance mapping; parser API ported from rmcp-server-kit (MIT/Apache-2.0).

The item-scanner adapter imports todo 13's scanner explicitly.
Offsets here are Python character offsets, never compiler UTF-8 byte offsets.
"""

from __future__ import annotations

import difflib
import fnmatch
import re
import subprocess
import sys
import tomllib
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


def line_mapping(head: str, reference: str) -> dict[int, int]:
    """Map real HEAD lines to upstream lines; baseline-only lines disappear."""
    ranges = migration_ranges(head)
    masked = blank_ranges(head, ranges).splitlines(keepends=True)
    lines: list[tuple[int, str]] = []
    offset = 0
    range_index = 0
    for number, text in enumerate(head.splitlines(keepends=True), 1):
        while range_index < len(ranges) and ranges[range_index][1] <= offset:
            range_index += 1
        visible = masked[number - 1]
        overlaps = range_index < len(ranges) and ranges[range_index][0] < offset + len(
            text
        )
        if visible.strip() or not overlaps:
            lines.append((number, "".join(visible.split())))
        offset += len(text)
    matcher = difflib.SequenceMatcher(
        None,
        ["".join(x.split()) for x in reference.splitlines()],
        [value for _, value in lines],
        autojunk=False,
    )
    return {
        lines[j + delta][0]: i + delta + 1
        for tag, i, stop, j, _ in matcher.get_opcodes()
        if tag == "equal"
        for delta in range(stop - i)
    }


def moved_sources(root: Path) -> dict[str, str]:
    path = root / "scripts/lint-ratchet/moves.toml"
    if not path.exists():
        return {}
    return {row["new"]: row["from"] for row in tomllib.loads(path.read_text())["move"]}


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
    upstream = "async fn f() {}\n#[test]\nfn test_f() {}\n"
    head = '#[expect(dead_code, reason = "lint-migration: baseline")]\n' + upstream
    assert line_mapping(head, upstream) == {2: 1, 3: 2, 4: 3}
    assert 2 not in line_mapping(head.replace("f() {}", "f() { work(); }"), upstream)
    assert (
        attribute_calls(
            "#[cfg_attr(test, cfg_attr(unix, allow(x)), allow(y), derive(Debug))]"
        )[0].predicate
        == "all(test, unix)"
    )
    print("common self-test: ok (cfg_attr siblings, lexemes, baseline provenance)")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else 2)
