#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/prose_gate.py --self-test
"""Whole-tree prose rules, ported from rmcp-server-kit (MIT/Apache-2.0)."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

import common
import path_scope
from prose_infallible import infallible_test

CHECKS: Final = (
    "cancel-safety",
    "test-docs",
    "test-result",
    "drop-audit",
    "emptiness-message",
    "credential-mutating",
)


def scan(source: str, production: bool) -> list[tuple[str, int, str]]:
    stripped = common.strip_comments_and_strings(source)
    literals = common.strip_comments_and_strings(source, keep_literals=True)
    items = common.scan_items(source)
    test_ranges = common.cfg_test_line_ranges(stripped)
    lines = source.splitlines()
    hits = []
    touched = set(items)
    proptest_ranges = []
    for match in re.finditer(r"\bproptest!\s*\{", stripped):
        close = common.match_bracket(stripped, match.end() - 1)
        if close is not None:
            proptest_ranges.append((match.start(), close))
    for item in items:
        if item not in touched:
            continue
        line = common.line_of(source, item.keyword)
        prefix = source[item.start : item.keyword]
        attrs = [
            body.strip()
            for _, _, _, body in common.iter_attributes(
                stripped[item.start : item.keyword]
            )
        ]
        signature = stripped[item.keyword : item.end].split("{", 1)[0]
        if item.kind == "fn":
            is_async = bool(
                re.search(
                    r"\basync\s+(?:unsafe\s+)?$", stripped[item.start : item.keyword]
                )
            )
            is_test = any(
                re.match(r"(?:test$|tokio::test\b|should_panic\b)", attr)
                for attr in attrs
            )
            if production and is_async and not common.in_ranges(line, test_ranges):
                lookback = lines[max(0, line - 7) : line - 1]
                if "Cancel safety" not in prefix and not any(
                    "cancel-safe:" in value for value in lookback
                ):
                    hits.append(("cancel-safety", line, f"async fn {item.name}"))
            if is_async and re.match(
                r"(?:change_password|set_password|exchange_kpasswd)", item.name
            ):
                section = re.search(
                    r"(?s)# Cancel safety\s*\n(.*?)(?:\n\s*///\s*# |\Z)", prefix
                )
                if section is None or "NOT cancel-safe" not in section[1]:
                    hits.append(("credential-mutating", line, f"async fn {item.name}"))
            if is_test and not any(a <= item.keyword <= b for a, b in proptest_ranges):
                if not re.search(r"(?m)^\s*///", prefix):
                    hits.append(("test-docs", line, f"fn {item.name}"))
                if (
                    not any(attr.startswith("should_panic") for attr in attrs)
                    and not re.search(r"->\s*(?:[\w]+::)*Result\s*<", signature)
                    and not infallible_test(
                        stripped[item.keyword : item.end].partition("{")[2],
                    )
                ):
                    hits.append(("test-result", line, f"fn {item.name}"))
        if (
            production
            and item.kind == "impl"
            and re.search(r"\bDrop\s+for\b", signature)
        ):
            if not any(
                "Drop audit" in value for value in lines[max(0, line - 4) : line - 1]
            ):
                hits.append(("drop-audit", line, item.identity))
    for match in re.finditer(r"(?<!\w)(?:debug_)?assert!\s*\(", stripped):
        item = common.owner(items, match.start())
        if item not in touched:
            continue
        opening = match.end() - 1
        close = common.match_bracket(stripped, opening)
        if close is None:
            continue
        args = stripped[opening + 1 : close]
        spans = common.split_top_level(args)
        a, b = spans[0]
        condition = "".join(args[a:b].split())
        depth = 0
        compound = False
        for index, char in enumerate(condition):
            depth += (char in "([{") - (char in ")]}")
            compound |= depth == 0 and condition.startswith(("&&", "||"), index)
        if condition.endswith(".is_empty()") and not compound:
            if not any(
                literals[opening + 1 + a : opening + 1 + b].strip()
                for a, b in spans[1:]
            ):
                hits.append(
                    (
                        "emptiness-message",
                        common.line_of(source, match.start()),
                        "assert!(... .is_empty()) without message",
                    )
                )
    return hits


def report(root: Path, paths: list[str] | None) -> list[tuple[str, str, int, str]]:
    hits = []
    for path in common.iter_rust_files(root):
        relative = path.relative_to(root).as_posix()
        if not path_scope.selected(relative, paths):
            continue
        source = path.read_text()
        hits.extend(
            (gate, relative, line, detail)
            for gate, line, detail in scan(source, relative.startswith("src/"))
        )
    return hits


def self_test() -> int:
    upstream = "async fn old() {}\n#[test]\nfn old_test() {}\n"
    baseline = '#[expect(dead_code, reason = "lint-migration: baseline")]\n' + upstream
    assert scan(baseline, True)
    edited = baseline.replace("old() {}", "old() { work(); }")
    assert any(gate == "cancel-safety" for gate, _, _ in scan(edited, True))
    source = (
        "pub(crate) async fn prose_probe() {}\n"
        "/// # Cancel safety\n/// NOT cancel-safe: mutates credentials.\nasync fn change_password_ok() {}\n"
        "\n\n\n\n\n\n\nasync fn set_password_bad() {}\n#[test]\nfn test_bad() { work(); }\n"
        "/// proves something\n#[test]\nfn test_good() -> Result<(), Error> { Ok(()) }\n"
        "/// deliberately panics\n#[test]\n#[should_panic]\nfn panics() {}\n"
        "impl Drop for Guard { fn drop(&mut self) {} }\n"
        'fn empty() { assert!(v.is_empty(),); assert!(v.is_empty(), "empty"); assert!(a.is_empty() && b.is_empty()); }\n'
    )
    hits = scan(source, True)
    assert sum(g == "cancel-safety" for g, _, _ in hits) == 2
    assert sum(g == "credential-mutating" for g, _, _ in hits) == 1
    assert sum(g == "test-docs" for g, _, _ in hits) == 1
    assert sum(g == "test-result" for g, _, _ in hits) == 1
    assert sum(g == "drop-audit" for g, _, _ in hits) == 1
    assert sum(g == "emptiness-message" for g, _, _ in hits) == 1
    # Given a touched upstream test with only construction and assertions,
    # when scanned, Result is optional for inherited and fork-authored tests.
    upstream_test = "/// checks status\n#[test]\nfn status() {\n let result = Status { code: 1 };\n assert!(matches!(result.ensure_success(), Err(_)));\n}\n"
    touched_test = upstream_test.replace("code: 1", "code: 1, text_raw: &[]")
    assert not scan(touched_test, False)
    # Given literal/field ownership conversions, only nested fallible calls
    # should introduce a propagation site when the inherited test is scanned.
    for conversion in (
        '"failure".to_owned()',
        'b"failure".to_vec()',
        '"failure".to_string()',
        '"failure".into()',
        'String::from("failure")',
        'Vec::from(b"failure")',
    ):
        converted = touched_test.replace("text_raw: &[]", "text_raw: " + conversion)
        assert not scan(converted, False)
    for call in ("String::from(read_file())", "read_file().to_owned()", "read_file()"):
        converted = touched_test.replace("text_raw: &[]", "text_raw: " + call)
        assert any(g == "test-result" for g, _, _ in scan(converted, False))
    assert not scan(touched_test, False)
    fallible = touched_test.replace(
        " let result", ' read_file().expect("fixture");\n let result'
    )
    assert any(g == "test-result" for g, _, _ in scan(fallible, False))
    with TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "tests/support").mkdir(parents=True)
        moved = "fn helper() { assert!(v.is_empty()); }\n"
        (root / "tests/support/topic.rs").write_text(moved)
        assert report(root, None)
        assert report(root, []) == []
        (root / "tests/support/topic.rs").write_text(
            moved.replace("v.is_empty()", "w.is_empty()")
        )
        assert report(root, ["tests/support/*.rs"])
    print("prose_gate self-test: ok (all six checks, whole-tree and explicit scopes)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=common.ROOT)
    parser.add_argument("--paths-file", type=Path)
    parser.add_argument("--paths", nargs="+")
    parser.add_argument("--only", action="append", choices=CHECKS)
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        hits = report(args.root, path_scope.patterns(args.paths, args.paths_file))
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"prose_gate: {error}", file=sys.stderr)
        return 1
    hits = [hit for hit in hits if not args.only or hit[0] in args.only]
    for gate, path, line, detail in hits:
        print(f"{path}:{line}: {gate}: {detail}")
    print(f"prose_gate: {len(hits)} violations")
    return int(args.enforce and bool(hits))


if __name__ == "__main__":
    sys.exit(main())
