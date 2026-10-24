#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/fork_lines_gate.py --self-test
"""Differential diagnostics across K1-K7, rustdoc, and the fork-only fuzz crate."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

import common
import fork_reference
import provenance

CONFIGS: Final = (
    ("--all-features",),
    (),
    ("--no-default-features",),
    ("--features", "http"),
    ("--features", "tower"),
    ("--features", "evaluation"),
    ("--no-default-features", "--features", "tokio"),
)
NIGHTLY: Final = "+nightly-2026-10-03"


from diagnostics import Diagnostic, collect, parse_messages, run_cargo


def lint_flags(manifest: dict) -> list[str]:
    entries = [
        (namespace, name, value if isinstance(value, dict) else {"level": value})
        for namespace, table in manifest["lints"].items()
        for name, value in table.items()
    ]
    entries.sort(key=lambda entry: entry[2].get("priority", 0))
    return [
        flag
        for namespace, name, value in entries
        for flag in (
            {"deny": "-D", "forbid": "-F", "warn": "-W", "allow": "-A"}[value["level"]],
            name if namespace == "rust" else namespace + "::" + name,
        )
    ]


def normalize(root: Path, reference: bool) -> None:
    for path in common.iter_rust_files(root):
        source, _ = common.read_source(path)
        ranges = common.migration_ranges(source)
        if not reference:
            ranges = [
                (a + source[a:b].index("///") + 3, b)
                if "///" in source[a:b] and source[a:b].lstrip().startswith("///")
                else (a, b)
                for a, b in ranges
            ]
        if reference:
            ranges = []
            clean = common.strip_comments_and_strings(source)
            for start, end, inner, body in common.iter_attributes(clean):

                def prune(text: str, offset: int) -> bool:
                    match = re.match(r"\s*(\w+)\s*\(", text)
                    if match is None:
                        return False
                    if match[1] == "allow":
                        return True
                    if match[1] != "cfg_attr":
                        return False
                    opening = match.end() - 1
                    closing = common.match_bracket(text, opening)
                    if closing is None:
                        raise RuntimeError("unclosed cfg_attr")
                    args = text[opening + 1 : closing]
                    spans = common.split_top_level(args)
                    removed = []
                    for index, (a, b) in enumerate(spans[1:], 1):
                        if not args[a:b].strip():
                            continue
                        if prune(args[a:b], offset + opening + 1 + a):
                            removed.append(index)
                    live = [
                        i for i, (a, b) in enumerate(spans[1:], 1) if args[a:b].strip()
                    ]
                    if removed == live:
                        return True
                    for index in removed:
                        a, b = spans[index]
                        ranges.append((offset + opening + a, offset + opening + 1 + b))
                    return False

                if prune(body, start + (3 if inner else 2)):
                    ranges.append((start, end))
        path.write_text(common.blank_ranges(source, ranges))


def violations(
    head: list[Diagnostic],
    reference: list[Diagnostic],
    mappings: dict[str, dict[int, int]],
    moves: dict[str, str],
) -> list[Diagnostic]:
    inherited = set(reference)
    return [
        d
        for d in head
        if Diagnostic(
            d.config,
            d.mode,
            moves.get(d.file, d.file),
            d.lint,
            mappings.get(d.file, {}).get(d.line, -1),
        )
        not in inherited
    ]


def compare_trees(root: Path, reference: Path, head: Path) -> list[Diagnostic]:
    moves = common.moved_sources(root)
    shutil.copy2(root / "rustfmt.toml", reference / "rustfmt.toml")
    shutil.copy2(root / "clippy.toml", reference / "clippy.toml")
    # Equality gate owns validation; copy the actual HEAD tables, including order.
    cargo = (root / "Cargo.toml").read_text()
    fork_reference.align_msrv(reference, cargo)
    tables = re.findall(r"(?ms)^\[lints\.[^\n]+\n.*?(?=^\[|\Z)", cargo)
    if not tables:
        raise RuntimeError("HEAD has no lint profile; finish todo 14 first")
    with (reference / "Cargo.toml").open("a") as manifest_file:
        manifest_file.write("\n" + "\n".join(tables))
    fork_reference.compensate_reference(reference)
    run_cargo(reference, [NIGHTLY, "fmt", "--all"])
    normalize(reference, True)
    mappings = {}
    for path in common.iter_rust_files(head):
        rel = path.relative_to(head).as_posix()
        source = moves.get(rel, rel)
        ref_path = reference / source
        ref = ref_path.read_text() if source and ref_path.is_file() else ""
        mappings[rel] = provenance.mapping(root, rel, (path.read_text(), ref))
    normalize(head, False)
    found = violations(collect(head), collect(reference), mappings, moves)
    flags = lint_flags(tomllib.loads(cargo))
    output = run_cargo(
        head,
        [
            NIGHTLY,
            "clippy",
            "--manifest-path",
            "fuzz/Cargo.toml",
            "--all-targets",
            "--message-format=json",
            "--",
            "--cap-lints",
            "warn",
            *flags,
        ],
    )
    found.extend(
        d
        for d in parse_messages(output, head, "FUZZ")
        if d.file.startswith("fuzz/fuzz_targets/")
    )
    return sorted(set(found), key=lambda d: (d.file, d.line, d.lint, d.config, d.mode))


def self_test() -> int:
    fork_reference.self_test()
    with TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "src").mkdir()
        path = root / "src/lib.rs"
        source = "#[cfg_attr(test, allow(dead_code), derive(Debug))]\nstruct A;\n#[cfg_attr(unix, allow(unused))]\nfn f() {}\n"
        path.write_text(source)
        normalize(root, True)
        normalized = path.read_text()
        assert len(normalized) == len(source) and normalized.count(
            "\n"
        ) == source.count("\n")
        assert not common.attribute_calls(normalized) and "derive(Debug)" in normalized
    upstream = "#[allow(clippy::too_many_arguments)]\nfn old() {}\n"
    head = '#[expect(clippy::too_many_arguments, reason = "lint-migration: baseline")]\nfn old() {}\nfn new() { values[index] }\n'
    mapping = common.line_mapping(head, upstream)
    original = Diagnostic(
        "K1", "not(test)", "src/lib.rs", "clippy::too_many_arguments", 2
    )
    masking = Diagnostic("K1", "not(test)", "src/lib.rs", "clippy::indexing_slicing", 3)
    assert violations([original, masking], [original], {"src/lib.rs": mapping}, {}) == [
        masking
    ]
    k7 = Diagnostic("K7", "not(test)", "src/lib.rs", "clippy::unwrap_used", 2)
    assert violations([k7], [], {"src/lib.rs": mapping}, {}) == [k7]
    moved = Diagnostic("K1", "test", "tests/support/a.rs", "dead_code", 1)
    old = Diagnostic("K1", "test", "tests/common/mod.rs", "dead_code", 2)
    assert not violations([moved], [old], {moved.file: {1: 2}}, {moved.file: old.file})
    assert violations([moved], [old], {moved.file: {}}, {moved.file: old.file})
    assert len(CONFIGS) == 7 and CONFIGS[-1] == (
        "--no-default-features",
        "--features",
        "tokio",
    )
    flags = lint_flags(
        {
            "lints": {
                "clippy": {
                    "unwrap_used": "deny",
                    "all": {"level": "deny", "priority": -1},
                }
            }
        }
    )
    assert flags == ["-D", "clippy::all", "-D", "clippy::unwrap_used"]
    print(
        "fork_lines_gate self-test: ok (reference dev-dependency, masking, K7, removed allow, moved helper, fuzz flags)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=common.ROOT)
    parser.add_argument("--paths", nargs="+")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        with TemporaryDirectory(prefix="rskrb5-fork-gate-") as directory:
            ref, head = Path(directory) / "reference", Path(directory) / "head"
            common.git(args.root, "worktree", "add", "--detach", str(ref), "6f4abc9")
            try:
                shutil.copytree(
                    args.root,
                    head,
                    ignore=shutil.ignore_patterns(".git", "target", "__pycache__"),
                )
                found = compare_trees(args.root, ref, head)
            finally:
                common.git(args.root, "worktree", "remove", "--force", str(ref))
        hits = [d for d in found if common.selected(d.file, args.paths)]
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"fork_lines_gate: {error}", file=sys.stderr)
        return 1
    for diagnostic in hits:
        print(
            f"{diagnostic.file}:{diagnostic.line} {diagnostic.lint} [{diagnostic.config} {diagnostic.mode}]"
        )
    print(f"fork_lines_gate: {len(hits)} violations")
    return int(args.enforce and bool(hits))


if __name__ == "__main__":
    sys.exit(main())
