#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/facade_gate.py --self-test
"""Close the crate-root public-facade expectation's descendant coverage."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import common
import provenance
from diagnostics import Diagnostic


def scan(source: str, file: str, mapping: dict[int, int]) -> list[Diagnostic]:
    """Reject fork re-exports except at the library root's own scope."""
    clean = common.strip_comments_and_strings(source)
    hits = []
    for match in re.finditer(r"\bpub\s*(?:\([^)]*\)\s*)?use\b[^;]*;", clean):
        prefix = clean[: match.start()]
        if file == "src/lib.rs" and prefix.count("{") == prefix.count("}"):
            continue
        first = common.line_of(source, match.start())
        last = common.line_of(source, match.end() - 1)
        if any(
            line not in mapping and text.strip()
            for line, text in enumerate(clean.splitlines(), 1)
            if first <= line <= last
        ):
            hits.append(Diagnostic("SOURCE", "all", file, "clippy::pub_use", first))
    return hits


def report(root: Path, paths: list[str] | None) -> list[Diagnostic]:
    """Check source before any Cargo build, including cfg-disabled imports."""
    hits = []
    for path in common.iter_rust_files(root):
        file = path.relative_to(root).as_posix()
        if not common.selected(file, paths):
            continue
        source = path.read_text()
        if not re.search(r"\bpub\s*(?:\([^)]*\)\s*)?use\b", source):
            continue
        origin = common.moved_sources(root).get(file, file)
        exists = origin and common.git(root, "ls-tree", "6f4abc9", "--", origin).strip()
        upstream = common.git(root, "show", f"6f4abc9:{origin}") if exists else ""
        if upstream:
            upstream = subprocess.run(
                [
                    "rustfmt",
                    "+nightly-2026-10-03",
                    "--emit",
                    "stdout",
                    "--edition",
                    "2024",
                    "--config-path",
                    str(root / "rustfmt.toml"),
                    "--config",
                    "skip_children=true",
                ],
                input=upstream,
                text=True,
                capture_output=True,
                check=True,
            ).stdout
        hits.extend(
            scan(source, file, provenance.mapping(root, file, (source, upstream)))
        )
    return hits


def self_test() -> None:
    # Given a root re-export, when scanned at crate scope, it is permitted.
    assert not scan("pub use crate::Thing;\n", "src/lib.rs", {})
    # Given inherited re-exports, when unchanged, their root-facade coverage stays.
    inherited = "pub use crate::Thing;\n"
    assert not scan(inherited, "src/client.rs", {1: 1})
    # Given fork visibility variants, when outside the root facade, each fails.
    for visibility in ("pub", "pub(crate)", "pub(super)", "pub(in crate::client)"):
        source = f"{visibility}\nuse crate::{{Thing, Other}};\n"
        assert len(scan(source, "src/client.rs", {})) == 1
        assert len(scan("mod nested {\n" + source + "}\n", "src/lib.rs", {})) == 1
    # Given a changed continuation, when the pub-use header is inherited, it fails.
    assert scan("pub use crate::{\n Thing, Fork,\n};\n", "src/client.rs", {1: 1, 3: 3})
    # Given comments and literals, when scanned, they are not Rust re-exports.
    assert not scan(
        '// pub use fake;\nconst S: &str = "pub use fake;";\n', "src/client.rs", {}
    )
    print(
        "facade_gate self-test: ok (root scope, inherited, restricted visibility, continuation, lexemes)"
    )


if __name__ == "__main__":
    self_test()
