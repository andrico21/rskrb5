#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/facade_gate.py --enforce
"""Restrict public re-exports to the root facade and shrinking statement keys."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import common
from diagnostics import Diagnostic

EXCEPTIONS = "scripts/lint-ratchet/facade-exceptions.txt"


def statements(source: str, file: str) -> list[tuple[str, int]]:
    clean = common.strip_comments_and_strings(source)
    items = common.scan_items(source)
    module = (
        "crate"
        if file == "src/lib.rs"
        else "crate::"
        + file.removeprefix("src/")
        .removesuffix(".rs")
        .removesuffix("/mod")
        .replace("/", "::")
    )
    result = []
    for match in re.finditer(r"\bpub\s*(?:\([^)]*\)\s*)?use\b[^;]*;", clean):
        nested = [
            item
            for item in items
            if item.kind == "mod" and item.start <= match.start() < item.end
        ]
        nested.sort(key=lambda item: item.start)
        owner = module + "".join(
            "::" + item.identity.rsplit("mod ", 1)[-1] for item in nested
        )
        if file == "src/lib.rs" and not nested:
            continue
        statement = re.sub(r"\s+", "", match[0])
        result.append((owner + "\t" + statement, common.line_of(source, match.start())))
    return result


def report(root: Path, paths: list[str] | None = None) -> list[Diagnostic]:
    allowed = set((root / EXCEPTIONS).read_text().splitlines())
    return [
        Diagnostic("SOURCE", "all", file, "clippy::pub_use", line)
        for path in common.iter_rust_files(root)
        if common.selected(file := path.relative_to(root).as_posix(), paths)
        for key, line in statements(path.read_text(), file)
        if key not in allowed
    ]


def self_test() -> int:
    assert not statements("pub use crate::Thing;", "src/lib.rs")
    for visibility in ("pub", "pub(crate)", "pub(super)", "pub(in crate::client)"):
        assert statements(f"{visibility} use crate::Thing;", "src/client.rs")
        assert statements(
            f"mod nested {{ {visibility} use crate::Thing; }}", "src/lib.rs"
        )
    assert statements("pub use crate::{Thing, Other};", "src/client.rs") == statements(
        "pub use crate::{\n Thing, Other\n};", "src/client.rs"
    )
    assert not statements(
        '// pub use fake;\nconst S: &str = "pub use fake;";', "src/client.rs"
    )
    print("facade_gate self-test: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=common.ROOT)
    parser.add_argument("--paths", nargs="+")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    hits = report(args.root, args.paths)
    for hit in hits:
        print(f"{hit.file}:{hit.line}: {hit.lint}")
    print(f"facade_gate: {len(hits)} violations")
    return int(args.enforce and bool(hits))


if __name__ == "__main__":
    sys.exit(main())
