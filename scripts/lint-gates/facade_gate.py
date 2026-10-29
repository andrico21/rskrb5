#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/facade_gate.py --enforce
"""Restrict public re-exports to the crate-root facade."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import redirect_stdout
from io import StringIO

import common
import path_scope


@dataclass(frozen=True, slots=True)
class Violation:
    file: str
    line: int
    statement: str


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


def report(root: Path, paths: list[str] | None = None) -> list[Violation]:
    """Violations in the whole tree, or only in `paths` (an empty list selects nothing)."""
    return [
        Violation(file, line, statement)
        for path in common.iter_rust_files(root)
        if path_scope.selected(file := path.relative_to(root).as_posix(), paths)
        for statement, line in statements(path.read_text(), file)
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
    with TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "src").mkdir()
        (root / "src/lib.rs").write_text("pub use crate::client::Thing;\n")
        module = root / "src/client.rs"
        module.write_text("pub struct Thing;\n")
        assert not report(root)
        module.write_text("pub use crate::Thing;\n")
        assert [hit.statement for hit in report(root)] == [
            "crate::client\tpubusecrate::Thing;"
        ]
        assert report(root, []) == []
        assert len(report(root, ["src/client.rs"])) == 1
        with redirect_stdout(StringIO()):
            assert main(["--root", str(root)]) == 0
            assert main(["--enforce", "--root", str(root)]) == 1
    print("facade_gate self-test: ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=common.ROOT)
    parser.add_argument("--paths", nargs="+")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        hits = report(args.root, args.paths)
    except common.source_set.SourceSetError as error:
        print(f"facade_gate: {error}")
        return 1
    for hit in hits:
        owner, statement = hit.statement.split("\t", 1)
        print(
            f"{hit.file}:{hit.line}: clippy::pub_use outside the crate-root facade "
            f"(in {owner}: {statement})"
        )
    print(f"facade_gate: {len(hits)} violations")
    return int(args.enforce and bool(hits))


if __name__ == "__main__":
    sys.exit(main())
