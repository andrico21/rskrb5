#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/path_scope.py --self-test
"""Explicit whole-tree, selected-path and empty-path lint scopes."""

from __future__ import annotations

import fnmatch
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


def patterns(paths: list[str] | None, paths_file: Path | None) -> list[str] | None:
    if paths_file is None:
        return paths
    return [
        *(paths or []),
        *[
            line.strip()
            for line in paths_file.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ],
    ]


def selected(path: str, scope: list[str] | None) -> bool:
    return scope is None or any(fnmatch.fnmatchcase(path, pattern) for pattern in scope)


def self_test() -> int:
    with TemporaryDirectory() as directory:
        path = Path(directory) / "paths"
        path.write_text("")
        assert selected("src/der.rs", patterns(None, None))
        assert not selected("src/der.rs", patterns(None, path))
        path.write_text("# comment\nsrc/*.rs\n")
        assert selected("src/der.rs", patterns(None, path))
        assert not selected("tests/der.rs", patterns(None, path))
    print("path_scope self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else 2)
