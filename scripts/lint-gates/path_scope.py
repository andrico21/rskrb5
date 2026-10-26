#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/path_scope.py --self-test
"""Whole-tree (no patterns), selected-path and empty-path lint scopes."""

from __future__ import annotations

import fnmatch
import sys


def selected(path: str, scope: list[str] | None) -> bool:
    return scope is None or any(fnmatch.fnmatchcase(path, pattern) for pattern in scope)


def self_test() -> int:
    assert selected("src/der.rs", None)
    assert not selected("src/der.rs", [])
    assert selected("src/der.rs", ["src/*.rs"])
    assert not selected("tests/der.rs", ["src/*.rs"])
    print("path_scope self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else 2)
