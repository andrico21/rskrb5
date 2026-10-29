#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/prose_scope.py --self-test
"""Where the prose rules apply: test context, macro-generated items, attached contracts.

* A file is production unless it is an integration test or a benchmark
  (`tests/`, `benches/`); `cfg(test)` code inside a production file is test
  context too. Examples, fuzz targets and build scripts are production.
* A macro token tree (a `macro_rules!` definition or any invocation) that can
  generate an `async fn`, a test or a `Drop` impl is scanned like source, with
  its metavariables read as plain identifiers, so generated items get the same
  checks as written ones. `proptest!` bodies are tests without the test-doc and
  `Result` rules (their cases are generated).
* A cancellation contract must be attached to its function (the contiguous
  comment, doc and attribute lines directly above it) and must say something.
"""

from __future__ import annotations

import re
import sys
from typing import Final

from rust_lex import match_bracket, strip_comments_and_strings

TEST_DIRS: Final = ("tests", "benches")
ITEM_MARKERS: Final = re.compile(
    r"\basync\s+(?:unsafe\s+)?fn\b|#\s*\[\s*(?:tokio\s*::\s*)?test\b|\bDrop\s+for\b"
)
MACRO_TREE: Final = re.compile(
    r"(?<![\w$])(?:r#)?(\w+)\s*!\s*(?:(?:r#)?\w+\s*)?([({\[])"
)
CANCEL_HEADING: Final = re.compile(r"///\s*#+\s*Cancel safety\s*$")
CANCEL_NOTE: Final = re.compile(r"//(?!/).*?cancel-safe:(.*)$")


def is_test_path(relative: str) -> bool:
    return any(part in TEST_DIRS for part in relative.split("/")[:-1])


def macro_bodies(source: str) -> list[tuple[str, str]]:
    """(macro name, body as same-offset source) of each item-generating token tree."""
    stripped = strip_comments_and_strings(source)
    found = []
    for match in MACRO_TREE.finditer(stripped):
        close = match_bracket(stripped, match.end() - 1)
        if close is None or not ITEM_MARKERS.search(stripped, match.end(), close):
            continue
        body = source[match.end() : close].replace("$", "_")
        before = "".join(c if c in "\r\n" else " " for c in source[: match.end()])
        found.append((match[1], before + body))
    return found


def attached_lines(lines: list[str], start_line: int, keyword_line: int) -> list[str]:
    """The item's own doc/attribute lines plus the comment lines directly above them."""
    above = start_line - 2
    while above >= 0 and lines[above].lstrip().startswith("//"):
        above -= 1
    return [line.strip() for line in lines[above + 1 : keyword_line - 1]]


def has_cancel_contract(block: list[str]) -> bool:
    """A non-empty `# Cancel safety` doc section or `cancel-safe:` note."""
    for index, line in enumerate(block):
        if CANCEL_HEADING.match(line):
            for following in block[index + 1 :]:
                content = following.removeprefix("///").strip()
                if not following.startswith("///"):
                    continue
                if content.startswith("#"):
                    break
                if content:
                    return True
        note = CANCEL_NOTE.match(line)
        if note:
            continuation = block[index + 1] if index + 1 < len(block) else ""
            wrapped = re.match(r"//(?!/)\s*(\S.*)$", continuation)
            if note[1].strip() or wrapped is not None:
                return True
    return False


def self_test() -> int:
    assert is_test_path("tests/flow.rs") and is_test_path("fuzz/benches/b.rs")
    assert not is_test_path("examples/tests.rs") and not is_test_path("src/lib.rs")
    bodies = macro_bodies("fn f() { assert!(x); }\nm! {\n async fn $name() {} }\n")
    assert [name for name, _ in bodies] == ["m"]
    assert bodies[0][1].splitlines()[2] == " async fn _name() {} ", bodies
    lines = [
        "// cancel-safe: earlier",
        "fn a() {}",
        "// cancel-safe: yes",
        "/// Doc.",
        "#[inline]",
        "async fn b() {}",
    ]
    assert attached_lines(lines, 4, 6) == [
        "// cancel-safe: yes",
        "/// Doc.",
        "#[inline]",
    ]
    assert has_cancel_contract(["// NOT cancel-safe: mutates credentials."])
    assert not has_cancel_contract(
        ["/// # Cancel safety", "///", "/// # Errors", "/// Fails."]
    )
    print(
        "prose_scope self-test: ok (test paths, macro bodies, attached lines, contract text)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else 2)
