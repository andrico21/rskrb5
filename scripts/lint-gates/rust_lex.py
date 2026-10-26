#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/rust_lex.py --self-test
"""Rust suppression lexer; character offsets preserve line structure."""

from __future__ import annotations

import re
import sys
import tomllib
from dataclasses import dataclass
from typing import Final, Iterator


def strip_comments_and_strings(src: str, *, keep_literals: bool = False) -> str:
    """Blank Rust comments/literals without changing character offsets or lines."""
    out = list(src)
    token = re.compile(
        r'//[^\n\r]*|/\*|(?:br|cr|r)(#*)"|(?:b|c)?"|(?:b)?\'(?:\\(?:u\{[^}]*\}|x..|.)|[^\'\\\n])\''
    )
    pos = 0
    while match := token.search(src, pos):
        start, end = match.span()
        text = match.group()
        comment = text.startswith(("//", "/*"))
        if text == "/*":
            depth = 1
            while depth and end < len(src):
                nested = re.search(r"/\*|\*/", src[end:])
                if nested is None:
                    end = len(src)
                    break
                depth += 1 if nested.group() == "/*" else -1
                end += nested.end()
        elif text.endswith('"'):
            hashes = match.group(1)
            if hashes is not None:
                close = src.find('"' + hashes, end)
                end = len(src) if close < 0 else close + 1 + len(hashes)
            else:
                close = re.search(r'\\.|"', src[end:])
                while close is not None:
                    end += close.end()
                    if close.group() == '"':
                        break
                    close = re.search(r'\\.|"', src[end:])
                if close is None:
                    end = len(src)
        if comment or not keep_literals:
            out[start:end] = [c if c in "\r\n" else " " for c in src[start:end]]
        pos = end
    return "".join(out)


def line_of(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


def match_bracket(src: str, open_idx: int) -> int | None:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    for i in range(open_idx, len(src)):
        if src[i] in pairs:
            stack.append(pairs[src[i]])
        elif stack and src[i] == stack[-1]:
            stack.pop()
            if not stack:
                return i
    return None


def split_top_level(text: str) -> list[tuple[int, int]]:
    spans = []
    depth = start = 0
    for i, char in enumerate(text):
        depth += (char in "([{") - (char in ")]}")
        if char == "," and depth == 0:
            spans.append((start, i))
            start = i + 1
    return spans + [(start, len(text))]


# `#`, `!` and `[` are separate tokens: whitespace (and so a blanked comment)
# may sit between them, as in `# ! [allow(x)]` under `rustfmt::skip`.
ATTRIBUTE_START: Final = re.compile(r"#\s*(!)?\s*\[")
# An attribute path, optionally raw (`r#allow`) or `::`-qualified.
META_PATH: Final = r"(?:::\s*)?(?:r#)?[A-Za-z_]\w*(?:\s*::\s*(?:r#)?\w+)*"


def iter_attributes(src: str) -> Iterator[tuple[int, int, bool, str]]:
    pos = 0
    while match := ATTRIBUTE_START.search(src, pos):
        start = match.start()
        bracket = match.end() - 1
        close = match_bracket(src, bracket)
        if close is None:
            return
        yield start, close + 1, match[1] is not None, src[bracket + 1 : close]
        pos = close + 1


def opaque_constructs(stripped: str) -> list[tuple[int, str]]:
    """Report spellings whose expansion the lexer cannot read, so gates fail closed.

    A suppression can hide behind a macro: `#[$m]` with `$m:meta`, `#$t` with a
    bracketed `$t:tt`, `cfg_attr(p, $($t)*)`, or an `allow(..)`/`expect(..)`
    token tree handed to any macro (local or foreign) that emits `#[..]` from it.
    Every attribute must also start with a plain path, as all lint and
    `cfg_attr` attributes do; anything else is reported, never guessed.
    """
    found: list[tuple[int, str]] = []
    spans = []
    for match in re.finditer(r"#\s*!?\s*\$", stripped):
        found.append((match.start(), "attribute spliced from a macro metavariable"))
    for start, end, inner, body in iter_attributes(stripped):
        spans.append((start, end))
        if "$" in body:
            found.append((start, "attribute body uses a macro metavariable"))
            continue

        def visit(part: str) -> None:
            head = re.match(r"\s*(" + META_PATH + r")\s*(?:([(\[{])|=|$)", part, re.S)
            if head is None:
                found.append((start, "attribute is not a plain path"))
                return
            if re.sub(r"\s+|r#", "", head[1]).lstrip(":") == "cfg_attr" and head[2]:
                opening = head.end() - 1
                closing = match_bracket(part, opening)
                if closing is None:
                    found.append((start, "cfg_attr without a closing bracket"))
                    return
                args = part[opening + 1 : closing]
                for a, b in split_top_level(args)[1:]:
                    if args[a:b].strip():
                        visit(args[a:b])

        visit(body)
    for match in re.finditer(
        r"(?<![\w.:#$])(?:r#)?(allow|expect)\s*[(\[{]", stripped
    ):
        if any(a <= match.start() < b for a, b in spans):
            continue
        before = stripped[: match.start()].rstrip()
        if before.endswith((".", "::")) or re.search(r"\bfn\Z", before[-3:]):
            continue
        found.append(
            (
                match.start(),
                f"`{match[1]}(..)` token tree outside an attribute "
                "(a macro argument can expand to a lint attribute)",
            )
        )
    return sorted(found)


@dataclass(frozen=True, slots=True)
class AttributeCall:
    form: str
    lints: tuple[str, ...]
    reason: str
    predicate: str
    start: int
    end: int
    kw_start: int
    kw_end: int
    inner: bool


def attribute_calls(original: str, stripped: str | None = None) -> list[AttributeCall]:
    """Read every suppression, including all siblings in nested cfg_attr lists."""
    clean = strip_comments_and_strings(original) if stripped is None else stripped
    calls: list[AttributeCall] = []
    for start, end, inner, body in iter_attributes(clean):

        def visit(part: str, offset: int, predicates: tuple[str, ...]) -> None:
            match = re.match(r"\s*(?:r#)?(\w+)\s*[(\[{]", part)
            if match is None:
                return
            opening = match.end() - 1
            closing = match_bracket(part, opening)
            if closing is None:
                return
            args = part[opening + 1 : closing]
            spans = split_top_level(args)
            name = match[1]
            if name == "cfg_attr":
                a, b = spans[0]
                predicate = original[
                    offset + opening + 1 + a : offset + opening + 1 + b
                ].strip()
                for a, b in spans[1:]:
                    visit(
                        args[a:b], offset + opening + 1 + a, predicates + (predicate,)
                    )
            elif name in ("allow", "expect"):
                reason = ""
                lints = []
                for a, b in spans:
                    value = args[a:b].strip()
                    if value.startswith("reason") and "=" in value:
                        raw = original[
                            offset + opening + 1 + a : offset + opening + 1 + b
                        ]
                        literal = raw.split("=", 1)[1].strip()
                        # Rust ordinary strings use the same escapes as TOML here.
                        if literal.startswith('"'):
                            reason = tomllib.loads("reason = " + literal)["reason"]
                        elif raw_match := re.fullmatch(r'r(#*)"(.*)"\1', literal, re.S):
                            reason = raw_match[2]
                    elif re.fullmatch(r"\w+(?:::\w+)*", value):
                        lints.append(value)
                predicate = (
                    predicates[0]
                    if len(predicates) == 1
                    else "all(" + ", ".join(predicates) + ")"
                )
                calls.append(
                    AttributeCall(
                        name,
                        tuple(lints),
                        reason,
                        predicate if predicates else "always",
                        start,
                        end,
                        offset + match.start(1),
                        offset + match.end(1),
                        inner,
                    )
                )

        # The body ends just before the closing `]`, whatever the spacing after `#`.
        visit(body, end - 1 - len(body), ())
    return calls


if __name__ == "__main__":
    import common

    sys.exit(common.self_test() if "--self-test" in sys.argv else 2)
