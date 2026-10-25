#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/provenance_fixtures.py --self-test
"""Behavior fixtures for reviewed rewrite credit and diagnostic isolation."""

from provenance import Revision, chain, rewrite_mapping


def check_rewrites() -> None:
    # Given the eight original rewrite classes, when replaced, identifiers map.
    for before, after in (
        ("use std::time::Duration;", "use core::time::Duration;"),
        (
            "pub struct Reader<'a> { bytes: &'a [u8] }",
            "pub struct Reader<'buffer> { bytes: &'buffer [u8] }",
        ),
        (
            "pub type Result<T> = std::result::Result<T, Error>;",
            "pub type Result<T> = core::result::Result<T, Error>;",
        ),
        ("use std::fmt;", "use alloc::fmt;"),
        ("Io(#[from] std::io::Error),", "Io(#[from] io::Error),"),
        (
            "type Future = Pin<Box<dyn Future<Output = std::result::Result<Response, Error>>>>;",
            "type Future = Pin<Box<dyn Future<Output = core::result::Result<Response, Error>>>>;",
        ),
        (
            "impl std::fmt::Display for ProbeOutcome {",
            "impl core::fmt::Display for ProbeOutcome {",
        ),
        (
            "type MutualSendResult = std::result::Result<Response, Error>;",
            "type MutualSendResult = core::result::Result<Response, Error>;",
        ),
    ):
        assert rewrite_mapping(Revision(before, after)) == {1: 1}
    # Given unrelated replacements sharing only keywords/short names/literals,
    # when rewritten, none gains inherited credit.
    for before, after in (
        ("let old = source();", "let new = values[index];"),
        ("pub fn x() {}", "pub fn y() { values[index]; }"),
        ("let ab = old();", "let ab = new();"),
        ('old("shared_name");', 'new("shared_name");'),
    ):
        assert not rewrite_mapping(Revision(before, after))
    # Given a genuinely credited line, when a new lint appears, it stays visible.
    from fork_lines_gate import violations
    from diagnostics import Diagnostic

    before = "use std::time::Duration;"
    after = "use core::time::Duration;"
    inherited = Diagnostic("K1", "test", "src/probe.rs", "clippy::absolute_paths", 1)
    introduced = Diagnostic("K1", "test", "src/probe.rs", "clippy::unused_imports", 1)
    mapped = chain(after, before, [Revision(before, after)])
    assert violations(
        [inherited, introduced], [inherited], {"src/probe.rs": mapped}, {}
    ) == [introduced]
    # Given a post-review edit, when it adds a diagnostic, it loses line credit.
    edited = chain(after + " values[index];", before, [Revision(before, after)])
    assert violations([inherited], [inherited], {"src/probe.rs": edited}, {}) == [
        inherited
    ]
    print(
        "provenance fixtures: ok (eight rewrites, keyword/short/literal abuse, new diagnostics)"
    )


if __name__ == "__main__":
    check_rewrites()
