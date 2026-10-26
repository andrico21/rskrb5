#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/prose_infallible.py --self-test
"""Require test Results only when a propagation site is present.

Assertions (including expect_err/unwrap_err) consume their fallible receivers.
Known infallible constructors, conversions and child-test harness calls cannot
propagate. Unknown calls remain conservative; this applies to every test origin.
"""

from __future__ import annotations

import re

import common


def infallible_test(body: str) -> bool:
    """Inspect stripped Rust; never hide fallibility in conversion arguments."""
    ranges = []
    for match in re.finditer(
        r"\b(?:assert|assert_eq|assert_ne|debug_assert|debug_assert_eq|debug_assert_ne)!\s*\(",
        body,
    ):
        closing = common.match_bracket(body, match.end() - 1)
        if closing is not None:
            ranges.append((match.start(), closing + 1))
    remaining = common.blank_ranges(body, ranges)
    if re.search(r"\?|\.\s*(?:unwrap|expect)\s*\(|\bpanic!", remaining):
        return False
    ranges = []
    for match in re.finditer(r"\.\s*(?:expect_err|unwrap_err)\s*\(", remaining):
        closing = common.match_bracket(remaining, match.end() - 1)
        if closing is None:
            continue
        start = match.start()
        depth = 0
        while start:
            char = remaining[start - 1]
            if depth == 0 and char in ";{}=":
                break
            depth += (char in ")]}") - (char in "([{")
            start -= 1
        ranges.append((start, closing + 1))
    remaining = common.blank_ranges(remaining, ranges)
    remaining = re.sub(
        r"\.\s*(?:to_owned|to_vec|to_string|into)\s*\("
        r"|\b(?:String|Vec)\s*::\s*from\s*\("
        r"|\b(?:AsReqOptions::from_libdefaults|Default::default|Config::new"
        r"|TokioClient::from_tgt_session|timestamp|sample_tgt_session"
        r"|env::in_child|env::run_in_child)\s*\("
        r"|\bvec!\s*\[",
        "(",
        remaining,
    )
    remaining = re.sub(r"\b(?:if|while|match)\s*(?=[!(])", "", remaining)
    return not re.search(r"\?|\b\w+\s*(?:!\s*)?\(|\.\s*\w+\s*::\s*<", remaining)


def self_test() -> None:
    from prose_gate import scan

    for body in (
        "assert_eq!(PA_FX_COOKIE, 133_i32);",
        "let defaults = LibDefaults { default_tkt_enctype_ids: vec![19_i32], ..Default::default() };\n"
        "let options = AsReqOptions::from_libdefaults(timestamp(1), 2, &defaults);\nassert_eq!(options.etypes, vec![19_i32]);",
        "if !env::in_child(TEST_PATH) { env::run_in_child(TEST_PATH, &[]); return; }\n"
        'let error = TokioClient::from_default_ccache_name(Config::new(), KdcProtocol::Tcp).expect_err("missing");\n'
        "let client = TokioClient::from_tgt_session(Config::new(), KdcProtocol::Tcp, sample_tgt_session());\n"
        "let error = client.save_default_ccache_name().unwrap_err();\nassert!(matches!(error, Error::NoDefaultCCacheName));",
    ):
        source = "/// checks behavior\n#[test]\nfn probe() {\n" + body + "\n}\n"
        assert not scan(source, False), body
        for fallible in (
            'read_file().expect("fixture");',
            "value.unwrap();",
            'panic!("failure");',
            "read_file();",
            "read_file()?;",
            "let data = String::from(read_file());",
            "AsReqOptions::from_libdefaults(read_file(), 2, &defaults);",
            'read_file().expect("fixture").unwrap_err();',
            "let error = read_file().unwrap_err(); unrelated();",
        ):
            changed = source.replace("fn probe() {", "fn probe() { " + fallible)
            assert any(g == "test-result" for g, _, _ in scan(changed, False)), fallible
    print(
        "prose_infallible self-test: ok (fork assertions, constructors, error assertions, fallible controls)"
    )


if __name__ == "__main__":
    self_test()
