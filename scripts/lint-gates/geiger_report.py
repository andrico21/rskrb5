#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/geiger_report.py geiger.json
"""Summarize a `cargo geiger --output-format Json` scan and judge its completeness.

cargo-geiger's text output exits 1 on its own "Dependency file was never
scanned" warnings, so a scan that completed looked like a failure (CI run
40742338863: "error: Found 333 warnings"). The JSON report lists those files
(`used_but_not_scanned_files`); this script classifies them:

* build-script output (`.../build/<pkg>/out/...`): generated at build time,
  outside every package source tree, so geiger cannot attribute it;
* non-Rust files (`README.md`, `*.data`, ...) pulled in with `include_str!`,
  `include_bytes!` or `#[doc = include_str!(..)]`: data, not code;
* any other Rust source: genuinely unscanned code, an incomplete scan.

It prints the unsafe totals of the root package and of the dependencies
separately and exits 0 when the scan is complete (no unscanned Rust source
outside build-script output, every package measured), else 1. Unsafe code
found in dependencies is a result, never a failure.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Final

ROOT_PACKAGE: Final = "rskrb5-ng"
KINDS: Final = ("functions", "exprs", "item_impls", "item_traits", "methods")
BUILD_OUTPUT: Final = re.compile(r"/build/[^/]+/out/")


def classify(path: str) -> str:
    if BUILD_OUTPUT.search(path):
        return "build-script output"
    if not path.endswith(".rs"):
        return "non-Rust file"
    return "unscanned Rust source"


def unsafe_count(unsafety: dict) -> int:
    return sum(
        unsafety[usage][kind]["unsafe_"]
        for usage in ("used", "unused")
        for kind in KINDS
    )


def summarize(report: dict) -> tuple[list[str], bool]:
    """(summary lines, scan complete) of one geiger JSON report."""
    packages = report["packages"]
    root = [p for p in packages if p["package"]["id"]["name"] == ROOT_PACKAGE]
    dependencies = [p for p in packages if p["package"]["id"]["name"] != ROOT_PACKAGE]
    unscanned = Counter(classify(path) for path in report["used_but_not_scanned_files"])
    without_metrics = report.get("packages_without_metrics", [])
    with_unsafe = sorted(
        f"{p['package']['id']['name']} {p['package']['id']['version']}"
        for p in dependencies
        if unsafe_count(p["unsafety"])
    )
    lines = [
        f"geiger: {len(packages)} packages scanned",
        f"geiger: {ROOT_PACKAGE} unsafe items: "
        + (str(unsafe_count(root[0]["unsafety"])) if root else "root package missing"),
        f"geiger: dependencies with unsafe code: {len(with_unsafe)} of {len(dependencies)}"
        f" ({sum(unsafe_count(p['unsafety']) for p in dependencies)} unsafe items)",
        *(f"geiger:   {name}" for name in with_unsafe),
        f"geiger: files used but not scanned: {sum(unscanned.values())} "
        + str(dict(sorted(unscanned.items()))),
        f"geiger: packages without metrics: {len(without_metrics)}",
    ]
    complete = (
        bool(root) and not without_metrics and not unscanned["unscanned Rust source"]
    )
    lines.append(
        "geiger: scan complete"
        if complete
        else "geiger: scan INCOMPLETE (unscanned Rust source, a package without metrics, or no root package)"
    )
    return lines, complete


def self_test() -> int:
    def package(name: str, unsafe_exprs: int) -> dict:
        counts = {kind: {"safe": 1, "unsafe_": 0} for kind in KINDS}
        used = {**counts, "exprs": {"safe": 1, "unsafe_": unsafe_exprs}}
        return {
            "package": {"id": {"name": name, "version": "1.0.0"}},
            "unsafety": {"used": used, "unused": counts, "forbids_unsafe": False},
        }

    report = {
        "packages": [package(ROOT_PACKAGE, 0), package("aes", 54), package("hex", 0)],
        "packages_without_metrics": [],
        "used_but_not_scanned_files": [
            "/t/debug/build/serde-1/out/private.rs",
            "/reg/bitvec-1.1.1/README.md",
            "/reg/x-1/data/table.data",
        ],
    }
    lines, complete = summarize(report)
    assert complete, lines
    assert f"geiger: {ROOT_PACKAGE} unsafe items: 0" in lines
    assert "geiger: dependencies with unsafe code: 1 of 2 (54 unsafe items)" in lines
    assert "geiger:   aes 1.0.0" in lines
    for broken in (
        {**report, "used_but_not_scanned_files": ["/reg/x-1/src/hidden.rs"]},
        {**report, "packages_without_metrics": [{"name": "x"}]},
        {**report, "packages": report["packages"][1:]},
    ):
        assert not summarize(broken)[1], broken
    print(
        "geiger_report self-test: ok (classified unscanned files, totals, three incomplete scans)"
    )
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if len(argv) != 1:
        print("usage: geiger_report.py GEIGER_JSON | --self-test", file=sys.stderr)
        return 2
    try:
        report = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
        lines, complete = summarize(report)
    except (OSError, ValueError, KeyError, IndexError, TypeError) as error:
        print(f"geiger: the report cannot be read: {error}", file=sys.stderr)
        return 1
    print("\n".join(lines))
    return int(not complete)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
