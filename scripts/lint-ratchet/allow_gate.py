#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/allow_gate.py --self-test
"""Forbid Rust allow attributes; ported from rmcp-server-kit (MIT/Apache-2.0)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import common


def scan(files: list[Path]) -> list[str]:
    hits = []
    for path in files:
        original, stripped = common.read_source(path)
        for call in common.attribute_calls(original, stripped):
            if call.form == "allow":
                hits.append(
                    f"{path}:{common.line_of(original, call.kw_start)}: allow({', '.join(call.lints)}) [{call.predicate}]"
                )
    return hits


def self_test() -> int:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / "fixture.rs"
        path.write_text(
            '// #[allow(fake)]\nconst X: &str = "#[allow(fake)]";\n'
            "#[cfg_attr(test, allow(dead_code), derive(Debug))]\nfn f() {}\n"
            "#![allow(unused)]\n#[allow(a,b)]\n"
        )
        hits = scan([path])
        assert len(hits) == 3 and ":3:" in hits[0]
        assert "a, b" in hits[-1]
        (root / "fuzz/fuzz_targets").mkdir(parents=True)
        (root / "fuzz/fuzz_targets/probe.rs").write_text("#![allow(unused)]")
        assert len(scan(list(common.iter_rust_files(root)))) == 1
        assert main(["--enforce", "--files", str(path)]) == 1
    print("allow_gate self-test: ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--files", nargs="+")
    parser.add_argument("--root", type=Path, default=common.ROOT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    files = (
        [Path(p) for p in args.files]
        if args.files
        else list(common.iter_rust_files(args.root))
    )
    hits = scan(files)
    print("\n".join(hits + [f"allow_gate: {len(hits)} allow attribute(s)"]))
    return int(args.enforce and bool(hits))


if __name__ == "__main__":
    sys.exit(main())
