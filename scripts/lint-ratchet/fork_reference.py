#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/fork_reference.py --self-test
"""Compile compensation for the disposable fork-lines reference tree."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from tempfile import TemporaryDirectory


def compensate_reference(root: Path) -> None:
    """Repair only known upstream test-manifest omissions in the disposable tree."""
    path = root / "Cargo.toml"
    source = path.read_text()
    if "hex" in tomllib.loads(source).get("dev-dependencies", {}):
        return
    # 6f4abc9 tests/krb_priv.rs uses hex outside evaluation (K2/K4/K5/K7).
    # Match HEAD's hex = "0.4" dev-dependency, without enabling evaluation or
    # changing Rust sources, feature definitions, or either original manifest.
    addition = '\n# Gate compile compensation: upstream tests need hex without evaluation.\nhex = "0.4"\n'
    header = "[dev-dependencies]"
    source = (
        source.replace(header, header + addition, 1)
        if header in source
        else source + "\n" + header + addition
    )
    path.write_text(source)
    print(
        'fork_lines_gate: reference compile compensation: hex = "0.4" (dev-dependency)',
        file=sys.stderr,
    )


def self_test() -> int:
    with TemporaryDirectory() as directory:
        # Given: missing dev-dependencies, missing hex, or an existing version.
        root = Path(directory)
        path = root / "Cargo.toml"
        for dev_table, version in (
            ("", "0.4"),
            ('[dev-dependencies]\nother = "1"\n', "0.4"),
            ('[dev-dependencies]\nhex = "0.3"\n', "0.3"),
        ):
            source = (
                '[package]\nname = "fixture"\n[dependencies]\n'
                'hex = { version = "0.4", optional = true }\n' + dev_table
            )
            path.write_text(source)
            # When: the disposable reference receives compile compensation.
            compensate_reference(root)
            # Then: only the missing dev-dependency is added; repeats are safe.
            result = path.read_text()
            manifest = tomllib.loads(result)
            assert manifest["dev-dependencies"]["hex"] == version
            assert manifest["dev-dependencies"].get("other") == (
                tomllib.loads(source).get("dev-dependencies", {}).get("other")
            )
            assert manifest["dependencies"] == tomllib.loads(source)["dependencies"]
            compensate_reference(root)
            assert path.read_text() == result
    print(
        "fork_reference self-test: ok (missing dev-dependency, preservation, idempotence)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else 2)
