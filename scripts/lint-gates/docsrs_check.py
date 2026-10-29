#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/docsrs_check.py --self-test
"""Hold the docs.rs build configuration to the advertised optional APIs.

docs.rs builds the default features plus `[package.metadata.docs.rs]`
`features` (or every feature with `all-features = true`). The HTTP helpers
and the Tower middleware are optional, so the metadata must select `http` and
`tower`. `--features` prints the selection for `cargo doc --features`, and
`--verify DOC_DIR` checks that the rustdoc built with it documents every page
in `REQUIRED_PAGES`.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]
ADVERTISED: Final = ("http", "tower")
REQUIRED_PAGES: Final = (
    "rskrb5_ng/http/struct.NegotiateLayer.html",
    "rskrb5_ng/http/fn.send_with_negotiate.html",
)


def docs_rs_features(manifest: str) -> list[str]:
    """The optional features docs.rs enables; raises unless they cover `ADVERTISED`."""
    parsed = tomllib.loads(manifest)
    metadata = parsed.get("package", {}).get("metadata", {}).get("docs", {}).get("rs")
    if not isinstance(metadata, dict):
        raise ValueError("Cargo.toml has no [package.metadata.docs.rs] table")
    if metadata.get("all-features") is True:
        return sorted(name for name in parsed.get("features", {}) if name != "default")
    features = metadata.get("features", [])
    missing = [name for name in ADVERTISED if name not in features]
    if missing:
        raise ValueError(f"[package.metadata.docs.rs] features lack {missing}")
    return list(features)


def missing_pages(doc_dir: Path) -> list[str]:
    return [page for page in REQUIRED_PAGES if not (doc_dir / page).is_file()]


def self_test() -> int:
    base = (
        '[package]\nname = "p"\n[features]\ndefault = []\nhttp = []\ntower = ["http"]\n'
    )
    for manifest, expected in (
        (
            base + '[package.metadata.docs.rs]\nfeatures = ["http", "tower"]\n',
            ["http", "tower"],
        ),
        (base + "[package.metadata.docs.rs]\nall-features = true\n", ["http", "tower"]),
    ):
        assert docs_rs_features(manifest) == expected, manifest
    for manifest in (base, base + '[package.metadata.docs.rs]\nfeatures = ["http"]\n'):
        try:
            docs_rs_features(manifest)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted {manifest!r}")
    with TemporaryDirectory() as directory:
        doc = Path(directory)
        assert missing_pages(doc) == list(REQUIRED_PAGES)
        for page in REQUIRED_PAGES:
            (doc / page).parent.mkdir(parents=True, exist_ok=True)
            (doc / page).write_text("<html></html>")
        assert missing_pages(doc) == []
    print(
        "docsrs_check self-test: ok (explicit and all-features metadata, missing feature, missing page)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--features", action="store_true")
    parser.add_argument("--verify", type=Path, metavar="DOC_DIR")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        features = docs_rs_features(
            (args.root / "Cargo.toml").read_text(encoding="utf-8")
        )
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"docsrs_check: {error}", file=sys.stderr)
        return 1
    if args.features:
        print(",".join(features))
    if args.verify:
        missing = missing_pages(args.verify)
        for page in missing:
            print(
                f"docsrs_check: {args.verify / page} was not generated", file=sys.stderr
            )
        return int(bool(missing))
    return 0


if __name__ == "__main__":
    sys.exit(main())
