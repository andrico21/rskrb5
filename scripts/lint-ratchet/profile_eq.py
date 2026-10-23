#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/profile_eq.py --self-test
"""Semantic profile equality, without deltas (rmcp-server-kit MIT/Apache-2.0 port)."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path
from tempfile import TemporaryDirectory

import common


def find_fence(text: str, marker: str) -> str:
    for match in re.finditer(r"(?ms)^\s*```[^\n]*\n(.*?)^\s*```", text):
        if marker in match[1]:
            return match[1]
    raise RuntimeError(f"core fence not found: {marker}")


def normalise_profile(profile: dict) -> dict:
    return {
        table: {
            lint: {"level": value} if isinstance(value, str) else value
            for lint, value in entries.items()
        }
        for table, entries in profile.items()
    }


def check(root: Path, clippy_toml: bool = False) -> list[str]:
    core = (root / common.CORE_REL).read_text()
    fence = find_fence(core, "[workspace.lints.rust]").replace(
        "[workspace.lints.", "[lints."
    )
    expected = normalise_profile(tomllib.loads(fence)["lints"])
    actual = normalise_profile(
        tomllib.loads((root / "Cargo.toml").read_text()).get("lints", {})
    )
    errors = []
    for table in sorted(expected.keys() | actual.keys()):
        want, got = expected.get(table, {}), actual.get(table, {})
        for name in sorted(want.keys() | got.keys()):
            if want.get(name) != got.get(name):
                errors.append(
                    f"{table}.{name}: core={want.get(name)} Cargo.toml={got.get(name)}"
                )
    if clippy_toml:
        sample = tomllib.loads(find_fence(core, "avoid-breaking-exported-api"))
        config = tomllib.loads((root / "clippy.toml").read_text())
        for key in sample.keys() | config.keys():
            if key in ("allowed-duplicate-crates", "doc-valid-idents"):
                want, got = sample.get(key, []), config.get(key, [])
                if (
                    not isinstance(got, list)
                    or not isinstance(want, list)
                    or got[: len(want)] != want
                ):
                    errors.append(f"{key}: must append to core sample {want}")
            elif sample.get(key) != config.get(key):
                errors.append(
                    f"{key}: core={sample.get(key)} clippy.toml={config.get(key)}"
                )
    return errors


def self_test() -> int:
    profile = '[workspace.lints.rust]\nunsafe_code = "forbid"\n[workspace.lints.clippy]\nunwrap_used = "deny"\n'
    sample = 'avoid-breaking-exported-api = false\ndoc-valid-idents = [".."]\n'
    with TemporaryDirectory() as directory:
        root = Path(directory)
        (root / common.CORE_REL).parent.mkdir(parents=True)
        (root / common.CORE_REL).write_text(
            "```toml\n" + profile + "```\n```toml\n" + sample + "```\n"
        )
        manifest = profile.replace("workspace.", "")
        (root / "Cargo.toml").write_text(manifest)
        (root / "clippy.toml").write_text(
            sample.replace('[".."]', '["..", "Kerberos"]')
        )
        assert check(root, True) == []
        (root / "Cargo.toml").write_text(manifest.replace('"deny"', '"warn"'))
        (root / "scripts/lint-ratchet").mkdir(parents=True)
        (root / "scripts/lint-ratchet/profile-deltas.toml").write_text(
            '[[level]]\nlint = "clippy::unwrap_used"\nlevel = "warn"\n'
        )
        assert any("unwrap_used" in e for e in check(root))
        assert main(["--root", str(root)]) == 1
        (root / "Cargo.toml").write_text(manifest.replace('unwrap_used = "deny"\n', ""))
        assert any("unwrap_used" in e for e in check(root))
        (root / "Cargo.toml").write_text(manifest)
        (root / "clippy.toml").write_text(sample.replace('[".."]', '["Kerberos"]'))
        assert any("doc-valid-idents" in e for e in check(root, True))
    print("profile_eq self-test: ok (level, missing lint, delta bypass, append-only)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clippy-toml", action="store_true")
    parser.add_argument("--root", type=Path, default=common.ROOT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        errors = check(args.root, args.clippy_toml)
    except (OSError, ValueError, RuntimeError) as error:
        errors = [str(error)]
    print("\n".join(errors) if errors else "profile_eq: core profile matches")
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
