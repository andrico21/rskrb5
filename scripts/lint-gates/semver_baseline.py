#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/semver_baseline.py [--self-test]
"""Run cargo-semver-checks against the last published rskrb5-ng release tag.

The baseline is the highest `vX.Y.Z` tag whose `Cargo.toml` names `rskrb5-ng`
with a version strictly below the candidate in `Cargo.toml`, and whose version
is published for `rskrb5-ng` on crates.io. Without such a tag this is the first
`rskrb5-ng` release: print a notice and exit 0. A failed crates.io lookup is an
error, never a silent skip.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]
CRATE: Final = "rskrb5-ng"
TAG: Final = re.compile(r"v(\d+)\.(\d+)\.(\d+)")
VERSION: Final = re.compile(
    r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?"
)
USER_AGENT: Final = (
    "rskrb5-ng-ci semver_baseline.py (https://github.com/andrico21/rskrb5-ng)"
)
NOTICE: Final = f"::notice::first {CRATE} release: no published baseline"

VersionKey = tuple[int, int, int, int, str]


def version_key(version: str) -> VersionKey:
    """Order versions by SemVer precedence (a pre-release sorts below its release)."""
    match = VERSION.fullmatch(version)
    if match is None:
        raise ValueError(f"not a SemVer version: {version!r}")
    major, minor, patch, pre = match.groups()
    return (int(major), int(minor), int(patch), 0 if pre else 1, pre or "")


def package(manifest: str) -> tuple[str, str] | None:
    """The `[package]` name and version of a manifest, or None without them."""
    table = tomllib.loads(manifest).get("package", {})
    name, version = table.get("name"), table.get("version")
    if isinstance(name, str) and isinstance(version, str):
        return name, version
    return None


def select(
    candidate: str,
    tags: list[str],
    manifest_at: Callable[[str], str | None],
    published: Callable[[str], bool],
) -> str | None:
    """The highest qualifying baseline tag for `candidate`, or None."""
    floor = version_key(candidate)
    release_tags = [tag for tag in tags if TAG.fullmatch(tag)]
    release_tags.sort(key=lambda tag: version_key(tag[1:]), reverse=True)
    for tag in release_tags:
        if version_key(tag[1:]) >= floor:
            continue
        manifest = manifest_at(tag)
        identity = package(manifest) if manifest is not None else None
        if identity is None or identity[0] != CRATE:
            continue
        if version_key(identity[1]) >= floor:
            continue
        if published(identity[1]):
            return tag
    return None


def git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=ROOT, text=True, capture_output=True, check=False
    )


def git_tags() -> list[str]:
    listing = git("tag", "--list", "v*")
    if listing.returncode != 0:
        raise RuntimeError(f"git tag failed: {listing.stderr.strip()}")
    return listing.stdout.split()


def git_manifest(tag: str) -> str | None:
    shown = git("show", f"{tag}:Cargo.toml")
    return shown.stdout if shown.returncode == 0 else None


def crates_io_published(version: str) -> bool:
    """True for 200, False for 404; every other outcome raises."""
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{CRATE}/{version}",
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status == 200:
                return True
            raise RuntimeError(
                f"crates.io answered {response.status} for {CRATE} {version}"
            )
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise RuntimeError(
            f"crates.io answered {error.code} for {CRATE} {version}"
        ) from error
    except urllib.error.URLError as error:
        raise RuntimeError(
            f"crates.io lookup failed for {CRATE} {version}: {error.reason}"
        ) from error


def candidate_version() -> str:
    identity = package((ROOT / "Cargo.toml").read_text())
    if identity is None or identity[0] != CRATE:
        raise RuntimeError(f"Cargo.toml does not name the {CRATE} package")
    return identity[1]


def self_test() -> int:
    def manifest(name: str, version: str) -> str:
        return f'[package]\nname = "{name}"\nversion = "{version}"\n'

    def fixture(
        manifests: dict[str, str], published_versions: set[str]
    ) -> tuple[
        list[str], Callable[[str], str | None], Callable[[str], bool], list[str]
    ]:
        queried: list[str] = []

        def published(version: str) -> bool:
            queried.append(version)
            return version in published_versions

        return list(manifests), manifests.get, published, queried

    # The v0.2.x tags name the predecessor package, not rskrb5-ng.
    patched = {
        "v0.2.1": manifest("predecessor", "0.2.1"),
        "v0.2.2": manifest("predecessor", "0.2.2"),
        "archive/release/0.3.0": manifest(CRATE, "0.2.9"),
    }
    # Given only predecessor release tags, there is no baseline (and no lookup).
    tags, manifest_at, published, queried = fixture(patched, set())
    assert select("0.3.0", tags, manifest_at, published) is None
    assert queried == []
    # Given a published prior rskrb5-ng release, it is the baseline.
    tags, manifest_at, published, queried = fixture(
        {**patched, "v0.3.0": manifest(CRATE, "0.3.0")}, {"0.3.0"}
    )
    assert select("0.4.0", tags, manifest_at, published) == "v0.3.0"
    # Given a higher prior tag whose version is not on crates.io, it is skipped.
    tags, manifest_at, published, queried = fixture(
        {
            **patched,
            "v0.3.0": manifest(CRATE, "0.3.0"),
            "v0.3.1": manifest(CRATE, "0.3.1"),
        },
        {"0.3.0"},
    )
    assert select("0.4.0", tags, manifest_at, published) == "v0.3.0"
    assert queried == ["0.3.1", "0.3.0"]
    # Given a published tag at the candidate version itself, it is never chosen.
    tags, manifest_at, published, queried = fixture(
        {**patched, "v0.4.0": manifest(CRATE, "0.4.0")}, {"0.4.0"}
    )
    assert select("0.4.0", tags, manifest_at, published) is None
    assert queried == []
    tags, manifest_at, published, queried = fixture(
        {"v0.3.0": manifest(CRATE, "0.4.0")}, {"0.4.0"}
    )
    assert select("0.4.0", tags, manifest_at, published) is None
    # A failing lookup is an error, never a silent skip.

    def broken(version: str) -> bool:
        raise RuntimeError(f"crates.io answered 503 for {CRATE} {version}")

    try:
        select("0.4.0", ["v0.3.0"], {"v0.3.0": manifest(CRATE, "0.3.0")}.get, broken)
    except RuntimeError:
        pass
    else:
        raise AssertionError("a failed lookup must propagate")
    assert version_key("0.4.0-rc.1") < version_key("0.4.0") < version_key("0.10.0")
    print(
        "semver_baseline self-test: ok (no baseline, published prior, unpublished prior, candidate tag)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        candidate = candidate_version()
        baseline = select(candidate, git_tags(), git_manifest, crates_io_published)
    except (OSError, ValueError, RuntimeError, tomllib.TOMLDecodeError) as error:
        print(f"semver_baseline: {error}", file=sys.stderr)
        return 1
    if baseline is None:
        print(NOTICE)
        return 0
    print(f"semver_baseline: {CRATE} {candidate} against {baseline}")
    command = ["cargo", "semver-checks", "check-release", "--baseline-rev", baseline]
    return subprocess.run(command, cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
