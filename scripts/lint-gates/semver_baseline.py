#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/semver_baseline.py [--self-test]
"""Run cargo-semver-checks against the highest published rskrb5-ng version.

The baseline is the highest `rskrb5-ng` version on crates.io whose SemVer
precedence is at most the candidate in `Cargo.toml`; cargo-semver-checks takes
it from the registry (`--baseline-version`), so the published bytes are what
the candidate is compared with. When that version equals the candidate, the
candidate is packaged (`cargo package --locked --no-verify`): if its sha256 is
the published checksum this commit is the published release and there is
nothing to compare; otherwise the check fails with "version already published;
bump the version". Only a crate with no published version is a first release
(a notice, exit 0). A failed crates.io lookup is an error, never a skip.

Release tags (`N.N.N`; the historical `vN.N.N` too) are not baselines, but
every tag whose `Cargo.toml` names `rskrb5-ng` must carry exactly the tag's
version: a mislabelled tag is an error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
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
TAG: Final = re.compile(r"v?(\d+\.\d+\.\d+)")
VERSION: Final = re.compile(
    r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?"
)
USER_AGENT: Final = (
    "rskrb5-ng-ci semver_baseline.py (https://github.com/andrico21/rskrb5-ng)"
)
NOTICE: Final = f"::notice::first {CRATE} release: no published version"
REPUBLISHED: Final = "version already published; bump the version"

Identifier = tuple[int, int, str]
VersionKey = tuple[int, int, int, tuple[int, tuple[Identifier, ...]]]


def version_key(version: str) -> VersionKey:
    """SemVer 2.0.0 precedence: numeric pre-release identifiers compare as
    numbers and below alphanumeric ones, a shorter identifier list first, and
    any pre-release below its release; build metadata is ignored."""
    match = VERSION.fullmatch(version)
    if match is None:
        raise ValueError(f"not a SemVer version: {version!r}")
    major, minor, patch, pre = match.groups()
    if pre is None:
        tail: tuple[int, tuple[Identifier, ...]] = (1, ())
    else:
        tail = (
            0,
            tuple(
                (0, int(part), "") if part.isdigit() else (1, 0, part)
                for part in pre.split(".")
            ),
        )
    return (int(major), int(minor), int(patch), tail)


def package(manifest: str) -> tuple[str, str] | None:
    """The `[package]` name and version of a manifest, or None without them."""
    table = tomllib.loads(manifest).get("package", {})
    name, version = table.get("name"), table.get("version")
    if isinstance(name, str) and isinstance(version, str):
        return name, version
    return None


def select(candidate: str, published: list[str]) -> str | None:
    """The highest published version at or below `candidate`, or None."""
    floor = version_key(candidate)
    eligible = [version for version in published if version_key(version) <= floor]
    return max(eligible, key=version_key, default=None)


def mislabelled_tags(
    tags: list[str], manifest_at: Callable[[str], str | None]
) -> list[str]:
    """Release-shaped tags whose `rskrb5-ng` manifest carries another version."""
    errors = []
    for tag in tags:
        shape = TAG.fullmatch(tag)
        manifest = manifest_at(tag) if shape else None
        identity = package(manifest) if manifest is not None else None
        if shape and identity is not None and identity[0] == CRATE:
            if identity[1] != shape[1]:
                errors.append(
                    f"tag {tag} names {CRATE} {identity[1]}: a release tag must carry "
                    "exactly its own version; move or delete the tag"
                )
    return errors


def git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=ROOT, text=True, capture_output=True, check=False
    )


def git_tags() -> list[str]:
    listing = git("tag", "--list")
    if listing.returncode != 0:
        raise RuntimeError(f"git tag failed: {listing.stderr.strip()}")
    return listing.stdout.split()


def git_manifest(tag: str) -> str | None:
    shown = git("show", f"{tag}:Cargo.toml")
    return shown.stdout if shown.returncode == 0 else None


def crates_io_versions() -> dict[str, str]:
    """Every published version of the crate and its `.crate` sha256; {} for 404."""
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{CRATE}", headers={"User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {}
        raise RuntimeError(f"crates.io answered {error.code} for {CRATE}") from error
    except (urllib.error.URLError, json.JSONDecodeError) as error:
        raise RuntimeError(f"crates.io lookup failed for {CRATE}: {error}") from error
    versions = {entry["num"]: entry["checksum"] for entry in body.get("versions", [])}
    if not versions:
        raise RuntimeError(f"crates.io lists {CRATE} without any version")
    return versions


def packaged_sha256(version: str) -> str:
    """Package the checkout without building anything and hash the `.crate`."""
    subprocess.run(
        ["cargo", "package", "--locked", "--no-verify", "--quiet"], cwd=ROOT, check=True
    )
    metadata = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--no-deps"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )
    archive = (
        Path(metadata["target_directory"]) / "package" / f"{CRATE}-{version}.crate"
    )
    return hashlib.sha256(archive.read_bytes()).hexdigest()


def candidate_version() -> str:
    identity = package((ROOT / "Cargo.toml").read_text())
    if identity is None or identity[0] != CRATE:
        raise RuntimeError(f"Cargo.toml does not name the {CRATE} package")
    return identity[1]


def plan(
    candidate: str, published: dict[str, str], local_sha256: Callable[[], str]
) -> tuple[str, str | None]:
    """("notice"|"release"|"check", baseline) for the candidate; raises on a republish."""
    if not published:
        return "notice", None
    baseline = select(candidate, list(published))
    if baseline is None:
        raise RuntimeError(
            f"{CRATE} {candidate} is below every published version "
            f"({', '.join(sorted(published, key=version_key))})"
        )
    if version_key(baseline) != version_key(candidate):
        return "check", baseline
    if local_sha256() != published[baseline]:
        raise RuntimeError(f"{CRATE} {candidate}: {REPUBLISHED}")
    return "release", baseline


def self_test() -> int:
    def manifest(name: str, version: str) -> str:
        return f'[package]\nname = "{name}"\nversion = "{version}"\n'

    def never() -> str:
        raise AssertionError("packaged without an equal published version")

    # SemVer precedence, pre-release identifiers included (FU-GATE-09).
    ordered = [
        "0.4.0-alpha",
        "0.4.0-alpha.1",
        "0.4.0-rc.2",
        "0.4.0-rc.10",
        "0.4.0-rc.a",
        "0.4.0",
        "0.10.0",
    ]
    assert sorted(reversed(ordered), key=version_key) == ordered
    assert version_key("1.0.0+build.5") == version_key("1.0.0")
    # No published version: the first release, and no packaging.
    assert plan("0.3.0", {}, never) == ("notice", None)
    # The highest published version below the candidate is the baseline.
    published = {"0.3.0": "a", "0.3.1": "b", "0.5.0": "c"}
    assert plan("0.4.0", published, never) == ("check", "0.3.1")
    # A published version equal to the candidate is the baseline, never a
    # first release (FU-GATE-11): the same bytes are the release itself ...
    assert plan("0.3.0", {"0.3.0": "same"}, lambda: "same") == ("release", "0.3.0")
    # ... and different bytes under a published version fail.
    try:
        plan("0.3.0", {"0.3.0": "published"}, lambda: "changed")
    except RuntimeError as error:
        assert REPUBLISHED in str(error)
    else:
        raise AssertionError("a changed tree under a published version passed")
    # A candidate below every published version is an error, not a notice.
    try:
        plan("0.2.0", {"0.3.0": "a"}, never)
    except RuntimeError as error:
        assert "below every published version" in str(error)
    else:
        raise AssertionError("a candidate below every published version passed")
    # A mislabelled release tag cannot select anything and is reported (FU-GATE-10).
    tags = {
        "0.3.9": manifest(CRATE, "0.3.0"),
        "0.3.1": manifest(CRATE, "0.3.1"),
        "v0.2.2": manifest("rskrb5-patched", "0.2.2"),
        "archive/release/0.3.0": manifest(CRATE, "0.2.9"),
    }
    assert plan("0.4.0", {"0.3.0": "a", "0.3.1": "b"}, never) == ("check", "0.3.1")
    assert mislabelled_tags(list(tags), tags.get) == [
        f"tag 0.3.9 names {CRATE} 0.3.0: a release tag must carry exactly its own "
        "version; move or delete the tag"
    ]
    print(
        "semver_baseline self-test: ok (pre-release precedence, first release, "
        "published baseline, equal published version, republish, mislabelled tag)"
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
        mislabelled = mislabelled_tags(git_tags(), git_manifest)
        if mislabelled:
            raise RuntimeError("; ".join(mislabelled))
        mode, baseline = plan(
            candidate, crates_io_versions(), lambda: packaged_sha256(candidate)
        )
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        subprocess.CalledProcessError,
        tomllib.TOMLDecodeError,
    ) as error:
        print(f"::error::semver_baseline: {error}", file=sys.stderr)
        return 1
    if mode == "notice":
        print(NOTICE)
        return 0
    if mode == "release":
        print(f"semver_baseline: this commit is the published {CRATE} {candidate}")
        return 0
    print(f"semver_baseline: {CRATE} {candidate} against the published {baseline}")
    command = [
        "cargo",
        "semver-checks",
        "check-release",
        "--baseline-version",
        str(baseline),
    ]
    return subprocess.run(command, cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
