#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/feature_closures.py list
"""Compute Cargo feature closures and canonical build arguments."""

from __future__ import annotations

import argparse
import itertools
import shlex
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

import common


@dataclass(frozen=True, slots=True)
class Closure:
    features: frozenset[str]
    arguments: tuple[str, ...]

    @property
    def label(self) -> str:
        return ",".join(sorted(self.features)) or "(none)"


def resolve(features: dict[str, list[str]], seeds: frozenset[str]) -> frozenset[str]:
    """Follow only local feature edges."""
    result = set(seeds)
    pending = list(seeds)
    while pending:
        for edge in features[pending.pop()]:
            if edge in features and edge not in result:
                result.add(edge)
                pending.append(edge)
    return frozenset(result)


def compute(features: dict[str, list[str]]) -> list[Closure]:
    """Expand reachable unions, retaining shortest lexicographic generators."""
    generators: dict[frozenset[str], tuple[str, ...]] = {frozenset(): ()}
    for name in sorted(features):
        for closure, seeds in list(generators.items()):
            expanded = closure | resolve(features, frozenset({name}))
            candidate = (*seeds, name)
            prior = generators.get(expanded)
            if prior is None or (len(candidate), candidate) < (len(prior), prior):
                generators[expanded] = candidate
    default = (
        resolve(features, frozenset({"default"}))
        if "default" in features
        else frozenset()
    )
    result = []
    for closure, seeds in generators.items():
        if closure == frozenset(features):
            arguments = ("--all-features",)
        elif "default" in closure:
            candidates = [
                seed
                for part, seed in generators.items()
                if "default" not in part and part | default == closure
            ]
            extra = min(candidates, key=lambda seed: (len(seed), seed))
            arguments = ("--features", ",".join(extra)) if extra else ()
        else:
            arguments = ("--no-default-features",)
            if seeds:
                arguments += ("--features", ",".join(seeds))
        result.append(Closure(closure, arguments))
    return sorted(result, key=lambda value: (len(value.features), value.label))


def load(root: Path) -> list[Closure]:
    with (root / "Cargo.toml").open("rb") as stream:
        return compute(tomllib.load(stream)["features"])


def check_ci(closures: list[Closure], path: Path) -> None:
    """Read the dedicated matrix's quoted shell strings without YAML dependencies."""
    import re

    match = re.search(r"(?m)^( +)closures:\s*\n((?:\1 +[^\n]*\n)+)", path.read_text())
    if match is None:
        raise RuntimeError("CI has no closures matrix")
    values = []
    for line in match[2].splitlines():
        value = line.strip().removeprefix("-").strip()
        if not value or value.startswith("#"):
            continue
        if value[0] not in "\"'" or value[-1] != value[0]:
            raise RuntimeError(f"closure matrix argument must be quoted: {value}")
        values.append(value[1:-1])
    expected = [shlex.join(closure.arguments) for closure in closures]
    if len(values) != len(set(values)) or set(values) != set(expected):
        raise RuntimeError(
            f"closure matrix mismatch: expected {expected}, got {values}"
        )


def self_test() -> int:
    # Given cycles and dep-only edges, expansion must match brute force.
    features = {
        "default": ["a"],
        "a": ["b"],
        "b": ["a"],
        "evaluation": ["dep:serde"],
        "serde": [],
    }
    closures = compute(features)
    brute = {
        resolve(features, frozenset(subset))
        for size in range(len(features) + 1)
        for subset in itertools.combinations(features, size)
    }
    assert {closure.features for closure in closures} == brute
    assert resolve(features, frozenset({"evaluation"})) == frozenset({"evaluation"})
    for closure in closures:
        args = closure.arguments
        seeds = (
            frozenset(args[args.index("--features") + 1].split(","))
            if "--features" in args
            else frozenset()
        )
        if "--all-features" in args:
            seeds = frozenset(features)
        elif "--no-default-features" not in args:
            seeds |= {"default"}
        assert resolve(features, seeds) == closure.features
    assert sum(not closure.arguments for closure in closures) == 1
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as directory:
        path = Path(directory) / "ci.yml"
        path.write_text(
            "matrix:\n  closures:\n"
            + "".join(
                f"    - '{shlex.join(closure.arguments)}'\n" for closure in closures
            )
        )
        check_ci(closures, path)
        for invalid in (
            "matrix:\n  closures:\n    - '--all-features'\n",
            path.read_text() + "    - '--all-features'\n",
        ):
            path.write_text(invalid)
            try:
                check_ci(closures, path)
            except RuntimeError:
                pass
            else:
                raise AssertionError("incomplete or duplicate closure matrix accepted")
    print("feature_closures self-test: ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", type=Path, default=common.ROOT)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list")
    run = sub.add_parser("run")
    mode = run.add_mutually_exclusive_group()
    mode.add_argument("--clippy-only", action="store_true")
    mode.add_argument("--test-only", action="store_true")
    sub.add_parser("check-ci").add_argument("workflow", type=Path)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    closures = load(args.root)
    if args.command == "list":
        for closure in closures:
            print(closure.label + "\t" + shlex.join(closure.arguments))
    elif args.command == "check-ci":
        check_ci(closures, args.workflow)
    elif args.command == "run":
        failures = 0
        for closure in closures:
            commands = []
            if not args.test_only:
                commands.append(
                    [
                        "clippy",
                        "--all-targets",
                        *closure.arguments,
                        "--",
                        "-D",
                        "warnings",
                    ]
                )
            if not args.clippy_only:
                commands.append(["test", *closure.arguments])
            for command in commands:
                print(f"{closure.label}: cargo {shlex.join(command)}", flush=True)
                failures += (
                    subprocess.run(
                        ["flock", "/tmp/rskrb5-cargo.lock", "cargo", *command],
                        cwd=args.root,
                    ).returncode
                    != 0
                )
        return int(bool(failures))
    else:
        parser.error("choose list, run or check-ci")
    return 0


if __name__ == "__main__":
    sys.exit(main())
