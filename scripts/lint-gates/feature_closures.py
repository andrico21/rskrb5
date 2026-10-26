#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/feature_closures.py list
"""Compute Cargo feature closures and canonical build arguments."""

from __future__ import annotations

import argparse
import itertools
import re
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


@dataclass(frozen=True, slots=True)
class Line:
    """One structural line of a block-style YAML workflow."""

    number: int
    indent: int
    item: bool
    key: str | None
    value: str


CLIPPY_RUN = "cargo clippy --all-targets ${{ matrix.closures }} -- -D warnings"
TEST_RUN = "cargo test ${{ matrix.closures }}"
_KEY = re.compile(
    r"""(?P<key>"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s"'#:\[\]{},&*!|>%@`-][^:#]*?|-[^\s:#][^:#]*?)"""
    r"""\s*:(?:[ \t]+(?P<value>.*)|)$"""
)


def _scalar(text: str, where: str) -> str:
    """Read one flow scalar: quoted, or plain, with an optional trailing comment."""
    text = text.strip()
    if text[:1] == '"':
        match = re.fullmatch(r'"([^"\\]*)"\s*(?:#.*)?', text)
        if match is None:
            raise RuntimeError(f"{where}: unsupported double-quoted scalar: {text}")
        return match[1]
    if text[:1] == "'":
        match = re.fullmatch(r"'((?:[^']|'')*)'\s*(?:#.*)?", text)
        if match is None:
            raise RuntimeError(f"{where}: unsupported single-quoted scalar: {text}")
        return match[1].replace("''", "'")
    value = re.split(r"\s+#", text, maxsplit=1)[0].strip()
    if not value or value[0] in "[]{},&*!|>%@`#" or ": " in value:
        raise RuntimeError(f"{where}: unsupported scalar: {text}")
    return value


def _structure(text: str) -> list[Line]:
    """Split a block-style workflow into keyed and list-item lines.

    Comments, blank lines and the bodies of `|`/`>` block scalars are dropped,
    so a script line such as `closures:` inside `run: |` is never a key. Tabs in
    indentation, flow collections and anchors are rejected, not guessed at.
    """
    lines: list[Line] = []
    block: int | None = None
    for number, raw in enumerate(text.splitlines(), 1):
        body = raw.lstrip(" ")
        indent = len(raw) - len(body)
        if block is not None:
            if not body.strip() or indent > block:
                continue
            block = None
        if not body.strip() or body.startswith("#"):
            continue
        if body.startswith("\t") or raw.startswith("\t"):
            raise RuntimeError(f"ci.yml:{number}: tab in indentation")
        item = False
        if re.match(r"-(?:\s|$)", body):
            item = True
            rest = body[1:].lstrip(" ")
            indent += len(body) - len(rest)
            body = rest
        match = _KEY.match(body.rstrip())
        if match is None:
            lines.append(Line(number, indent, item, None, body.rstrip()))
            continue
        key = match["key"]
        if key[0] == '"':
            key = key[1:-1]
        elif key[0] == "'":
            key = key[1:-1].replace("''", "'")
        value = (match["value"] or "").strip()
        if value.startswith(("&", "*", "<<")) or key == "<<":
            raise RuntimeError(f"ci.yml:{number}: anchors and merges are not supported")
        if re.match(r"[|>][-+0-9]*\s*(?:#.*)?$", value):
            block = indent
        lines.append(Line(number, indent, item, key, value))
    return lines


def _children(lines: list[Line], parent: int) -> list[int]:
    """Indexes of the direct children of `lines[parent]`."""
    end = parent + 1
    while end < len(lines) and lines[end].indent > lines[parent].indent:
        end += 1
    if end == parent + 1:
        return []
    depth = lines[parent + 1].indent
    return [i for i in range(parent + 1, end) if lines[i].indent == depth]


def _subtree(lines: list[Line], parent: int) -> list[Line]:
    end = parent + 1
    while end < len(lines) and lines[end].indent > lines[parent].indent:
        end += 1
    return lines[parent + 1 : end]


def _only(lines: list[Line], indexes: list[int], key: str, where: str) -> int:
    found = [i for i in indexes if lines[i].key == key and not lines[i].item]
    if len(found) != 1:
        raise RuntimeError(f"{where} needs exactly one `{key}:` key, found {len(found)}")
    return found[0]


def ci_matrix(text: str) -> list[str]:
    """The closure arguments of `jobs.closures.strategy.matrix.closures`.

    The job is selected by its id, exactly once; no other `closures:` key may
    exist anywhere (a decoy job or matrix), the matrix holds nothing else
    (no `include`/`exclude`), and the job runs both strict steps on every leg.
    """
    lines = _structure(text)
    top = [i for i, line in enumerate(lines) if line.indent == 0]
    if any(lines[i].item or lines[i].key is None for i in top):
        raise RuntimeError("ci.yml: the top level must be a mapping")
    jobs = _only(lines, top, "jobs", "ci.yml")
    job = _only(lines, _children(lines, jobs), "closures", "jobs")
    strategy = _only(lines, _children(lines, job), "strategy", "jobs.closures")
    matrix = _only(
        lines, _children(lines, strategy), "matrix", "jobs.closures.strategy"
    )
    keys = [lines[i].key for i in _children(lines, matrix)]
    if keys != ["closures"]:
        raise RuntimeError(f"jobs.closures matrix must hold only `closures`, has {keys}")
    key = _children(lines, matrix)[0]
    if lines[key].value and not lines[key].value.startswith("#"):
        raise RuntimeError("the closures matrix must be a block list of strings")
    entries = []
    end = key + 1
    while end < len(lines) and (
        lines[end].indent > lines[key].indent
        or (lines[end].indent == lines[key].indent and lines[end].item)
    ):
        end += 1
    items = lines[key + 1 : end]
    if any(not line.item or line.key is not None for line in items) or len(
        {line.indent for line in items}
    ) > 1:
        raise RuntimeError("the closures matrix must be a flat list of strings")
    for line in items:
        entries.append(_scalar(line.value, f"ci.yml:{line.number}"))
    stray = [
        line.number
        for line in lines
        if line.key == "closures" and line is not lines[job] and line is not lines[key]
    ]
    if stray:
        raise RuntimeError(f"ci.yml: another `closures:` key (decoy) on line(s) {stray}")
    body = _subtree(lines, job)
    for line in body:
        if line.key in ("continue-on-error", "if"):
            raise RuntimeError(f"ci.yml:{line.number}: the closures job may not use `{line.key}:`")
    runs = [
        _scalar(line.value, f"ci.yml:{line.number}")
        for line in body
        if line.key == "run"
    ]
    if runs != [CLIPPY_RUN, TEST_RUN]:
        raise RuntimeError(
            f"the closures job must run exactly {[CLIPPY_RUN, TEST_RUN]}, runs {runs}"
        )
    return entries


def check_ci(closures: list[Closure], path: Path) -> None:
    """Hold the real `closures` job's matrix equal to the computed closures."""
    values = ci_matrix(path.read_text())
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

    def job(
        entries: list[str],
        *,
        name: str = "closures",
        key: str = "closures:",
        runs: tuple[str, ...] = (CLIPPY_RUN, TEST_RUN),
    ) -> str:
        return (
            f"  {name}:\n    name: {name}\n    runs-on: ubuntu-latest\n"
            "    strategy:\n      fail-fast: false\n      matrix:\n"
            f"        # every closure\n        {key}\n"
            + "".join(f"          - {entry}\n" for entry in entries)
            + "    steps:\n      - uses: actions/checkout@v7 # pinned\n"
            + "".join(f"      - name: step\n        run: {run}\n" for run in runs)
        )

    quoted = [f'"{shlex.join(closure.arguments)}"' for closure in closures]
    head = "name: CI\non:\n  push:\njobs:\n  fmt:\n    runs-on: ubuntu-latest\n"
    script = (
        "  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n"
        "          closures:\n          - '--all-features'\n"
    )
    accepted = {
        "plain": head + job(quoted),
        "single-quoted, commented, unquoted and blank-separated entries": head
        + job(
            [f"'{value[1:-1]}'" for value in quoted[:-3]]
            + [quoted[-3] + "  # trailing comment\n\n          # comment line", quoted[-2]]
            + [quoted[-1][1:-1] or '""']
        ).replace("      matrix:\n", "      matrix: # comment\n"),
        "quoted keys": head.replace("jobs:", '"jobs":')
        + job(quoted, key="'closures':").replace('  closures:\n', '  "closures":\n', 1),
        "a block scalar mentioning closures": head + script + job(quoted),
    }
    rejected = {
        "missing entry": head + job(quoted[1:]),
        "duplicate entry": head + job(quoted + quoted[:1]),
        "decoy job before, real matrix short": head
        + job(quoted, name="decoy")
        + job(quoted[1:]),
        "decoy matrix after": head + job(quoted) + job(quoted, name="decoy"),
        "duplicate closures job": head + job(quoted) + job(quoted),
        "no jobs mapping": job(quoted).replace("  ", "", 1),
        "exclude in the matrix": head
        + job(quoted).replace(
            "    steps:", "        exclude:\n          - other: x\n    steps:", 1
        ),
        "flow-style list": head
        + job([]).replace(
            "        closures:\n", "        closures: [" + ", ".join(quoted) + "]\n"
        ),
        "continue-on-error": head
        + job(quoted).replace("    steps:", "    continue-on-error: true\n    steps:"),
        "skipped step": head
        + job(quoted).replace("        run: cargo test", "        if: false\n        run: cargo test"),
        "no -D warnings": head
        + job(quoted, runs=("cargo clippy --all-targets ${{ matrix.closures }}", TEST_RUN)),
        "no test step": head + job(quoted, runs=(CLIPPY_RUN,)),
        "tab indentation": head + job(quoted).replace("          - ", "\t- ", 1),
    }
    with TemporaryDirectory() as directory:
        path = Path(directory) / "ci.yml"
        for label, text in accepted.items():
            path.write_text(text)
            check_ci(closures, path)
            assert ci_matrix(text), label
        for label, text in rejected.items():
            path.write_text(text)
            try:
                check_ci(closures, path)
            except RuntimeError:
                pass
            else:
                raise AssertionError(f"check-ci accepted: {label}")
    print(
        f"feature_closures self-test: ok (check-ci: {len(accepted)} workflows "
        f"accepted, {len(rejected)} rejected)"
    )
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
