#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/generate_baseline.py --help
# noqa: SIZE_OK - User limits implementation to this CLI and scanner.py, including inline tests.
"""Generate narrow, configuration-aware Rust lint migration expectations.

Generation measures a disposable copy with old migration attributes removed.
No original source is written until every compiler run and placement succeeds.
Manifest counts count attribute occurrences, not repeated compiler diagnostics.
The scanner API is in scanner.py; this CLI intentionally does not import the
independently maintained gate scripts or common.py.
Only the pure module-wrap transition matcher is shared with the gate.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypedDict

from baseline_moves import additions
from scanner import (
    Item,
    ScanError,
    attributes,
    canonical,
    inner_position,
    scan_items,
    tokens,
)


class BaselineError(ValueError):
    """Generation cannot safely represent a diagnostic or manifest transition."""


class Span(TypedDict):
    file_name: str
    byte_start: int
    byte_end: int
    line_start: int
    column_start: int
    is_primary: bool
    expansion: Expansion | None


class Expansion(TypedDict):
    span: Span


class Diagnostic(TypedDict):
    code: dict[str, str] | None
    level: str
    message: str
    spans: list[Span]


class Target(TypedDict):
    name: str
    kind: list[str]
    src_path: str


class CargoMessage(TypedDict, total=False):
    reason: str
    package_id: str
    target: Target
    message: Diagnostic
    profile: dict[str, bool]
    filenames: list[str]
    features: list[str]
    success: bool


@dataclass(frozen=True, slots=True, order=True)
class Build:
    config: str
    mode: str
    features: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Unit:
    target: str
    build: Build
    files: frozenset[str]
    diagnostics: tuple[Diagnostic, ...]
    crate_root: str = ""


@dataclass(frozen=True, slots=True, order=True)
class Entry:
    file: str
    item: str
    lint: str
    predicate: str
    count: int = 1


@dataclass(frozen=True, slots=True)
class Placement:
    file: str
    item: Item | None
    lint: str
    predicate: str
    inner: bool = False


MATRIX: Final = (
    ("K1", ("--all-features",)),
    ("K2", ()),
    ("K3", ("--no-default-features",)),
    ("K4", ("--features", "http")),
    ("K5", ("--features", "tower")),
    ("K6", ("--features", "evaluation")),
    ("K7", ("--no-default-features", "--features", "tokio")),
)
FEATURES: Final = (
    "default",
    "evaluation",
    "http",
    "messages",
    "serde",
    "spnego",
    "tokio",
    "tower",
)
CARGO_LINTS: Final = frozenset(
    (
        "clippy::cargo_common_metadata",
        "clippy::multiple_crate_versions",
        "clippy::negative_feature_names",
        "clippy::redundant_feature_names",
        "clippy::wildcard_dependencies",
    )
)
MANIFEST: Final = Path("scripts/lint-ratchet/baseline.toml")
IMPORT_REWRITES: Final = frozenset(
    ("clippy::std_instead_of_core", "clippy::std_instead_of_alloc")
)


def rust_files(root: Path) -> list[Path]:
    return sorted(
        path
        for name in ("src", "tests", "examples", "benches")
        for path in (root / name).rglob("*.rs")
        if path.is_file()
    )


def local_file(root: Path, filename: str) -> str | None:
    path = Path(filename)
    resolved = (root / path).resolve() if not path.is_absolute() else path.resolve()
    return (
        resolved.relative_to(root).as_posix() if resolved.is_relative_to(root) else None
    )


def primary_span(root: Path, diagnostic: Diagnostic) -> tuple[str, int] | None:
    code = diagnostic["code"]
    if code is None:
        return None
    lint = code["code"]
    if lint in (
        "unfulfilled_lint_expectations",
        "unknown_lints",
        "renamed_and_removed_lints",
    ):
        raise BaselineError(
            f"{lint}: repair existing lint policy, not a migration baseline"
        )
    if lint in CARGO_LINTS or not diagnostic["spans"]:
        raise BaselineError(
            f"crate-level {lint}: fix configuration; cannot baseline: {diagnostic['message']}"
        )
    span = next((s for s in diagnostic["spans"] if s["is_primary"]), None)
    if span is None:
        raise BaselineError(f"{lint}: missing primary span")
    best: tuple[str, int] | None = None
    while span is not None:
        file = local_file(root, span["file_name"])
        if file is not None and (root / file).is_file():
            best = file, span["byte_start"]
        expansion = span.get("expansion")
        span = expansion["span"] if expansion else None
    return best


def dep_files(root: Path, artifact: CargoMessage) -> frozenset[str]:
    """Read only this artifact's rustc dep-info, never another unit's file set."""
    paths: set[Path] = set()
    for filename in artifact.get("filenames", []):
        output = Path(filename)
        stem = output.stem
        paths.add(output.with_suffix(".d"))
        if stem.startswith("lib"):
            paths.add(output.with_name(stem[3:] + ".d"))
    files: set[str] = set()
    found = False
    for path in sorted(paths):
        if not path.is_file():
            continue
        found = True
        text = path.read_text().replace("\\\n", "")
        for line in text.splitlines():
            if ": " not in line:
                continue
            for filename in shlex.split(line.split(": ", 1)[1]):
                file = local_file(root, filename)
                if file is not None and file.endswith(".rs"):
                    files.add(file)
    if not found:
        raise BaselineError(
            f"no dep-info for {artifact['target']['name']}: {sorted(map(str, paths))}"
        )
    return frozenset(files)


def associate(
    messages: list[CargoMessage], config: str
) -> list[tuple[CargoMessage, tuple[Diagnostic, ...]]]:
    """With jobs=1, artifact.profile.test labels its preceding buffered messages."""
    pending: dict[tuple[str, str, tuple[str, ...]], list[Diagnostic]] = defaultdict(
        list
    )
    result: list[tuple[CargoMessage, tuple[Diagnostic, ...]]] = []
    for message in messages:
        if message.get("reason") not in ("compiler-message", "compiler-artifact"):
            continue
        target = message["target"]
        key = message["package_id"], target["name"], tuple(target["kind"])
        if message["reason"] == "compiler-message":
            pending[key].append(message["message"])
        else:
            result.append((message, tuple(pending.pop(key, []))))
    for key, diagnostics in pending.items():
        if not config.startswith("D"):
            raise BaselineError(f"unassociated compiler messages for {key}")
        # Cargo rustdoc emits messages but no compiler-artifact on some versions.
        message = next(
            m
            for m in messages
            if m.get("package_id") == key[0]
            and m.get("target", {}).get("name") == key[1]
        )
        result.append((message, tuple(diagnostics)))
    return result


def run_command(root: Path, args: list[str], env: dict[str, str]) -> str:
    command = (["flock", "/tmp/rskrb5-cargo.lock"] if shutil.which("flock") else []) + [
        "timeout",
        "--kill-after=10s",
        "1800s",
        "cargo",
        *args,
    ]
    print("$ " + shlex.join(command), flush=True)
    result = subprocess.run(
        command, cwd=root, env=env, text=True, capture_output=True, check=False
    )
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    print(f"EXIT {result.returncode}", flush=True)
    if result.returncode:
        raise BaselineError(
            f"compiler command failed ({result.returncode}): {shlex.join(command)}"
        )
    return result.stdout


def collect(root: Path, target_dir: Path) -> list[Unit]:
    env = dict(
        os.environ,
        CARGO_TARGET_DIR=str(target_dir),
        CARGO_BUILD_JOBS="1",
        CARGO_BUILD_WARNINGS="allow",
    )
    metadata = json.loads(
        run_command(root, ["metadata", "--no-deps", "--format-version=1"], env)
    )
    package = next(
        p
        for p in metadata["packages"]
        if Path(p["manifest_path"]).resolve() == root / "Cargo.toml"
    )
    package_id: str = package["id"]
    feature_names = tuple(sorted(package["features"]))
    if feature_names != tuple(sorted(FEATURES)):
        raise BaselineError(
            f"package feature set changed: {feature_names}; update the matrix explicitly"
        )
    units: list[Unit] = []
    configs = [
        (
            key,
            [
                "clippy",
                "--all-targets",
                *flags,
                "--message-format=json",
                "--",
                "--cap-lints",
                "warn",
            ],
        )
        for key, flags in MATRIX
    ]
    configs += [
        (
            key,
            [*toolchain, "doc", "--no-deps", "--all-features", "--message-format=json"],
        )
        for key, toolchain in (("D1", []), ("D2", ["+nightly-2026-10-03"]))
    ]
    for config, args in configs:
        for path in target_dir.rglob("*.d"):
            path.unlink()
        run_env = (
            dict(
                env,
                RUSTFLAGS=env.get("RUSTFLAGS", "") + " --cap-lints=warn",
                RUSTDOCFLAGS="--cap-lints=warn --emit=dep-info,html-static-files,html-non-static-files",
            )
            if config.startswith("D")
            else env
        )
        output = run_command(root, args, run_env)
        messages: list[CargoMessage] = [
            json.loads(line) for line in output.splitlines() if line.strip()
        ]
        messages = [m for m in messages if m.get("package_id") == package_id]
        for artifact, diagnostics in associate(messages, config):
            target = artifact["target"]
            documented = config.startswith("D") and (
                artifact.get("reason") == "compiler-message"
                or any(
                    filename.endswith(".html")
                    for filename in artifact.get("filenames", [])
                )
            )
            mode = (
                "doc"
                if documented
                else "test"
                if artifact["profile"]["test"]
                else "not(test)"
            )
            if mode == "doc":
                # rustdoc's dep-info names its source root, not a rustc artifact.
                docs = list((target_dir / "doc").rglob("*.d"))
                synthetic: CargoMessage = dict(artifact)
                synthetic["filenames"] = [
                    str(p) for p in docs if p.stem == target["name"].replace("-", "_")
                ]
                files = dep_files(root, synthetic)
            else:
                files = dep_files(root, artifact)
            features = tuple(
                sorted(artifact.get("features", FEATURES if mode == "doc" else []))
            )
            units.append(
                Unit(
                    target["name"] + ":" + ",".join(target["kind"]),
                    Build(config, mode, features),
                    files,
                    diagnostics,
                    local_file(root, target["src_path"]) or "",
                )
            )
    return units


def predicate(firing: set[Build], compiled: set[Build]) -> str:
    docs = {build for build in compiled if build.mode == "doc"}
    if firing.intersection(docs) and not docs <= firing:
        raise BaselineError(
            "stable and nightly rustdoc disagree; no cfg can distinguish toolchains"
        )
    if all(build.mode == "doc" for build in firing):
        return "doc"
    normal = {build for build in compiled if build.mode != "doc"}
    if normal and normal <= firing:
        return "always"
    for mode in ("test", "not(test)"):
        if firing == {build for build in normal if build.mode == mode}:
            return mode
    terms = set()
    for build in firing:
        if build.mode == "doc":
            terms.add("doc")
            continue
        flags = [
            f'feature = "{name}"'
            if name in build.features
            else f'not(feature = "{name}")'
            for name in FEATURES
        ]
        terms.add("all(" + ", ".join([*flags, build.mode]) + ")")
    return canonical("any(" + ", ".join(sorted(terms)) + ")")


def placements(root: Path, units: list[Unit]) -> list[Placement]:
    sources = {p.relative_to(root).as_posix(): p.read_bytes() for p in rust_files(root)}
    items = {file: scan_items(data) for file, data in sources.items()}
    seen: dict[tuple[str, str, str], dict[str, set[Build]]] = defaultdict(
        lambda: defaultdict(set)
    )
    owners: dict[tuple[str, str], Item | None] = {}
    inner_sites: set[tuple[str, str]] = set()
    docs = {
        file: [
            (t.start, t.end) for t in tokens(data) if t.text.startswith(("//!", "/*!"))
        ]
        for file, data in sources.items()
    }
    compiled: dict[str, dict[str, set[Build]]] = defaultdict(lambda: defaultdict(set))
    for unit in units:
        for file in unit.files:
            compiled[file][unit.target].add(unit.build)
        for diagnostic in unit.diagnostics:
            code = diagnostic["code"]
            if code is None:
                continue
            span = primary_span(root, diagnostic)
            if span is None:
                continue
            file, offset = span
            if code["code"] == "clippy::mod_module_files":
                module_name = Path(file).parent.name
                declarations = [
                    (candidate, item.start)
                    for candidate in unit.files
                    if candidate in items
                    for item in items[candidate]
                    if item.kind == "mod" and item.name == f"mod {module_name}"
                ]
                if len(declarations) != 1:
                    raise BaselineError(
                        f"{file}: ambiguous module declaration ownership"
                    )
                file, offset = declarations[0]
            crate_only = code["code"] == "dead_code_pub_in_binary"
            if crate_only:
                if not unit.crate_root:
                    raise BaselineError("dead_code_pub_in_binary: missing crate root")
                file, offset = unit.crate_root, 0
            if file not in sources or file not in unit.files:
                raise BaselineError(
                    f"{file}: diagnostic not covered by compiled source dep-info"
                )
            if not 0 <= offset < len(sources[file]):
                raise BaselineError(f"{file}: invalid diagnostic byte offset {offset}")
            item = min(
                (i for i in items[file] if i.start <= offset < i.end),
                key=lambda i: i.end - i.start,
                default=None,
            )
            # rustc points a missing crate doc at byte zero, even when a use
            # starts there. Its semantic owner is the crate, not that first item.
            if (
                (
                    code["code"] == "missing_docs"
                    and diagnostic["message"] == "missing documentation for the crate"
                )
                or code["code"] == "rustdoc::missing_crate_level_docs"
                or crate_only
            ):
                item = None
            if (
                item is not None
                and item.kind == "use"
                and code["code"] in IMPORT_REWRITES
            ):
                print(f"rewrite required: {file}: {item.name}: {code['code']}")
                continue
            name = item.name if item else "<crate root>"
            if (
                item is not None
                and item.kind == "mod"
                and any(start <= offset < end for start, end in docs[file])
            ):
                inner_sites.add((file, name))
            owners[file, name] = item
            seen[file, name, code["code"]][unit.target].add(unit.build)
    result: list[Placement] = []
    for (file, name, lint), targets in sorted(seen.items()):
        available = compiled[file]
        firing = set().union(*targets.values())
        for target, builds in available.items():
            if firing.intersection(builds) != targets.get(target, set()):
                raise BaselineError(
                    f"{file}: {name}: {lint} has crate-dependent firing; split shared helpers ({target})"
                )
        result.append(
            Placement(
                file,
                owners[file, name],
                lint,
                predicate(firing, set().union(*available.values())),
                (file, name) in inner_sites,
            )
        )
    return result


def strip_migrations(data: bytes) -> bytes:
    ranges: set[tuple[int, int]] = set()
    parsed = attributes(data)
    for attr in parsed:
        if not attr.reason.startswith("lint-migration:"):
            continue
        calls = [a for a in parsed if a.start == attr.start]
        if any(not a.reason.startswith("lint-migration:") for a in calls):
            raise BaselineError(
                "migration attribute shares a cfg_attr with another expectation"
            )
        raw = data[attr.start : attr.end]
        ts = tokens(raw)
        if any(
            token.text == "("
            and i > 0
            and ts[i - 1].text not in ("cfg_attr", "expect", "any", "all", "not")
            for i, token in enumerate(ts)
        ):
            raise BaselineError(
                "migration cfg_attr contains unrelated attributes; separate it first"
            )
        start = attr.start
        end = attr.end
        line = data.rfind(b"\n", 0, start) + 1
        newline = data.find(b"\n", end)
        if (
            not data[line:start].strip()
            and newline >= 0
            and not data[end:newline].strip()
        ):
            start, end = line, newline + 1
        ranges.add((start, end))
    result = data
    for start, end in sorted(ranges, reverse=True):
        result = result[:start] + result[end:]
    return result


def emit(data: bytes, planned: list[Placement], reason: str) -> bytes:
    groups: dict[tuple[int, bool, str], set[str]] = defaultdict(set)
    for place in planned:
        inner = place.item is None or place.inner
        if place.item is None:
            position = inner_position(data)
            if place.lint == "missing_docs":
                prefix_tokens = tokens(data[:position])
                for index, token in enumerate(prefix_tokens[:-3]):
                    if [t.text for t in prefix_tokens[index : index + 4]] == [
                        "#",
                        "!",
                        "[",
                        "cfg",
                    ]:
                        position = token.start
                        break
        elif place.inner:
            position = inner_position(data[: place.item.end - 1], place.item.body_start)
        else:
            position = place.item.start
        groups[position, inner, place.predicate].add(place.lint)
        if (
            place.item is not None
            and place.item.kind == "use"
            and place.lint == "clippy::pub_use"
        ):
            groups[position, inner, place.predicate].add("clippy::useless_attribute")
    changes: dict[int, list[bytes]] = defaultdict(list)
    for (position, inner, pred), lints in sorted(
        groups.items(), key=lambda group: (group[0][0], not group[0][1], group[0][2])
    ):
        call = f"expect({', '.join(sorted(lints))}, reason = {json.dumps(reason)})"
        if pred != "always":
            call = f"cfg_attr({pred}, {call})"
        line = data.rfind(b"\n", 0, position) + 1
        indent = data[line:position]
        if indent.strip():
            indent = b""
        prefix = (
            b""
            if position == 0 or data[position - 1 : position] in (b"\n", b" ", b"\t")
            else b"\n"
        )
        changes[position].append(
            prefix
            + ("#![" if inner else "#[").encode()
            + call.encode()
            + b"]\n"
            + indent
        )
    result = data
    for position, chunks in sorted(changes.items(), reverse=True):
        result = result[:position] + b"".join(chunks) + result[position:]
    return result


def source_entries(root: Path, report: bool = False) -> list[Entry]:
    counts: Counter[tuple[str, str, str, str]] = Counter()
    for path in rust_files(root):
        data = path.read_bytes()
        items = scan_items(data)
        file = path.relative_to(root).as_posix()
        for attr in attributes(data):
            if not attr.reason.startswith("lint-migration:"):
                continue
            owner = min(
                (i for i in items if i.start <= attr.start < i.end),
                key=lambda i: i.end - i.start,
                default=None,
            )
            name = owner.name if owner else "<crate root>"
            if attr.inner and report:
                print(
                    f"{file}:{data.count(bytes([10]), 0, attr.start) + 1}: {name}: inner attribute; crate-level or module-doc diagnostic: {', '.join(attr.lints)} [{attr.predicate}]"
                )
            for lint in attr.lints:
                counts[file, name, lint, canonical(attr.predicate)] += 1
        for line in re.finditer(
            rb"(?m)^[ \t]*///[ \t]+#[ \t]+(#!?\[.*\])[ \t]*$", data
        ):
            for attr in attributes(line[1]):
                if attr.reason.startswith("lint-migration:"):
                    owner = min(
                        (i for i in items if i.start <= line.start() < i.end),
                        key=lambda i: i.end - i.start,
                        default=None,
                    )
                    for lint in attr.lints:
                        counts[
                            file,
                            owner.name if owner else "<crate root>",
                            lint,
                            "doctest",
                        ] += 1
    return [Entry(*key, count) for key, count in sorted(counts.items())]


def read_manifest(path: Path) -> list[Entry]:
    if not path.exists():
        return []
    with path.open("rb") as stream:
        document = tomllib.load(stream)
    entries: list[Entry] = []
    for row in document.get("baseline", []):
        if (
            set(row) != {"file", "item", "lint", "predicate", "count"}
            or not isinstance(row["count"], int)
            or row["count"] < 1
        ):
            raise BaselineError(f"{path}: malformed baseline entry")
        if any(
            not isinstance(row[key], str)
            for key in ("file", "item", "lint", "predicate")
        ):
            raise BaselineError(f"{path}: non-string baseline identity")
        entries.append(
            Entry(
                row["file"],
                row["item"],
                row["lint"],
                canonical(row["predicate"]),
                row["count"],
            )
        )
    keys = [(e.file, e.item, e.lint, e.predicate) for e in entries]
    if len(set(keys)) != len(keys):
        raise BaselineError(f"{path}: duplicate baseline identity")
    return sorted(entries)


def manifest_text(entries: list[Entry]) -> str:
    rows = ["# Generated by generate_baseline.py; counts are attribute occurrences.\n"]
    for entry in sorted(entries):
        rows.append(
            "\n[[baseline]]\n"
            + "".join(
                f"{key} = {json.dumps(getattr(entry, key), ensure_ascii=False)}\n"
                for key in ("file", "item", "lint", "predicate")
            )
            + f"count = {entry.count}\n"
        )
    return "".join(rows)


def refresh(root: Path, rebaseline: bool) -> None:
    current = source_entries(root)
    previous = Counter(
        {
            (e.file, e.item, e.lint, e.predicate): e.count
            for e in read_manifest(root / MANIFEST)
        }
    )
    added = additions(
        previous,
        Counter({(e.file, e.item, e.lint, e.predicate): e.count for e in current}),
    )
    if added and not rebaseline:
        raise BaselineError(
            f"manifest would add entries; use --rebaseline only for an authorized toolchain migration: {added}"
        )
    (root / MANIFEST).write_text(manifest_text(current))


def generate(root: Path) -> None:
    originals = {p.relative_to(root): p.read_bytes() for p in rust_files(root)}
    head = subprocess.run(
        [
            *(["flock", "/tmp/rskrb5-git.lock"] if shutil.which("flock") else []),
            "git",
            "rev-parse",
            "--short",
            "HEAD",
        ],
        cwd=root,
        env=dict(os.environ, GIT_MASTER="1"),
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="lint-baseline-") as temporary:
        scratch = Path(temporary) / "source"
        shutil.copytree(
            root,
            scratch,
            ignore=shutil.ignore_patterns(".git", "target", ".omo", "__pycache__"),
        )
        for path, data in originals.items():
            (scratch / path).write_bytes(strip_migrations(data))
        units = collect(
            scratch,
            Path(os.environ.get("CARGO_TARGET_DIR", str(Path(temporary) / "target"))),
        )
        planned = placements(scratch, units)
        for path in originals:
            source = scratch / path
            source.write_bytes(
                emit(
                    source.read_bytes(),
                    [p for p in planned if p.file == path.as_posix()],
                    f"lint-migration: upstream baseline at {head}",
                )
            )
        manifest = manifest_text(source_entries(scratch))
        if any((root / path).read_bytes() != data for path, data in originals.items()):
            raise BaselineError(
                "source changed during collection; no generated files installed"
            )
        for path in originals:
            (root / path).write_bytes((scratch / path).read_bytes())
        (root / MANIFEST).write_text(manifest)
    print(f"Generated {len(planned)} item/lint placements")


def failure_fixture(root: Path) -> None:
    diagnostic: Diagnostic = {
        "code": {"code": "clippy::multiple_crate_versions"},
        "level": "warning",
        "message": "multiple versions for dependency",
        "spans": [],
    }
    primary_span(root, diagnostic)


def self_test() -> None:
    from scanner import self_test as scanner_test

    scanner_test()
    # Given disjoint unit diagnostics, when emitting, then predicates stay item-local.
    with tempfile.TemporaryDirectory(prefix="baseline-self-test-") as temporary:
        root = Path(temporary)
        (root / "src").mkdir()
        (root / MANIFEST).parent.mkdir(parents=True)
        path = root / "src/lib.rs"
        data = b"//! docs\n#![deny(warnings)]\nuse std::time::Duration;\nfn a() {}\nfn b() {}\n"
        path.write_bytes(data)
        a = Build(
            "K2", "not(test)", ("default", "messages", "serde", "spnego", "tokio")
        )
        b = Build("K3", "not(test)", ())
        test_a = Build("K2", "test", a.features)
        test_b = Build("K3", "test", ())
        assert predicate({test_a, test_b}, {a, b, test_a, test_b}) == "test"
        assert predicate({test_a}, {a, b, test_a, test_b}) != "test"

        def diagnostic(name: bytes, lint: str = "dead_code") -> Diagnostic:
            return {
                "code": {"code": lint},
                "level": "warning",
                "message": "fixture",
                "spans": [
                    {
                        "file_name": "src/lib.rs",
                        "byte_start": data.index(name),
                        "byte_end": data.index(name) + len(name),
                        "line_start": 1,
                        "column_start": 1,
                        "is_primary": True,
                        "expansion": None,
                    }
                ],
            }

        units = [
            Unit("lib", a, frozenset({"src/lib.rs"}), (diagnostic(b"fn a"),)),
            Unit("lib", b, frozenset({"src/lib.rs"}), (diagnostic(b"fn b"),)),
        ]
        plan = placements(root, units)
        assert len(plan) == 2 and plan[0].predicate != plan[1].predicate
        generated = emit(data, plan, "lint-migration: test")
        path.write_bytes(generated)
        assert strip_migrations(generated) == data
        assert len(source_entries(root)) == 2
        refresh(root, True)
        old = (root / MANIFEST).read_text()
        refresh(root, False)
        assert (root / MANIFEST).read_text() == old
        assert (
            emit(strip_migrations(generated), plan, "lint-migration: test") == generated
        )
        path.write_bytes(data)
        # Given an unused public item in an out-of-line module, rustc requires
        # the expectation on the target root, only in the firing test unit.
        nested = root / "src/nested.rs"
        nested.write_bytes(b"pub fn unused() {}\n")
        crate_lint = diagnostic(b"fn a", "dead_code_pub_in_binary")
        crate_lint["spans"][0].update(file_name="src/nested.rs", byte_start=0)
        test_build = Build("K2", "test", a.features)
        compiled_files = frozenset({"src/lib.rs", "src/nested.rs"})
        crate_plan = placements(
            root,
            [
                Unit("lib", a, compiled_files, (), "src/lib.rs"),
                Unit("lib", test_build, compiled_files, (crate_lint,), "src/lib.rs"),
            ],
        )
        assert len(crate_plan) == 1
        assert crate_plan[0].file == "src/lib.rs" and crate_plan[0].item is None
        assert (
            "test" in crate_plan[0].predicate
            and "not(test)" not in crate_plan[0].predicate
        )
        crate_source = emit(data, crate_plan, "lint-migration: test")
        assert crate_source.startswith(b"//! docs\n#![deny(warnings)]\n#![cfg_attr(")
        path.write_bytes(crate_source)
        assert source_entries(root, report=True) == [
            Entry(
                "src/lib.rs",
                "<crate root>",
                "dead_code_pub_in_binary",
                crate_plan[0].predicate,
            )
        ]
        assert strip_migrations(crate_source) == data
        path.write_bytes(data)
        nested.unlink()
        data = b"pub mod nested;\n"
        path.write_bytes(data)
        (root / "src/nested").mkdir()
        module_path = root / "src/nested/mod.rs"
        module_path.write_bytes(b"pub fn f() {}\n")
        module_lint = diagnostic(b"mod", "clippy::mod_module_files")
        module_lint["spans"][0].update(file_name="src/nested/mod.rs", byte_start=0)
        module_plan = placements(
            root,
            [
                Unit(
                    "lib",
                    a,
                    frozenset({"src/lib.rs", "src/nested/mod.rs"}),
                    (module_lint,),
                    "src/lib.rs",
                )
            ],
        )
        assert module_plan[0].file == "src/lib.rs"
        assert module_plan[0].item.name == "mod nested"
        assert not emit(data, module_plan, "lint-migration: test").startswith(b"#![")
        module_path.unlink()
        # Given a crate diagnostic sharing byte zero with an import, its owner
        # must remain the crate; import-path diagnostics require source rewrites.
        data = b"use std::time::Duration;\npub struct Borrowed<'a>(&'a str);\n"
        path.write_bytes(data)
        crate_doc = diagnostic(b"use", "missing_docs")
        crate_doc["message"] = "missing documentation for the crate"
        measured = placements(
            root,
            [
                Unit(
                    "lib",
                    a,
                    frozenset({"src/lib.rs"}),
                    (
                        crate_doc,
                        diagnostic(b"std", "clippy::std_instead_of_core"),
                        diagnostic(b"'a", "clippy::single_char_lifetime_names"),
                    ),
                )
            ],
        )
        assert len(measured) == 2
        assert next(p for p in measured if p.lint == "missing_docs").item is None
        # Given rustdoc also points at the first token, its expectation must
        # precede an outer expectation inserted at that same byte offset.
        rustdoc = diagnostic(b"use", "rustdoc::missing_crate_level_docs")
        doc_plan = placements(
            root,
            [
                Unit(
                    "lib",
                    Build("D1", "doc", FEATURES),
                    frozenset({"src/lib.rs"}),
                    (rustdoc,),
                )
            ],
        )
        assert doc_plan[0].item is None
        first_item = scan_items(data)[0]
        combined = emit(
            data,
            [
                *doc_plan,
                Placement("src/lib.rs", first_item, "unused_imports", "always"),
            ],
            "lint-migration: test",
        )
        assert combined.startswith(b"#![cfg_attr(doc,")
        assert strip_migrations(combined) == data
        assert (
            next(
                p for p in measured if p.lint.endswith("single_char_lifetime_names")
            ).item.kind
            == "struct"
        )
        data = b"//! docs\n#![deny(warnings)]\nuse std::time::Duration;\nfn a() {}\nfn b() {}\n"
        path.write_bytes(data)
        merged = emit(
            data,
            [
                Placement("src/lib.rs", scan_items(data)[1], lint, "always")
                for lint in ("dead_code", "clippy::todo")
            ],
            "lint-migration: test",
        )
        assert len(attributes(merged)) == 1 and attributes(merged)[0].lints == (
            "clippy::todo",
            "dead_code",
        )
        inner = emit(
            data,
            [Placement("src/lib.rs", None, "missing_docs", "always")],
            "lint-migration: test",
        )
        assert inner.startswith(b"//! docs\n#![deny(warnings)]\n#![expect(")
        disabled = b'//! docs\n#![deny(warnings)]\n#![cfg(feature = "http")]\n'
        disabled_emitted = emit(
            disabled,
            [Placement("src/lib.rs", None, "missing_docs", "always")],
            "lint-migration: test",
        )
        assert disabled_emitted.index(b"#![expect(") < disabled_emitted.index(
            b"#![cfg("
        )
        assert strip_migrations(disabled_emitted) == disabled
        module = b"mod nested {\n//! module docs\nfn f() {}\n}\n"
        mod_item = scan_items(module)[0]
        emitted_module = emit(
            module,
            [Placement("src/lib.rs", mod_item, "missing_docs", "doc", True)],
            "lint-migration: test",
        )
        assert emitted_module.startswith(b"mod nested {\n//! module docs\n#![cfg_attr(")
        assert strip_migrations(emitted_module) == module
        path.write_bytes(
            b'/// #![not_a_doctest]\n/// # #![expect(dead_code, reason = "lint-migration: doctest")]\npub fn doc() {}\n'
        )
        assert source_entries(root) == [
            Entry("src/lib.rs", "fn doc", "dead_code", "doctest")
        ]
        path.write_bytes(data)
        expanded = diagnostic(b"fn a")
        expanded["spans"][0]["expansion"] = {"span": diagnostic(b"fn b")["spans"][0]}
        assert primary_span(root, expanded) == ("src/lib.rs", data.index(b"fn b"))
        outside = diagnostic(b"fn a")
        outside["spans"][0]["file_name"] = "/outside/dependency.rs"
        assert primary_span(root, outside) is None
        try:
            placements(
                root, [*units, Unit("integration", a, frozenset({"src/lib.rs"}), ())]
            )
        except BaselineError as error:
            assert "crate-dependent" in str(error)
        else:
            raise AssertionError("shared-file mismatch accepted")
        target: Target = {"name": "lib", "kind": ["lib"], "src_path": str(path)}
        messages: list[CargoMessage] = []
        for mode in (False, True):
            messages.extend(
                [
                    {
                        "reason": "compiler-message",
                        "package_id": "fixture",
                        "target": target,
                        "message": diagnostic(b"fn a"),
                    },
                    {
                        "reason": "compiler-artifact",
                        "package_id": "fixture",
                        "target": target,
                        "profile": {"test": mode},
                        "features": [],
                    },
                ]
            )
        for replay in (messages, json.loads(json.dumps(messages))):
            associated = associate(replay, "K1")
            assert [(m["profile"]["test"], len(ds)) for m, ds in associated] == [
                (False, 1),
                (True, 1),
            ]
        path.write_bytes(generated)
        (root / MANIFEST).write_text(manifest_text([]))
        try:
            refresh(root, False)
        except BaselineError:
            assert read_manifest(root / MANIFEST) == []
        else:
            raise AssertionError("manifest addition accepted")
        # Given tree attributes, refresh emits module-wrap keys, not stale keys.
        fixture = (
            '#[expect(dead_code, reason = "lint-migration: fixture")]\nfn f() {}\n'
        )
        for item in (fixture, fixture.replace("fn f() {}", "struct F;")):
            path.write_text(item)
            refresh(root, True)
            previous = read_manifest(root / MANIFEST)
            wrapped = "#[cfg(test)]\nmod tests {\n" + item + "}\n"
            path.write_text(wrapped)
            refresh(root, False)
            expected = [
                Entry(e.file, "mod tests::" + e.item, e.lint, e.predicate, e.count)
                for e in previous
            ]
            assert read_manifest(root / MANIFEST) == expected
            # Given changed metadata or duplicates, refresh rejects without writing.
            for invalid in (
                wrapped.replace("dead_code", "unused"),
                wrapped.replace(
                    "expect(dead_code,", "cfg_attr(test, expect(dead_code,"
                ).replace('fixture")]', 'fixture"))]'),
                wrapped.replace(
                    item,
                    item.replace(
                        "#[expect",
                        '#[expect(dead_code, reason = "lint-migration: extra")]\n#[expect',
                    ),
                ),
                wrapped + item,
                wrapped + wrapped.replace("mod tests", "mod other"),
                wrapped.replace("fn f", "fn g").replace("struct F", "struct G"),
            ):
                (root / MANIFEST).write_text(manifest_text(previous))
                path.write_text(invalid)
                try:
                    refresh(root, False)
                except BaselineError:
                    assert read_manifest(root / MANIFEST) == previous
                else:
                    raise AssertionError("invalid module-wrap move accepted")
            # Given a refreshed removal, restoring even the wrapped item fails.
            path.write_text("")
            refresh(root, False)
            path.write_text(wrapped)
            try:
                refresh(root, False)
            except BaselineError:
                assert read_manifest(root / MANIFEST) == []
            else:
                raise AssertionError("removed entry restored by wrapping")
            refresh(root, True)
            assert read_manifest(root / MANIFEST) == expected
    result = subprocess.run(
        [sys.executable, __file__, "--failure-fixture"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1 and "clippy::multiple_crate_versions" in result.stderr
    print(
        "generator self-test: PASS (locator, units/replays, predicates, merging, shared-file rejection, manifest, idempotence, subprocess failure)"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    for mode in (
        "generate",
        "report-placement",
        "refresh-manifest",
        "self-test",
        "failure-fixture",
    ):
        modes.add_argument("--" + mode, action="store_true")
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument("--rebaseline", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        if args.self_test:
            self_test()
        elif args.failure_fixture:
            failure_fixture(root)
        elif args.refresh_manifest:
            refresh(root, args.rebaseline)
        elif args.report_placement:
            source_entries(root, report=True)
        else:
            if args.rebaseline:
                parser.error("--rebaseline requires --refresh-manifest")
            generate(root)
    except (
        BaselineError,
        ScanError,
        OSError,
        subprocess.CalledProcessError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
    ) as error:
        print(f"baseline: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
