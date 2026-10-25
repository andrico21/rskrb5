#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/closure_report.py --report
"""Report unsuppressed lints and unconditional hard errors in every closure."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

import common
import feature_closures
import path_scope
from diagnostics import span_location


@dataclass(frozen=True, slots=True, order=True)
class Finding:
    hard: bool
    file: str
    line: int
    code: str
    message: str


def normalize(root: Path) -> None:
    """Blank migration expectations while preserving all source line numbers."""
    for path in common.iter_rust_files(root):
        source = path.read_text()
        ranges = [
            (a + source[a:b].index("///") + 3, b)
            if source[a:b].lstrip().startswith("///")
            else (a, b)
            for a, b in common.migration_ranges(source)
        ]
        path.write_text(common.blank_ranges(source, ranges))


def classify(output: str, root: Path, exit_code: int) -> list[Finding]:
    """Keep hard failures even without a local span or compiler artifact."""
    findings = []
    for line in output.splitlines():
        if not line.startswith("{"):
            continue
        row = json.loads(line)
        if row.get("reason") != "compiler-message":
            continue
        message = row["message"]
        level = message.get("level")
        if level not in ("warning", "error"):
            continue
        code = (message.get("code") or {}).get("code", "")
        lint = bool(re.fullmatch(r"(?:[a-z][a-z0-9_]*::)?[a-z][a-z0-9_]*", code))
        hard = level == "error" and not lint
        location = next(
            (
                located
                for span in message.get("spans", [])
                if span.get("is_primary") and (located := span_location(span, root))
            ),
            None,
        )
        if hard or (lint and location is not None):
            file, number = location or ("<compiler>", 0)
            findings.append(
                Finding(hard, file, number, code or "<no code>", message["message"])
            )
    if exit_code and not any(finding.hard for finding in findings):
        findings.append(
            Finding(
                True,
                "<cargo>",
                0,
                "<exit>",
                f"cargo failed without hard compiler diagnostic: exit {exit_code}",
            )
        )
    return sorted(set(findings))


def scoped(
    findings: list[Finding], scope: list[str] | None, ignored: set[str]
) -> list[Finding]:
    return [
        finding
        for finding in findings
        if finding.hard
        or (path_scope.selected(finding.file, scope) and finding.code not in ignored)
    ]


def report(root: Path, scope: list[str] | None, ignored: set[str]) -> tuple[int, int]:
    hard_total = lint_total = 0
    with TemporaryDirectory(prefix="rskrb5-closures-") as directory:
        scratch = Path(directory) / "source"
        shutil.copytree(
            root,
            scratch,
            ignore=shutil.ignore_patterns(".git", "target", ".omo", "__pycache__"),
        )
        normalize(scratch)
        env = dict(os.environ, CARGO_BUILD_WARNINGS="allow", CARGO_BUILD_JOBS="1")
        env.setdefault("CARGO_TARGET_DIR", str(Path(directory) / "target"))
        for closure in feature_closures.load(root):
            command = [
                "flock",
                "/tmp/rskrb5-cargo.lock",
                "cargo",
                "clippy",
                "--all-targets",
                *closure.arguments,
                "--message-format=json",
                "--",
                "--cap-lints",
                "warn",
            ]
            print(
                f"$ {shlex.join(command)} [{closure.label}] (cwd={scratch})", flush=True
            )
            try:
                result = subprocess.run(
                    command,
                    cwd=scratch,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=2700,
                )
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b"", error.stderr or b""
                result = subprocess.CompletedProcess(
                    command,
                    124,
                    stdout.decode() if isinstance(stdout, bytes) else stdout,
                    stderr.decode() if isinstance(stderr, bytes) else stderr,
                )
            print(result.stderr, end="", file=sys.stderr)
            print(result.stdout, end="")
            findings = scoped(
                classify(result.stdout, scratch, result.returncode), scope, ignored
            )
            for finding in findings:
                print(
                    f"{finding.file}:{finding.line}: {'HARD' if finding.hard else 'LINT'} {finding.code}: {finding.message} [{closure.label}]"
                )
            hard = sum(finding.hard for finding in findings)
            lints = len(findings) - hard
            hard_total += hard
            lint_total += lints
            print(
                f"closure {closure.label}: {hard} hard errors, {lints} lints; cargo exit {result.returncode}",
                flush=True,
            )
            target = Path(env["CARGO_TARGET_DIR"])
            size = sum(
                path.stat().st_size for path in target.rglob("*") if path.is_file()
            )
            if size > 8 * 1024**3:
                print(f"removing target cache ({size} bytes > 8 GiB)", flush=True)
                shutil.rmtree(target)
    print(f"closure_report: {hard_total} hard errors, {lint_total} lint diagnostics")
    return hard_total, lint_total


def self_test() -> int:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / "src/lib.rs"
        path.parent.mkdir()
        source = '#[expect(dead_code, reason = "lint-migration: test")]\nfn f() {}\n'
        path.write_text(source)
        normalize(root)
        assert path.read_text().count("\n") == source.count("\n")
        assert "expect" not in path.read_text()
        span = {"file_name": "src/lib.rs", "line_start": 2, "is_primary": True}

        def message(code: str | None, level: str) -> str:
            return json.dumps(
                {
                    "reason": "compiler-message",
                    "message": {
                        "level": level,
                        "code": {"code": code} if code else None,
                        "message": "fixture",
                        "spans": [span],
                    },
                }
            )

        hard = classify(message("E0432", "error"), root, 1)
        assert hard and all(finding.hard for finding in hard)
        assert classify(message(None, "error"), root, 1)[0].hard
        assert classify("", root, 101)[0].hard
        lint = classify(message("unused_results", "warning"), root, 0)
        assert len(lint) == 1 and not lint[0].hard
        assert scoped(lint, None, set()) == lint
        assert not scoped(lint, [], set())
        assert not scoped(lint, None, {"unused_results"})
        assert scoped(hard, [], {"E0432"}) == hard
        expansion = {
            "file_name": "/outside/macro.rs",
            "line_start": 1,
            "expansion": {"span": span},
        }
        assert span_location(expansion, root) == ("src/lib.rs", 2)
    print(
        "closure_report self-test: ok (hard errors, scope, normalization, expansions)"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=common.ROOT)
    parser.add_argument("--paths", nargs="+")
    parser.add_argument("--paths-file", type=Path)
    parser.add_argument("--ignore-lints", default="")
    parser.add_argument(
        "--lints-only",
        action="store_true",
        help="scope lint diagnostics only; hard errors always count",
    )
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    try:
        hard, lints = report(
            args.root,
            path_scope.patterns(args.paths, args.paths_file),
            set(filter(None, args.ignore_lints.split(","))),
        )
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"closure_report: {error}", file=sys.stderr)
        return 1
    return int(args.enforce and bool(hard or lints))


if __name__ == "__main__":
    sys.exit(main())
