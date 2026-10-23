#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/diagnostics.py --self-test
"""Cargo compiler-unit diagnostic collection for differential lint checks."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
import common

CONFIGS = (
    ("--all-features",),
    (),
    ("--no-default-features",),
    ("--features", "http"),
    ("--features", "tower"),
    ("--features", "evaluation"),
    ("--no-default-features", "--features", "tokio"),
)


@dataclass(frozen=True, slots=True)
class Diagnostic:
    config: str
    mode: str
    file: str
    lint: str
    line: int


def span_location(span: dict, root: Path) -> tuple[str, int] | None:
    chosen = None
    while span:
        path = Path(span["file_name"])
        path = path if path.is_absolute() else root / path
        if not path.exists() and (root / "fuzz" / span["file_name"]).is_file():
            path = root / "fuzz" / span["file_name"]
        try:
            relative = path.resolve().relative_to(root.resolve())
        except ValueError:
            relative = None
        if relative is not None and path.exists():
            chosen = (relative.as_posix(), span["line_start"])
        span = (span.get("expansion") or {}).get("span")
    return chosen


def parse_messages(output: str, root: Path, config: str) -> list[Diagnostic]:
    """Buffer diagnostics until their matching artifact supplies compiler-unit mode."""
    pending: dict[tuple, list[tuple[str, str, int]]] = {}
    found = []
    for line in output.splitlines():
        if not line.startswith("{"):
            continue
        row = json.loads(line)
        target = row.get("target", {})
        key = (row.get("package_id"), target.get("name"), tuple(target.get("kind", [])))
        if row.get("reason") == "compiler-message":
            message = row["message"]
            code = message.get("code")
            if code is None or message.get("level") not in ("warning", "error"):
                continue
            for span in message.get("spans", []):
                if span.get("is_primary") and (location := span_location(span, root)):
                    pending.setdefault(key, []).append(
                        (location[0], code["code"], location[1])
                    )
                    break
        elif row.get("reason") == "compiler-artifact":
            mode = "test" if row["profile"].get("test") else "not(test)"
            found.extend(
                Diagnostic(config, mode, file, lint, number)
                for file, lint, number in pending.pop(key, [])
            )
    if pending:
        if config == "D1":
            found.extend(
                Diagnostic(config, "doc", file, lint, number)
                for values in pending.values()
                for file, lint, number in values
            )
        else:
            raise RuntimeError(
                f"{config}: compiler messages without matching artifact; cannot establish unit mode"
            )
    return found


def run_cargo(root: Path, arguments: list[str]) -> str:
    env = dict(
        os.environ,
        CARGO_BUILD_JOBS="1",
        CARGO_BUILD_WARNINGS="allow",
        CARGO_TARGET_DIR=str(root / "target"),
        RUSTDOCFLAGS="--cap-lints=warn",
    )
    command = ["flock", "/tmp/rskrb5-cargo.lock", "cargo", *arguments]
    result = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True)
    print(f"$ {' '.join(command)} (cwd={root})\n{result.stderr}", file=sys.stderr)
    if result.returncode:
        print(result.stdout, file=sys.stderr)
        raise RuntimeError(
            f"configuration failed to compile: {' '.join(arguments)} (exit {result.returncode})"
        )
    return result.stdout


def collect(root: Path) -> list[Diagnostic]:
    found = []
    for index, flags in enumerate(CONFIGS, 1):
        output = run_cargo(
            root,
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
        found.extend(parse_messages(output, root, f"K{index}"))
    output = run_cargo(
        root, ["doc", "--no-deps", "--all-features", "--message-format=json"]
    )
    found.extend(parse_messages(output, root, "D1"))
    return found


def self_test() -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "lib.rs").write_text("fn f() {}")
        target = {"name": "fixture", "kind": ["lib"]}
        message = {
            "reason": "compiler-message",
            "package_id": "fixture",
            "target": target,
            "message": {
                "code": {"code": "dead_code"},
                "level": "warning",
                "spans": [{"file_name": "lib.rs", "line_start": 1, "is_primary": True}],
            },
        }
        rows = [
            message,
            {
                "reason": "compiler-artifact",
                "package_id": "fixture",
                "target": target,
                "profile": {"test": False},
            },
            message,
            {
                "reason": "compiler-artifact",
                "package_id": "fixture",
                "target": target,
                "profile": {"test": True},
            },
        ]
        output = "\n".join(json.dumps(row) for row in rows)
        assert [d.mode for d in parse_messages(output, root, "K7")] == [
            "not(test)",
            "test",
        ]
        assert parse_messages(output, root, "K7") == parse_messages(output, root, "K7")
    print("diagnostics self-test: ok (compiler-unit modes and cached replay)")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else 2)
