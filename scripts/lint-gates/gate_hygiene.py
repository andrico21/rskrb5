#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-gates/gate_hygiene.py --enforce
"""Flag dead work in the gate scripts themselves.

Two static checks over every `scripts/lint-gates/*.py`:

* an `argparse` option or positional whose value the script never reads
  (`args.<dest>`): a flag that is accepted but changes nothing;
* a module-level function that nothing in the directory references outside a
  `self_test`: a helper whose result no gate uses.

`main` and `self_test` are entry points and are exempt.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

GATES: Final = Path(__file__).resolve().parent
ENTRY_POINTS: Final = frozenset({"main", "self_test"})


def unread_options(tree: ast.Module) -> list[str]:
    read = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
    }
    found = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            continue
        flag = str(node.args[0].value)
        dest = next(
            (
                str(k.value.value)
                for k in node.keywords
                if k.arg == "dest" and isinstance(k.value, ast.Constant)
            ),
            flag.lstrip("-").replace("-", "_"),
        )
        if dest not in read:
            found.append(
                f"line {node.lineno}: option {flag} is never read (args.{dest})"
            )
    return found


def unused_functions(trees: dict[str, ast.Module]) -> list[str]:
    used: set[str] = set()
    for tree in trees.values():
        production = [
            node
            for node in tree.body
            if not (isinstance(node, ast.FunctionDef) and node.name == "self_test")
        ]
        for node in (inner for top in production for inner in ast.walk(top)):
            if isinstance(node, ast.Name):
                used.add(node.id)
            elif isinstance(node, ast.Attribute):
                used.add(node.attr)
            elif isinstance(node, ast.ImportFrom):
                used.update(alias.name for alias in node.names)
    return [
        f"{name}:{node.lineno}: function {node.name} is never used"
        for name, tree in sorted(trees.items())
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name not in ENTRY_POINTS
        and node.name not in used
    ]


def check(directory: Path) -> list[str]:
    trees = {
        path.name: ast.parse(path.read_text(encoding="utf-8"), path.name)
        for path in sorted(directory.glob("*.py"))
    }
    problems = [
        f"{name}: {problem}"
        for name, tree in trees.items()
        for problem in unread_options(tree)
    ]
    return problems + unused_functions(trees)


def self_test() -> int:
    clean = (
        "import argparse\n"
        "def helper():\n    return 1\n"
        "def main():\n    p = argparse.ArgumentParser()\n"
        '    p.add_argument("--enforce", action="store_true")\n'
        '    p.add_argument("--out-dir", dest="target")\n'
        '    p.add_argument("workflow")\n'
        "    args = p.parse_args()\n"
        "    return helper() if args.enforce and args.target else args.workflow\n"
    )
    with TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "gate.py").write_text(clean)
        assert check(root) == [], check(root)
        (root / "gate.py").write_text(
            clean.replace(
                '    p.add_argument("workflow")\n',
                '    p.add_argument("--report", action="store_true")\n    p.add_argument("workflow")\n',
            )
        )
        assert [p for p in check(root) if "--report" in p], check(root)
        (root / "gate.py").write_text(clean + "def selected(path):\n    return True\n")
        assert [p for p in check(root) if "selected" in p], check(root)
        (root / "gate.py").write_text(
            clean + "def selected(path):\n    return True\ndef self_test():\n    return selected('x')\n"
        )
        assert [p for p in check(root) if "selected" in p], check(root)
        (root / "other.py").write_text("from gate import selected\nselected('x')\n")
        assert check(root) == [], check(root)
    print("gate_hygiene self-test: ok (unread option, unused helper, cross-module use)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--root", type=Path, default=GATES)
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    problems = check(args.root)
    print(
        "\n".join(
            problems + [f"gate_hygiene: {len(problems)} dead option(s) or helper(s)"]
        )
    )
    return int(args.enforce and bool(problems))


if __name__ == "__main__":
    sys.exit(main())
