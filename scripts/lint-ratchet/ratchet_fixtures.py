#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/ratchet_fixtures.py --self-test
"""Real Git history fixtures for reverse merges and shallow ratchet boundaries."""

from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
import sys

import common
from baseline_gate import MANIFEST, manifest, ratchet


def commit(root: Path, message: str) -> str:
    """Create an isolated fixture commit without depending on user Git identity."""
    common.git(root, "add", ".")
    common.git(
        root,
        "-c",
        "user.name=Ratchet fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        message,
    )
    return common.git(root, "rev-parse", "HEAD").strip()


def self_test() -> int:
    with TemporaryDirectory(prefix="rskrb5-ratchet-fixtures-") as directory:
        root = Path(directory) / "source"
        root.mkdir()
        common.git(root, "init", "-b", "main")
        path = root / MANIFEST
        path.parent.mkdir(parents=True)
        path.write_text("")
        before = commit(root, "before anchor")
        (path.parent / "clean-paths.txt").write_text("")
        (path.parent / "facade-exceptions.txt").write_text("")
        anchor = commit(root, "anchor")
        assert ratchet(root, Counter(), anchor)[0] == []
        # Given an empty manifest, deleting the exhausted facade list is valid;
        # restoring an exception later must still be rejected by history.
        facade = path.parent / "facade-exceptions.txt"
        facade.unlink()
        commit(root, "remove exhausted facade list")
        assert ratchet(root, Counter(), anchor)[0] == []
        facade.write_text("crate::a\tpubusecrate::Thing;\n")
        commit(root, "restore facade exception")
        assert ratchet(root, Counter(), anchor)[0]
        common.git(root, "checkout", "-b", "clean", anchor)
        common.git(root, "branch", "-f", "main", anchor)
        common.git(root, "checkout", "main")
        row = '[[baseline]]\nfile = "src/a.rs"\nitem = "fn f"\nlint = "dead_code"\npredicate = "always"\ncount = 1\n'

        # Given a pre-anchor branch, when main is its second parent (S9),
        # then the trusted anchor cannot be replaced by the reverse merge.
        common.git(root, "checkout", "-b", "old", before)
        path.write_text(row)
        commit(root, "add entry before anchor")
        common.git(
            root,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=f@example.invalid",
            "merge",
            "--no-ff",
            "main",
            "-m",
            "reverse merge",
        )
        common.git(root, "merge-base", "--is-ancestor", anchor, "HEAD")
        assert ratchet(root, manifest(row), anchor)[0]

        # Given a branch from the anchor, when it adds an entry and merges
        # newer main as second parent (S10), then the addition still fails.
        common.git(root, "checkout", "main")
        common.git(root, "checkout", "-b", "side", anchor)
        path.write_text(row)
        commit(root, "add entry after anchor")
        common.git(root, "checkout", "main")
        (root / "unrelated").write_text("main advances\n")
        commit(root, "advance main")
        common.git(root, "checkout", "side")
        common.git(
            root,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=f@example.invalid",
            "merge",
            "--no-ff",
            "main",
            "-m",
            "reverse merge control",
        )
        assert ratchet(root, manifest(row), anchor)[0]

        # Given shallow clones with/without the anchor, when checked,
        # then both fail closed, even without any baseline addition.
        for depth in (1, 2):
            shallow = Path(directory) / f"shallow-{depth}"
            common.git(
                root,
                "clone",
                "--depth",
                str(depth),
                "--branch",
                "main",
                root.as_uri(),
                str(shallow),
            )
            assert (
                common.git(shallow, "rev-parse", "--is-shallow-repository").strip()
                == "true"
            )
            assert ratchet(shallow, Counter(), anchor)[0]

        # Given an unrelated history, when the anchor is absent, fail closed.
        common.git(root, "checkout", before)
        assert ratchet(root, Counter(), anchor)[0]
    print("ratchet_fixtures self-test: ok (S9, S10, shallow boundaries, absent anchor)")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else 2)
