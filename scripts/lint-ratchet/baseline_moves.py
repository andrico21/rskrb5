#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/baseline_moves.py --self-test
"""Identify additions after one-to-one, count-preserving module-wrap moves."""

from __future__ import annotations

import re
from collections import Counter
from itertools import combinations
from typing import Final

Entry = tuple[str, str, str, str]
MODULE_PREFIX: Final = re.compile(r"(?:mod (?:r#)?\w+::)+")


def additions(previous: Counter[Entry], current: Counter[Entry]) -> Counter[Entry]:
    """Consume disappeared keys once; retained keys cannot sponsor a duplicate."""
    added = current - previous
    removed = previous.keys() - current.keys()
    candidates = {
        new: [
            old
            for old in sorted(removed)
            if old[0] == new[0]
            and old[2:] == new[2:]
            and previous[old] == current[new]
            and new not in previous
            and old[1] != "<crate root>"
            and new[1].endswith(old[1])
            and MODULE_PREFIX.fullmatch(new[1][: -len(old[1])])
        ]
        for new in added
    }
    matched: dict[Entry, Entry] = {}

    def match(new: Entry, visited: set[Entry]) -> bool:
        for old in candidates[new]:
            if old in visited:
                continue
            visited.add(old)
            if old not in matched or match(matched[old], visited):
                matched[old] = new
                return True
        return False

    for new in sorted(added):
        if match(new, set()):
            del added[new]
    return added


def self_test() -> None:
    # Given overlapping suffixes, when matching moves, then each old key is used once.
    old = Counter(
        {
            ("f.rs", site, "lint", "test"): 1
            for site in (
                "fn f",
                "mod a::fn f",
            )
        }
    )
    new = Counter(
        {
            ("f.rs", site, "lint", "test"): 1
            for site in (
                "mod b::mod a::fn f",
                "mod z::fn f",
            )
        }
    )
    assert not additions(old, new)
    assert additions(old, new + new)
    # Given arbitrary subsets of keys, accepted transitions never increase bucket totals.
    keys = [
        ("f.rs", site, lint, predicate)
        for site in ("fn f", "mod a::fn f", "mod b::mod a::fn f")
        for lint, predicate in (("lint", "test"), ("other", "always"))
    ]
    fixtures = [
        Counter(dict.fromkeys(subset, 1))
        for size in range(4)
        for subset in combinations(keys, size)
    ]
    for previous in fixtures:
        for current in fixtures:
            if not additions(previous, current):
                before: Counter[tuple[str, str, str]] = Counter()
                after: Counter[tuple[str, str, str]] = Counter()
                for (file, _, lint, predicate), count in previous.items():
                    before[file, lint, predicate] += count
                for (file, _, lint, predicate), count in current.items():
                    after[file, lint, predicate] += count
                assert not after - before
    for site in ("impl W::fn f", "mod a::fn g", "mod a::fn f::fn f"):
        assert additions(
            Counter({("f.rs", "fn f", "lint", "test"): 1}),
            Counter({("f.rs", site, "lint", "test"): 1}),
        )
    print("baseline_moves self-test: ok (one-to-one overlapping module prefixes)")


if __name__ == "__main__":
    self_test()
