#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/baseline_sources.py --self-test
"""Removal-only baseline transitions; moved identities receive no credits."""

from collections import Counter
import sys


def additions(previous: Counter, current: Counter) -> Counter:
    return current - previous


def self_test() -> int:
    old = Counter({("src/a.rs", "fn f", "dead_code", "always"): 1})
    assert not additions(old, Counter())
    assert not additions(old, old)
    assert additions(Counter(), old)
    assert additions(
        old, Counter({("src/a.rs", "mod tests::fn f", "dead_code", "always"): 1})
    )
    print("baseline_sources self-test: ok (removals only)")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv else 2)
