#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/baseline_moves.py --self-test
"""Shrink-only credit transfers between proven, one-to-one source sites."""

from __future__ import annotations

import re
from collections import Counter
from typing import Final

Entry = tuple[str, str, str, str]
Site = tuple[str, str]
Move = tuple[Site, Site]
MODULE_PREFIX: Final = re.compile(r"(?:mod (?:r#)?\w+::)+")


def additions(
    previous: Counter[Entry],
    current: Counter[Entry],
    proven: frozenset[Move] = frozenset(),
) -> Counter[Entry]:
    """No source proof means no move; an old site's lints cannot split owners."""
    added = current - previous
    old_sites = {e[:2] for e in previous} - {e[:2] for e in current}
    new_sites = {e[:2] for e in current} - {e[:2] for e in previous}
    candidates: dict[Site, list[Site]] = {}
    for new in sorted(new_sites):
        new_rows = Counter({e[2:]: n for e, n in current.items() if e[:2] == new})
        for old in sorted(old_sites):
            if (old, new) not in proven or old[0] != new[0]:
                continue
            old_rows = Counter({e[2:]: n for e, n in previous.items() if e[:2] == old})
            is_use = old[1].startswith("use ") and new[1].startswith("use ")
            wrapped = (
                old[1] != "<crate root>"
                and not old[1].startswith("mod ")
                and new[1].endswith(old[1])
                and MODULE_PREFIX.fullmatch(new[1][: -len(old[1])])
            )
            if (is_use and old_rows == new_rows) or (
                wrapped and not new_rows - old_rows
            ):
                candidates.setdefault(new, []).append(old)
    consumed: set[Site] = set()
    for new, options in candidates.items():
        # Ambiguous transfers fail closed rather than distributing a site's lints.
        if len(options) == 1 and options[0] not in consumed:
            consumed.add(options[0])
            for entry in list(added):
                if entry[:2] == new:
                    del added[entry]
    return added


def self_test() -> None:
    old_site, new_site = ("f.rs", "fn f"), ("f.rs", "mod tests::fn f")
    old = Counter({(*old_site, "lint", "test"): 2, (*old_site, "other", "test"): 1})
    new = Counter({(*new_site, "lint", "test"): 1})
    proof = frozenset({(old_site, new_site)})
    # Given a proven wrap, when counts/entries shrink, then the move is accepted.
    assert not additions(old, new, proof)
    assert additions(old, new)
    for invalid in (
        Counter({(*new_site, "lint", "test"): 3}),
        Counter({(*new_site, "lint", "always"): 1}),
        old + new,
    ):
        assert additions(old, invalid, proof)
    split = ("f.rs", "mod other::fn f")
    assert additions(
        old, new + Counter({(*split, "other", "test"): 1}), proof | {(old_site, split)}
    )
    assert additions(Counter(), new, proof)
    a, b = ("f.rs", "use std::A"), ("f.rs", "use std::A as _")
    uses = frozenset({(a, b)})
    assert not additions(
        Counter({(*a, "lint", "test"): 1}), Counter({(*b, "lint", "test"): 1}), uses
    )
    assert additions(
        Counter({(*a, "lint", "test"): 2}), Counter({(*b, "lint", "test"): 1}), uses
    )
    print(
        "baseline_moves self-test: ok (proof required, wrap shrink, use re-key, one-to-one)"
    )


if __name__ == "__main__":
    self_test()
