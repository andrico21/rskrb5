#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/provenance.py --self-test
"""Trace authorized rewrites through their actual parent, never a global waiver."""

from __future__ import annotations

import difflib
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import common


@dataclass(frozen=True, slots=True)
class Revision:
    before: str
    after: str


def rewrite_mapping(revision: Revision) -> dict[int, int]:
    """Match tokens only inside an authorized diff; insertions get no credit."""
    before, after = revision.before.splitlines(), revision.after.splitlines()
    result = common.line_mapping(revision.after, revision.before)
    diff = difflib.SequenceMatcher(None, before, after, autojunk=False)
    for tag, a, b, c, d in diff.get_opcodes():
        if tag != "replace":
            continue
        old = [
            (i + 1, token)
            for i in range(a, b)
            for token in re.findall(r"[A-Za-z_]\w*", before[i])
            if token not in {"std", "core", "alloc"}
        ]
        new = [
            (i + 1, token)
            for i in range(c, d)
            for token in re.findall(r"[A-Za-z_]\w*", after[i])
            if token not in {"std", "core", "alloc"}
        ]
        tokens = difflib.SequenceMatcher(
            None, [t for _, t in old], [t for _, t in new], autojunk=False
        )
        votes: dict[int, Counter[int]] = {}
        for i, j, size in tokens.get_matching_blocks():
            for offset in range(size):
                votes.setdefault(new[j + offset][0], Counter())[old[i + offset][0]] += 1
        for line, choices in votes.items():
            result[line] = choices.most_common(1)[0][0]
    return result


def chain(head: str, reference: str, revisions: list[Revision]) -> dict[int, int]:
    """Only pre-existing upstream credit can cross an authorized replacement."""
    previous = reference
    inherited = {i: i for i in range(1, len(reference.splitlines()) + 1)}
    for revision in revisions:
        before = common.line_mapping(revision.before, reference)
        before.update(
            {
                line: inherited[old]
                for line, old in common.line_mapping(revision.before, previous).items()
                if old in inherited
            }
        )
        inherited = {
            line: before[old]
            for line, old in rewrite_mapping(revision).items()
            if old in before
        }
        previous = revision.after
    result = common.line_mapping(head, reference)
    result.update(
        {
            line: inherited[old]
            for line, old in common.line_mapping(head, previous).items()
            if old in inherited
        }
    )
    return result


def revisions(root: Path, file: str) -> list[Revision]:
    # h/j/k are all the eight `lint: rewrite` commits. No n commit exists yet;
    # todo-20's uncommitted WIP is NOT implicitly authorized by a subject match.
    # `lint: bring fork-authored` is deliberately not an exemption.
    history = common.git(
        root, "log", "--reverse", "--format=%H %s", "6f4abc9..HEAD", "--", file
    )
    result = []
    for row in history.splitlines():
        commit, subject = row.split(" ", 1)
        if subject.startswith("lint: rewrite "):
            result.append(
                Revision(
                    common.git(root, "show", f"{commit}^:{file}"),
                    common.git(root, "show", f"{commit}:{file}"),
                )
            )
    return result


def mapping(root: Path, file: str, texts: tuple[str, str]) -> dict[int, int]:
    return chain(*texts, revisions(root, file))


def self_test() -> None:
    # Given two approved rewrites separated by a real fork addition,
    # when tracing through parents, only inherited lines retain credit.
    upstream = "pub struct Old<'a> {\n value: &'a str,\n}\n"
    first = upstream.replace("'a", "'buffer")
    mixed = first + "fn fork() { values[index]; }\n"
    last = mixed.replace("str", "core::primitive::str")
    steps = [Revision(upstream, first), Revision(mixed, last)]
    assert chain(last, upstream, steps) == {1: 1, 2: 2, 3: 3}
    edited = last.replace("value:", "changed:")
    assert 2 not in chain(edited, upstream, steps)
    assert 4 not in chain(last, upstream, steps)
    assert 2 not in common.line_mapping(last, upstream)
    print("provenance self-test: ok (chained rewrites, fork edits, fork-only origins)")


if __name__ == "__main__":
    self_test()
