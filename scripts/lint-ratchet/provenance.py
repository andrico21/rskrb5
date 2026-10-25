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
from typing import Final

import common

# Adding credit requires an explicit reviewed edit, never a commit-subject match.
REVIEWED_REWRITES: Final = frozenset(
    {
        "57127243c69550681e7a18e3ac698639f8733286",
        "52b8cdcfb0c5c28a295f801683cb84176b8c7c0b",
        "1cf7b68109964fe2776072e1d51038a6794ab674",
        "4d3d3a2afcb41ac189b2bf885f41c893f700f9bf",
        "20f6404fcd80e24b0ecb4db66f09a2c88e4a43cb",
        "2091037cfb46e0eadde3261a482e945b329cf9e3",
        "0a22457f7456bb189cd0047c649fc210b03a7f5f",
        "7d8926e3d1cbfff5fc08debd6bbcfb73adc6130e",
        "cd371cc36923a572c3e798a51053c4504faf1045",
        # The crate rename: three statements rustfmt rewrapped for `rskrb5_ng`.
        "c54d3cd4b649242117a83cf1fe3480d9a1526d37",
    }
)
RUST_KEYWORDS: Final = frozenset(
    """
    as async await break const continue crate dyn else enum extern false fn for
    if impl in let loop match mod move mut pub ref return self Self static struct
    super trait true type unsafe use where while abstract become box do final gen
    macro override priv typeof unsized virtual yield try union safe raw
    std core alloc
""".split()
)
# The crate rename (`rskrb5` -> `rskrb5_ng`) is not a fork edit. Upstream
# 6f4abc9 never contains `rskrb5_ng`, so undoing it is one-sided.
CRATE_RENAME: Final = re.compile(r"\brskrb5_ng\b")


@dataclass(frozen=True, slots=True)
class Revision:
    before: str
    after: str


def rewrite_mapping(revision: Revision) -> dict[int, int]:
    """Match tokens only inside an authorized diff; insertions get no credit."""
    before, after = revision.before.splitlines(), revision.after.splitlines()
    old_code = common.strip_comments_and_strings(revision.before).splitlines()
    new_code = common.strip_comments_and_strings(revision.after).splitlines()
    result = common.line_mapping(revision.after, revision.before)
    diff = difflib.SequenceMatcher(None, before, after, autojunk=False)
    for tag, a, b, c, d in diff.get_opcodes():
        if tag != "replace":
            continue
        old = [
            (i + 1, token)
            for i in range(a, b)
            for token in re.findall(r"[A-Za-z_]\w*", old_code[i])
            if len(token) >= 3 and token not in RUST_KEYWORDS
        ]
        new = [
            (i + 1, token)
            for i in range(c, d)
            for token in re.findall(r"[A-Za-z_]\w*", new_code[i])
            if len(token) >= 3 and token not in RUST_KEYWORDS
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
    history = common.git(
        root, "log", "--reverse", "--format=%H", "6f4abc9..HEAD", "--", file
    )
    result = []
    for commit in history.splitlines():
        if commit in REVIEWED_REWRITES:
            result.append(
                Revision(
                    common.git(root, "show", f"{commit}^:{file}"),
                    common.git(root, "show", f"{commit}:{file}"),
                )
            )
    return result


def mapping(root: Path, file: str, texts: tuple[str, str]) -> dict[int, int]:
    aliases = {
        Path(new).stem: "common"
        for new, old in common.moved_sources(root).items()
        if old == "tests/common/mod.rs"
    }
    history = revisions(root, file)

    def normalize(text: str) -> str:
        text = crate_renamed(text)
        return renamed_paths(text, aliases) if file.startswith("tests/") else text

    return chain(
        *(normalize(text) for text in texts),
        [Revision(normalize(r.before), normalize(r.after)) for r in history],
    )


def crate_renamed(text: str) -> str:
    """Undo the crate rename everywhere: code, comments and strings."""
    return CRATE_RENAME.sub("rskrb5", text)


def renamed_paths(source: str, aliases: dict[str, str]) -> str:
    """Normalize moved helper paths in code only; literals remain significant."""
    result = source
    clean = common.strip_comments_and_strings(source)
    for match in reversed(list(re.finditer(r"\b(\w+)(?=\s*::)", clean))):
        if match[1] in aliases:
            result = result[: match.start()] + aliases[match[1]] + result[match.end() :]
    return result


def self_test() -> None:
    from provenance_fixtures import check_rewrites

    check_rewrites()
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
    # Given the recorded helper moves, when only a call path changes,
    # then it inherits; a changed argument or string does not.
    aliases = {"pac_ad_win2k": "common", "pac_trust": "common"}
    original = 'Keytab::parse(common::DATA).expect("common::fixture");\n'
    for module in aliases:
        moved = original.replace("common::DATA", module + "::DATA")
        assert common.line_mapping(renamed_paths(moved, aliases), original) == {1: 1}
        assert not common.line_mapping(
            renamed_paths(moved.replace("DATA", "OTHER"), aliases), original
        )
        assert not common.line_mapping(
            renamed_paths(
                moved.replace("common::fixture", module + "::fixture"), aliases
            ),
            original,
        )
    # Given the crate rename, when a line differs from upstream only by
    # `rskrb5::` -> `rskrb5_ng::`, then it maps; any other change does not.
    upstream = 'use rskrb5::Config;\nlet cfg = rskrb5::Config::load()?; // rskrb5::x\n'
    renamed = upstream.replace("rskrb5::", "rskrb5_ng::")
    assert not common.line_mapping(renamed, upstream)
    assert common.line_mapping(crate_renamed(renamed), crate_renamed(upstream)) == {
        1: 1,
        2: 2,
    }
    assert chain(crate_renamed(renamed), crate_renamed(upstream), []) == {1: 1, 2: 2}
    for edited in (
        renamed.replace("load()", "load_default()"),
        renamed.replace("rskrb5_ng::Config::", "rskrb5_ng::Settings::"),
        renamed.replace("// rskrb5_ng::x", "// rskrb5_ng::y"),
    ):
        assert chain(crate_renamed(edited), crate_renamed(upstream), []) == {1: 1}
    assert crate_renamed("rskrb5_ngx rskrb5-ng rskrb5_ng") == "rskrb5_ngx rskrb5-ng rskrb5"
    # Given a statement rustfmt rewrapped only because of the longer name,
    # when the rename commit is a reviewed rewrite, every wrapped line inherits.
    upstream = "    let part = rskrb5::kadmin::decrypt_part(&parsed.krb_priv, &reply_key)\n        .expect(\"decrypts\");\n"
    rewrapped = "    let part =\n        rskrb5_ng::kadmin::decrypt_part(&parsed.krb_priv, &reply_key)\n            .expect(\"decrypts\");\n"
    assert 2 not in chain(crate_renamed(rewrapped), crate_renamed(upstream), [])
    renamed_revision = Revision(crate_renamed(upstream), crate_renamed(rewrapped))
    assert chain(crate_renamed(rewrapped), upstream, [renamed_revision]) == {
        1: 1,
        2: 1,
        3: 2,
    }
    print(
        "provenance self-test: ok (chained rewrites, fork edits, fork-only origins, crate rename)"
    )


if __name__ == "__main__":
    self_test()
