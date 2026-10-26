#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/baseline_gate.py --self-test
# noqa: SIZE_OK - Gate CLI retains its inline ownership and transition regression fixtures.
"""Check suppression ownership, manifest equality, and every ratchet transition."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

import common
from baseline_sources import additions

MANIFEST: Final = "scripts/lint-ratchet/baseline.toml"
# Reviewed integration commit introducing clean-paths.txt; never rediscover from HEAD.
RATCHET_ANCHOR: Final = "1b54b82020611d79b79cdc1800b486346005b086"
API_LINTS: Final = frozenset(
    "exhaustive_structs exhaustive_enums pub_use module_name_repetitions partial_pub_fields error_impl_error impl_trait_in_params too_many_arguments struct_excessive_bools fn_params_excessive_bools same_name_method".split()
)
TEST_DOCS: Final = frozenset(
    ("missing_errors_doc", "missing_panics_doc", "too_long_first_doc_paragraph")
)
Entry = tuple[str, str, str, str]
PENDING_SUBKEY_REASON: Final = (
    "deliberate: client::build_tgs_req_for_realm_with_confounder_and_subkey"
    " - public API from fork commit 782dcb8, upstream PR pending"
)


def manifest(text: str) -> Counter[Entry]:
    entries: Counter[Entry] = Counter()
    for row in tomllib.loads(text).get("baseline", []):
        count = row["count"]
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise RuntimeError("baseline count must be a positive integer")
        entries[
            (
                row["file"],
                row.get("item", row.get("site", "")),
                row["lint"],
                canonical(row["predicate"]),
            )
        ] += count
    return entries


def canonical(predicate: str) -> str:
    return re.sub(r"\s+", "", predicate)


def sanctioned(
    call: common.AttributeCall, item: common.Item | None, source: str, file: str
) -> bool:
    lints = {lint.removeprefix("clippy::") for lint in call.lints}
    if call.reason == PENDING_SUBKEY_REASON:
        return (
            file == "src/client.rs"
            and call.lints == ("clippy::too_many_arguments",)
            and call.predicate == "always"
            and item is not None
            and item.identity == "fn build_tgs_req_for_realm_with_confounder_and_subkey"
            and bool(re.search(r"\bpub\s+fn\b", source[item.start : item.end]))
        )
    if call.reason == "public facade":
        return (
            call.lints == ("clippy::pub_use",)
            and source[call.start : call.start + 3] == "#!["
            and file == "src/lib.rs"
            and item is None
        )
    if call.reason == "public API: unused inside the unit-test harness":
        return (
            file == "src/lib.rs"
            and item is None
            and call.lints == ("dead_code_pub_in_binary",)
            and canonical(call.predicate) == "test"
            and source[call.start : call.start + 3] == "#!["
        )
    if re.fullmatch(r"deliberate: \w+(?:::\w+)+ - .+", call.reason):
        if call.lints == ("clippy::missing_const_for_fn",):
            return item is not None and item.kind == "fn" and call.predicate == "always"
        if call.lints == ("clippy::unused_async_trait_impl",):
            return (
                item is not None
                and item.kind in ("fn", "impl")
                and " mandates async" in call.reason
                and call.predicate == "always"
            )
    if re.fullmatch(
        r"deliberate: \w+(?:::\w+)+ - mirrors upstream PR #[1-9]\d*", call.reason
    ):
        return (
            bool(lints)
            and lints <= API_LINTS
            and item is not None
            and bool(re.search(r"\bpub\s+(?!\()", source[item.start : item.keyword]))
        )
    if item is None:
        return False
    if call.reason == "secret material must not be implicitly copied":
        return lints == {"missing_copy_implementations"} and item.kind in (
            "struct",
            "enum",
            "union",
        )
    is_test_module = item.kind == "mod" and common.in_ranges(
        common.line_of(source, item.keyword),
        common.cfg_test_line_ranges(common.strip_comments_and_strings(source)),
    )
    if call.reason == "test code is not rendered API documentation":
        return bool(lints) and lints <= TEST_DOCS and is_test_module
    return (
        call.reason == "a test fails by panicking"
        and lints == {"panic_in_result_fn"}
        and is_test_module
    )


def source_entries(root: Path) -> tuple[Counter[Entry], list[str]]:
    entries: Counter[Entry] = Counter()
    errors = []
    for path in common.iter_rust_files(root):
        source, _ = common.read_source(path)
        items = common.scan_items(source)
        rel = path.relative_to(root).as_posix()
        for call in common.attribute_calls(source):
            if call.form != "expect":
                continue
            item = common.owner(items, call.start)
            if call.reason.startswith("lint-migration:"):
                site = item.identity if item is not None else "<crate root>"
                for lint in call.lints:
                    entries[(rel, site, lint, canonical(call.predicate))] += 1
            elif not sanctioned(call, item, source, rel):
                errors.append(
                    f"{rel}:{common.line_of(source, call.start)}: invalid expect reason/item: {call.reason!r}"
                )
        for match in re.finditer(
            r"(?m)^\s*///\s*#\s*(#!?\[.*lint-migration:.*)$", source
        ):
            item = common.owner(items, match.start())
            for call in common.attribute_calls(match[1]):
                for lint in call.lints:
                    entries[
                        (
                            rel,
                            item.identity if item else "<crate root>",
                            lint,
                            "doctest",
                        )
                    ] += 1
    return entries, errors


def transition(
    previous: Counter[Entry],
    current: Counter[Entry],
    label: str,
) -> list[str]:
    return [
        f"{label}: baseline addition/restoration {key} (+{count})"
        for key, count in additions(previous, current).items()
    ]


def ratchet(
    root: Path, current: Counter[Entry], anchor: str = RATCHET_ANCHOR
) -> tuple[list[str], int]:
    clean = "scripts/lint-ratchet/clean-paths.txt"
    facade = "scripts/lint-ratchet/facade-exceptions.txt"
    if common.git(root, "rev-parse", "--is-shallow-repository").strip() != "false":
        return [
            "shallow repository: ratchet requires complete history (CI fetch-depth: 0)"
        ], 0
    if (
        anchor
        not in common.git(root, "rev-list", "--first-parent", "HEAD").splitlines()
    ):
        return [
            f"pinned ratchet anchor {anchor} is not a first-parent ancestor of HEAD"
        ], 0
    base = anchor
    previous = manifest(common.git(root, "show", f"{base}:{MANIFEST}"))
    previous_clean = ratchet_lines(common.git(root, "show", f"{base}:{clean}"))
    previous_facade = ratchet_lines(common.git(root, "show", f"{base}:{facade}"))
    base_count = previous.total()
    errors = []
    for commit in common.git(
        root,
        "log",
        "--first-parent",
        "--reverse",
        "--format=%H",
        f"{base}..HEAD",
        "--",
        MANIFEST,
        clean,
        facade,
    ).splitlines():
        now = manifest(common.git(root, "show", f"{commit}:{MANIFEST}"))
        errors.extend(transition(previous, now, commit))
        now_clean = ratchet_lines(common.git(root, "show", f"{commit}:{clean}"))
        now_facade = ratchet_lines(historical_optional(root, commit, facade))
        errors.extend(list_transition(previous_clean, now_clean, commit, grow=True))
        errors.extend(list_transition(previous_facade, now_facade, commit, grow=False))
        previous_clean, previous_facade = now_clean, now_facade
        previous = now
    errors.extend(transition(previous, current, "working tree"))
    errors.extend(
        list_transition(
            previous_clean,
            ratchet_lines((root / clean).read_text()),
            "working tree",
            grow=True,
        )
    )
    errors.extend(
        list_transition(
            previous_facade,
            ratchet_lines(
                (root / facade).read_text() if (root / facade).exists() else ""
            ),
            "working tree",
            grow=False,
        )
    )
    return errors, base_count


def historical_optional(root: Path, commit: str, file: str) -> str:
    """Treat a removed facade list as empty, without hiding Git failures."""
    present = common.git(root, "ls-tree", "--name-only", commit, "--", file).strip()
    return common.git(root, "show", f"{commit}:{file}") if present else ""


def ratchet_lines(text: str) -> list[str]:
    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if lines != sorted(set(lines)):
        raise RuntimeError("ratchet lists must be sorted and unique")
    return lines


def list_transition(
    previous: list[str], current: list[str], label: str, *, grow: bool
) -> list[str]:
    forbidden = set(previous) - set(current) if grow else set(current) - set(previous)
    return [
        f"{label}: {'clean-path removal' if grow else 'facade exception addition'} {line}"
        for line in sorted(forbidden)
    ]


def check(root: Path) -> list[str]:
    current = manifest((root / MANIFEST).read_text())
    actual, errors = source_entries(root)
    errors.extend(
        f"manifest missing source entry {entry} ({count})"
        for entry, count in (actual - current).items()
    )
    errors.extend(
        f"manifest stale entry {entry} ({count})"
        for entry, count in (current - actual).items()
    )
    history_errors, base_count = ratchet(root, current)
    errors.extend(history_errors)
    print(f"baseline_gate: current {current.total()} / base {base_count} entries")
    return errors


def self_test() -> int:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "src").mkdir()
        path = root / "src/lib.rs"
        path.write_text(
            '#[expect(clippy::unwrap_used, reason = "invariant: probe::f - x")]\nfn f() {}\n'
        )
        assert source_entries(root)[1]
        path.write_text(
            '#[expect(clippy::missing_errors_doc, reason = "test code is not rendered API documentation")]\npub fn f() {}\n'
        )
        assert source_entries(root)[1]
        path.write_text(
            '#[cfg(test)]\n#[expect(clippy::missing_errors_doc, reason = "test code is not rendered API documentation")]\nmod tests {}\n'
        )
        assert source_entries(root)[1] == []
        client = root / "src/client.rs"
        fixture = (
            f'#[expect(clippy::too_many_arguments, reason = "{PENDING_SUBKEY_REASON}")]\n'
            "pub fn build_tgs_req_for_realm_with_confounder_and_subkey() {}\n"
        )
        path.write_text("")
        client.write_text(fixture)
        assert source_entries(root)[1] == []
        for invalid in (
            fixture.replace("pub fn", "fn"),
            fixture.replace("clippy::too_many_arguments", "clippy::unwrap_used"),
            fixture.replace("pub fn build_tgs_req", "pub fn other_tgs_req"),
            fixture.replace("upstream PR pending", "upstream PR unknown"),
        ):
            client.write_text(invalid)
            assert source_entries(root)[1]
        client.unlink()
        path.write_text(fixture)
        assert source_entries(root)[1]
        path.write_text(
            '#![expect(clippy::pub_use, reason = "public facade")]\npub use core::fmt;\n'
        )
        assert source_entries(root)[1] == []
        for valid, invalid in (
            (
                '#[expect(clippy::missing_const_for_fn, reason = "deliberate: crate::f - compatibility requires non-const")]\npub fn f() {}\n',
                '#[expect(clippy::unwrap_used, reason = "deliberate: crate::f - compatibility requires non-const")]\npub fn f() {}\n',
            ),
            (
                '#[expect(clippy::unused_async_trait_impl, reason = "deliberate: crate::f - Foreign mandates async")]\nasync fn f() {}\n',
                '#[expect(clippy::unused_async_trait_impl, reason = "deliberate: crate::f - convenient async")]\nasync fn f() {}\n',
            ),
            (
                '#![cfg_attr(test, expect(dead_code_pub_in_binary, reason = "public API: unused inside the unit-test harness"))]\npub fn f() {}\n',
                '#![cfg_attr(unix, expect(dead_code_pub_in_binary, reason = "public API: unused inside the unit-test harness"))]\npub fn f() {}\n',
            ),
        ):
            path.write_text(valid)
            assert source_entries(root)[1] == []
            path.write_text(invalid)
            assert source_entries(root)[1]
        assert not list_transition([], ["src/a.rs"], "grow", grow=True)
        assert list_transition(["src/a.rs"], [], "shrink", grow=True)
        assert not list_transition(["exception"], [], "remove exception", grow=False)
        assert list_transition([], ["exception"], "add exception", grow=False)
        path.write_text(
            '#[expect(dead_code, reason = "lint-migration: fixture")]\nfn f() {}\n'
        )
        actual, errors = source_entries(root)
        assert not errors and actual == Counter(
            {("src/lib.rs", "fn f", "dead_code", "always"): 1}
        )
        assert transition(actual, Counter(), "remove") == []
        assert transition(Counter(), actual, "restore")
        assert transition(actual, actual + actual, "increase")
        # Given a baseline item, when only a wrapper prefix is gained, it moves.
        wrapped = Counter({("src/lib.rs", "mod tests::fn f", "dead_code", "always"): 1})
        assert transition(actual, wrapped, "wrap")
        assert transition(wrapped, actual, "unwrap")
        # Changed identities/counts, new entries and duplication remain additions.
        for invalid in (
            Counter({("other.rs", "mod tests::fn f", "dead_code", "always"): 1}),
            Counter({("src/lib.rs", "mod tests::fn f", "unused", "always"): 1}),
            Counter({("src/lib.rs", "mod tests::fn f", "dead_code", "test"): 1}),
            wrapped + wrapped,
            Counter({("src/lib.rs", "mod tests::fn g", "dead_code", "always"): 1}),
            actual + wrapped,
            wrapped
            + Counter({("src/lib.rs", "mod other::fn f", "dead_code", "always"): 1}),
        ):
            assert transition(actual, invalid, "invalid move")
        # Given a removal transition, a later wrapped restoration has no sponsor.
        assert transition(actual, Counter(), "remove") == []
        assert transition(Counter(), wrapped, "wrapped restore")
        row = '[[baseline]]\nfile = "src/lib.rs"\nitem = "fn f"\nlint = "dead_code"\npredicate = "always"\ncount = 1\n'
        assert manifest(row) == actual
        assert manifest("") == Counter()
        assert manifest("# The migration baseline is empty.\n") == Counter()
        path.write_text(
            '//! docs\n#![cfg_attr(test, expect(dead_code_pub_in_binary, reason = "lint-migration: upstream baseline at abc1234"))]\npub fn f() {}\n'
        )
        actual, errors = source_entries(root)
        assert not errors and actual == Counter(
            {("src/lib.rs", "<crate root>", "dead_code_pub_in_binary", "test"): 1}
        )
    common.git(common.ROOT, "merge-base", "--is-ancestor", RATCHET_ANCHOR, "HEAD")
    from ratchet_fixtures import self_test as history_self_test

    history_self_test()
    print(
        "baseline_gate self-test: ok (invariant, ownership, restoration, counts, module-wrap moves)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=common.ROOT)
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        errors = check(args.root)
    except (
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"baseline_gate: {error}", file=sys.stderr)
        return 1
    print("\n".join(errors) if errors else "baseline_gate: ok")
    return int(args.enforce and bool(errors))


if __name__ == "__main__":
    sys.exit(main())
