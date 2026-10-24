#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/baseline_gate.py --self-test
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

MANIFEST: Final = "scripts/lint-ratchet/baseline.toml"
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
    previous: Counter[Entry], current: Counter[Entry], label: str
) -> list[str]:
    return [
        f"{label}: baseline addition/restoration {key} (+{count})"
        for key, count in (current - previous).items()
    ]


def ratchet(root: Path, current: Counter[Entry]) -> tuple[list[str], int]:
    history = common.git(root, "log", "--format=%H %s", "--", MANIFEST).splitlines()
    base = next(
        (
            line.split(" ", 1)[0]
            for line in history
            if re.match(
                r"[0-9a-f]+ lint: (?:rebaseline for Rust |adopt the rmcp-server-kit strictest profile)",
                line,
            )
        ),
        None,
    )
    if base is None:
        return ["no ratchet base commit found; finish todo 14 first"], 0
    previous = manifest(common.git(root, "show", f"{base}:{MANIFEST}"))
    base_count = previous.total()
    errors = []
    for commit in common.git(
        root, "log", "--reverse", "--format=%H", f"{base}..HEAD", "--", MANIFEST
    ).splitlines():
        now = manifest(common.git(root, "show", f"{commit}:{MANIFEST}"))
        errors.extend(transition(previous, now, commit))
        previous = now
    errors.extend(transition(previous, current, "working tree"))
    return errors, base_count


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
        row = '[[baseline]]\nfile = "src/lib.rs"\nitem = "fn f"\nlint = "dead_code"\npredicate = "always"\ncount = 1\n'
        assert manifest(row) == actual
    print(
        "baseline_gate self-test: ok (invariant, non-test exception, ownership, restoration, counts)"
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
