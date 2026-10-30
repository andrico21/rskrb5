#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/check-error-constructions.py [--self-test]
"""Audit public error variants against explicit Rust construction expressions."""

from __future__ import annotations

import re
import sys
from functools import lru_cache
from dataclasses import dataclass
from pathlib import Path
from typing import Final

sys.path.insert(0, str(Path(__file__).resolve().parent / "lint-gates"))
from rust_lex import (
    iter_attributes,
    match_bracket,
    split_top_level,
    strip_comments_and_strings,
)

ROOT: Final = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class AuditError(Exception):
    detail: str

    def __str__(self) -> str:
        return self.detail


@dataclass(frozen=True, slots=True)
class Variant:
    domain: str
    name: str
    shape: str


def variants(text: str) -> list[Variant]:
    clean = strip_comments_and_strings(text)
    result: list[Variant] = []
    for enum in re.finditer(r"\bpub\s+enum\s+(\w+)\s*\{", clean):
        end = match_bracket(clean, enum.end() - 1)
        if end is None:
            raise AuditError(f"unclosed enum {enum[1]}")
        body = clean[enum.end() : end]
        for start, stop in split_top_level(body):
            part = body[start:stop]
            for left, right, _, _ in reversed(list(iter_attributes(part))):
                part = part[:left] + " " * (right - left) + part[right:]
            if not part.strip():
                continue
            item = re.fullmatch(r"\s*(\w+)\s*([({].*[)}])?\s*", part, re.S)
            if item is None:
                raise AuditError(f"unparsed variant in {enum[1]}: {part.strip()}")
            result.append(Variant(enum[1], item[1], item[2][:1] if item[2] else "unit"))
    if len(re.findall(r"\bpub\s+enum\b", clean)) != len(
        list(re.finditer(r"\bpub\s+enum\s+\w+\s*\{", clean))
    ):
        raise AuditError("unsupported public enum declaration")
    return result


def expression_uses(clean: str, variant: Variant, aliases: set[str]) -> bool:
    """Accept constructors in expression-only funnels, never arbitrary mentions."""
    paths = "|".join(re.escape(alias) for alias in sorted(aliases))
    path = rf"(?:{paths})\s*::\s*{re.escape(variant.name)}\b"
    funnels = r"(?:\b(?:Err|Some|ok_or|ok_or_else|map_err|from|new)\s*\(|(?:=|\breturn)\s*|=>\s*|\|\s*|\{\s*|,\s*)"
    for hit in re.finditer(funnels + r"\s*(" + path + r")", clean):
        tail = clean[hit.end() :].lstrip()
        after = tail
        if tail.startswith(("(", "{")):
            end = match_bracket(tail, 0)
            if end is None:
                raise AuditError("unclosed constructor expression")
            after = tail[end + 1 :].lstrip()
        if re.match(r"[),\s]*(?:=>|\bif\b|\|)", after):
            continue
        if variant.shape == "unit" or tail.startswith(variant.shape):
            return True
        if tail.startswith(")") and re.search(
            r"map_err\s*\(\s*$", clean[: hit.start(1)]
        ):
            return True
    return False


@lru_cache(maxsize=16384)
def aliases_for(text: str, domain: str) -> set[str]:
    """Resolve explicit error-domain imports, including the conventional Error alias."""
    aliases = {
        f"error::{domain}",
        f"crate::error::{domain}",
        f"rskrb5_ng::error::{domain}",
    }
    for statement in re.finditer(r"\buse\s+([^;]+);", text, re.S):
        body = statement[1]
        if re.search(rf"\berror\s*::\s*{domain}\b", body) or (
            "error::{" in re.sub(r"\s+", "", body) and re.search(rf"\b{domain}\b", body)
        ):
            rename = re.search(rf"\b{domain}\s+as\s+(\w+)", body)
            aliases.add(rename[1] if rename else domain)
    return aliases


def audit(root: Path) -> list[str]:
    definition_paths = [
        root / "src/error.rs",
        *sorted((root / "src/error").rglob("*.rs")),
    ]
    inventory = [
        item
        for path in definition_paths
        for item in variants(path.read_text(encoding="utf-8"))
    ]
    if not inventory or len(set((item.domain, item.name) for item in inventory)) != len(
        inventory
    ):
        raise AuditError("empty or duplicate public error variant inventory")
    sources = []
    for folder in ("src", "tests", "examples", "fuzz/fuzz_targets"):
        for path in sorted((root / folder).rglob("*.rs")):
            if path not in definition_paths:
                text = path.read_text(encoding="utf-8")
                template = re.search(
                    r"macro_rules!\s+crypto_random_sources\s*\{",
                    strip_comments_and_strings(text),
                )
                for call in re.finditer(
                    r"crypto_random_sources!\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)",
                    strip_comments_and_strings(text),
                ):
                    if template is None:
                        raise AuditError(
                            "source fixture macro has no readable definition"
                        )
                    stop = match_bracket(
                        strip_comments_and_strings(text), template.end() - 1
                    )
                    if stop is None:
                        raise AuditError("unclosed source fixture macro")
                    text += "\n" + text[template.end() : stop].replace(
                        "$domain", call[1]
                    )
                inherited = text
                for parent in path.relative_to(root).parents:
                    if not parent.name:
                        continue
                    ancestor = root / parent.with_suffix(".rs")
                    if ancestor.is_file() and ancestor != path:
                        inherited += "\n" + ancestor.read_text(encoding="utf-8")
                sources.append(
                    (
                        path,
                        strip_comments_and_strings(text),
                        strip_comments_and_strings(inherited),
                    )
                )
    if not sources:
        raise AuditError("no Rust construction sources found")
    missing = []
    for item in inventory:
        if item.domain == "Any" and item.name not in {"Hex", "Decode"}:
            payload = {"CCache": "Ccache", "Krb": "KrbErrorCodec"}.get(
                item.name, item.name
            )
            api_test = strip_comments_and_strings(
                (root / "tests/error_api.rs").read_text(encoding="utf-8")
            )
            definition = (root / "src/error/any.rs").read_text(encoding="utf-8")
            conversion = re.search(
                rf"\b{item.name}\s*\(\s*#\[from\]\s*{payload}\s*\)", definition
            )
            if (
                conversion
                and re.search(
                    rf"propagates_domain!\(\s*\w+\s*,\s*error::{payload}\s*,", api_test
                )
                and "let _value = $operation?;" in api_test
                and "|| -> Result<()>" in api_test
            ):
                continue
        if not any(
            expression_uses(text, item, aliases_for(imports, item.domain))
            for _, text, imports in sources
        ):
            missing.append(f"{item.domain}::{item.name}")
    print(f"public error variants: {len(inventory)}; unconstructed: {len(missing)}")
    return missing


def self_test() -> None:
    # Given unit, tuple and struct declarations under CRLF and attributes.
    sample = (
        'pub enum Demo { #[error("x,y")] Unit, Tuple(String), Record { n: u8 }, }\r\n'
    )
    items = variants(sample)
    assert [item.name for item in items] == ["Unit", "Tuple", "Record"]
    # When matching genuine construction funnels versus pattern/prose decoys.
    unit, pair, record = items
    assert expression_uses("Err(error::Demo::Unit)", unit, {"error::Demo"})
    assert expression_uses("x.map_err(error::Demo::Tuple)", pair, {"error::Demo"})
    assert expression_uses(
        "return error::Demo::Record { n: 1 };", record, {"error::Demo"}
    )
    for decoy in (
        '"Err(error::Demo::Unit)"',
        "// Err(error::Demo::Unit)\r\n",
        "error::Demo::Unit => true",
        "match x { error::Demo::Unit => true }",
    ):
        assert not expression_uses(
            strip_comments_and_strings(decoy), unit, {"error::Demo"}
        )
    # Then malformed definitions fail closed instead of shrinking the inventory.
    try:
        variants("pub enum Demo { macro!(), }")
    except AuditError:
        pass
    else:
        raise AssertionError("opaque variant accepted")
    print("error-constructions self-test: PASS")


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return 0
    if sys.argv[1:]:
        raise AuditError("usage: check-error-constructions.py [--self-test]")
    missing = audit(ROOT)
    for name in missing:
        print(f"unconstructed: {name}")
    return int(bool(missing))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuditError, OSError, UnicodeError) as failure:
        print(f"error-constructions: {failure}", file=sys.stderr)
        raise SystemExit(2) from failure
