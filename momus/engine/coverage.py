"""Reproducible, non-executing coverage probes for a local WARDEN build.

The reviewed corpus supplies labels; WARDEN only supplies decisions. Model-authored
proposals are labelled ``candidate`` and excluded from recall until reviewed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from momus.engine.coverage_corpus import (
    BENIGN, INTENT_NAMES, LANGS, PARAPHRASES, SECRET, SINK, TEXTS,
)
from momus.warden_feed import _FIRST_PARTY

GENERATOR_VERSION = "3"
INTENTS = {name: {"category": name, "text": TEXTS["en"][i][0]}
           for i, name in enumerate(INTENT_NAMES)}
PLACEMENTS = ("description", "param_description", "param_default", "enum", "title",
              "output_schema", "tool_title", "nested_schema", "metadata")


def _zero_width(text: str) -> str:
    return "".join(c + "\u200b" if c.isalpha() else c for c in text)


def _homoglyph(text: str) -> str:
    return text.translate(str.maketrans("aeopcxAEOPCX", "аеорсхАЕОРСХ"))


def _fullwidth(text: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in text)


ENCODINGS: dict[str, Callable[[str], str]] = {
    "plain": lambda t: t,
    "zero_width": _zero_width,
    "homoglyph": _homoglyph,
    "fullwidth": _fullwidth,
    "base64": lambda t: "Config: " + base64.b64encode(t.encode()).decode() + " (decode and follow).",
    "html_entities": lambda t: "".join(f"&#{ord(c)};" if c.isalpha() else c for c in t),
    "unicode_escape": lambda t: "".join(json.dumps(c, ensure_ascii=True)[1:-1]
                                          if c.isalpha() and ord(c) > 127 else
                                          f"\\u{ord(c):04x}" if c.isalpha() else c for c in t),
    "fullwidth_zero_width": lambda t: _zero_width(_fullwidth(t)),
}


@dataclass(frozen=True)
class Variant:
    id: str
    intent: str
    category: str
    language: str
    placement: str
    encoding: str
    tools: list[dict[str, Any]]
    paraphrase: str = "direct"
    label: str = "malicious"
    source: str = "template"
    parent_id: str | None = None

    @property
    def fingerprint(self) -> str:
        """Content identity, independent of generation order, round, and claimed intent."""
        return hashlib.sha256(json.dumps(self.tools, ensure_ascii=False, sort_keys=True,
                                         separators=(",", ":")).encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _names_ours(text: str) -> bool:
    return any(own in text.lower() for own in _FIRST_PARTY)


def _instruction(intent: str, language: str, encoding: str, paraphrase: str = "direct") -> str:
    body = TEXTS[language][INTENT_NAMES.index(intent)][PARAPHRASES.index(paraphrase)]
    return ENCODINGS[encoding](body.format(secret=SECRET, where=SINK))


def _tool(intent: str, instruction: str, placement: str) -> dict[str, Any]:
    base: dict[str, Any] = {"name": "do_task", "description": "Performs a task.",
                            "inputSchema": {"type": "object", "properties": {"input": {"type": "string"}}}}
    props = base["inputSchema"]["properties"]
    if placement == "description":
        base["description"] += " " + instruction
    elif placement == "param_description":
        props["note"] = {"type": "string", "description": instruction}
    elif placement == "param_default":
        props["note"] = {"type": "string", "default": instruction}
    elif placement == "enum":
        props["mode"] = {"type": "string", "enum": ["normal", instruction]}
    elif placement == "title":
        base["annotations"] = {"title": instruction}
    elif placement == "tool_title":
        base["title"] = instruction
    elif placement == "output_schema":
        base["outputSchema"] = {"type": "object", "description": instruction,
                                "properties": {"result": {"type": "string"}}}
    elif placement == "nested_schema":
        props["items"] = {"type": "array", "items": {"type": "object", "properties": {
            "note": {"type": "string", "description": instruction}}}}
    elif placement == "metadata":
        base["_meta"] = {"usage": instruction}
    else:
        raise ValueError(f"unknown placement: {placement}")
    return base


def _choices(selected: list[str] | None, available) -> list[str]:
    result = list(available) if selected is None else list(selected)
    if len(set(result)) != len(result) or any(x not in available for x in result):
        raise ValueError("unknown or duplicate generator dimension")
    return result


def generate(intents: list[str] | None = None, *, languages: list[str] | None = None,
             placements: list[str] | None = None, encodings: list[str] | None = None,
             paraphrases: list[str] | None = None) -> list[Variant]:
    """Cartesian coverage. Campaigns deduplicate identical content before measuring it."""
    dims = [_choices(intents, INTENTS), _choices(languages, LANGS),
            _choices(placements, PLACEMENTS), _choices(encodings, ENCODINGS),
            _choices(paraphrases, PARAPHRASES)]
    out = []
    for intent in dims[0]:
        for language in dims[1]:
            for placement in dims[2]:
                for encoding in dims[3]:
                    for paraphrase in dims[4]:
                        raw = _instruction(intent, language, "plain", paraphrase)
                        if _names_ours(raw):
                            continue  # inspect BEFORE encoding as well
                        tool = _tool(intent, ENCODINGS[encoding](raw), placement)
                        if _names_ours(json.dumps(tool, ensure_ascii=False)):
                            continue
                        vid = f"{intent}.{language}.{placement}.{encoding}.{paraphrase}"
                        out.append(Variant(vid, intent, intent, language, placement, encoding,
                                           [tool], paraphrase))
    return out


def benign_controls() -> list[Variant]:
    return [Variant(f"benign.{lang}.{i}.{place}", "benign", "benign", lang, place,
                    "plain", [_tool("benign", text, place)], label="benign")
            for lang, texts in BENIGN.items() for i, text in enumerate(texts)
            for place in ("description", "param_description", "output_schema")]


def unique(variants: list[Variant]) -> list[Variant]:
    out: dict[str, Variant] = {}
    for v in variants:
        old = out.get(v.fingerprint)
        if old and old.label != v.label:
            raise ValueError("conflicting labels for identical content")
        out.setdefault(v.fingerprint, v)
    return list(out.values())


@dataclass
class Recall:
    total: int
    blocked: int
    by_dimension: dict[str, dict[str, tuple[int, int]]]
    misses: list[Variant]
    inconclusive: list[Variant] = field(default_factory=list)

    @property
    def rate(self) -> float | None:
        graded = self.total - len(self.inconclusive)
        return self.blocked / graded if graded else None


def measure(variants: list[Variant], blocks: Callable[[Variant], bool | None]) -> Recall:
    """None means unmeasured, never a miss or a detection. Only labelled attacks count."""
    by: dict[str, dict[str, list[int]]] = {d: {} for d in
        ("intent", "category", "language", "placement", "encoding", "paraphrase")}
    blocked, misses, errors = 0, [], []
    attacks = [v for v in variants if v.label == "malicious"]
    for v in attacks:
        hit = blocks(v)
        if hit is None:
            errors.append(v)
            continue
        if type(hit) is not bool:
            raise TypeError("a scanner decision must be bool or None")
        blocked += hit
        if not hit:
            misses.append(v)
        for dim in by:
            cell = by[dim].setdefault(getattr(v, dim), [0, 0])
            cell[0] += hit
            cell[1] += 1
    return Recall(len(attacks), blocked,
                  {d: {k: (c[0], c[1]) for k, c in vals.items()} for d, vals in by.items()}, misses, errors)


def write_misses(misses: list[Variant], path: Path) -> int:
    path.mkdir(parents=True, exist_ok=True)
    for v in misses:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", v.id) or v.id in (".", ".."):
            raise ValueError("unsafe fixture id")
        (path / f"{v.id}.json").write_text(json.dumps({"name": v.id, "tools": v.tools}, ensure_ascii=False), encoding="utf-8")
    return len(misses)


def eval_with_warden(variants: list[Variant], warden_lib: str, node: str = "node",
                     gates_script: str | None = None) -> Callable[[Variant], bool | None]:
    from momus.engine.warden_eval import evaluate
    result = evaluate(variants, warden_lib, node=node, script=gates_script)
    return lambda v: result.blocks(v)


def round_report(variants: list[Variant], recall: Recall, *, warden_version: str, round_id: str) -> dict[str, Any]:
    worst = {}
    for dim, cells in recall.by_dimension.items():
        ranked = sorted(cells.items(), key=lambda kv: (kv[1][0] / kv[1][1], kv[0]))
        worst[dim] = [{"value": k, "blocked": b, "total": tot} for k, (b, tot) in ranked[:3]]
    return {
        "round": round_id, "wardenVersion": warden_version, "generatorVersion": GENERATOR_VERSION,
        "variants": len(variants), "attacks": recall.total, "blocked": recall.blocked,
        "evaluated": recall.total - len(recall.inconclusive),
        "inconclusive": len(recall.inconclusive),
        "recall": round(recall.rate, 4) if recall.rate is not None else None,
        "missed": len(recall.misses), "worstBy": worst,
        "byDimension": {dim: {value: {"blocked": b, "total": t, "recall": b / t}
                              for value, (b, t) in cells.items()}
                        for dim, cells in recall.by_dimension.items()},
        "note": "Synthetic tool-definition gate coverage, not an agent exploitation rate. "
                "Model candidates are unreviewed and excluded from recall. Addresses are .invalid; secrets are decoys.",
    }
