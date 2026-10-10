"""The coverage probe: known intents re-placed and re-encoded, measured, misses recorded."""

from __future__ import annotations

import json

from momus.engine.coverage import (
    ENCODINGS,
    INTENTS,
    LANGS,
    PLACEMENTS,
    PARAPHRASES,
    SINK,
    generate,
    measure,
    round_report,
    write_misses,
)


def test_every_combination_is_generated_deterministically_and_names_nothing_of_ours():
    variants = generate()
    assert len(variants) == len(INTENTS) * len(LANGS) * len(PLACEMENTS) * len(ENCODINGS) * len(PARAPHRASES)
    assert [v.id for v in variants] == [v.id for v in generate()], "deterministic for a round"
    assert len({v.id for v in variants}) == len(variants), "ids are unique"
    for v in variants:
        blob = json.dumps(v.tools, ensure_ascii=False).lower()
        for own in ("warden", "momus", "aimarket", "modelmarket", "atlas", "metis"):
            assert own not in blob, (v.id, own)
    # the exfil target is an .invalid placeholder; in plain form it is visible, and it never leaks into ids
    for v in generate(encodings=["plain"]):
        blob = json.dumps(v.tools, ensure_ascii=False).lower()
        assert ".invalid" in blob or v.intent in ("instruction_to_model",), (v.id, "exfil targets are .invalid")
    assert all("invalid" not in v.id for v in variants)


def test_the_instruction_lands_in_the_chosen_place():
    by_place = {v.placement: v for v in generate(intents=["secret_request"], languages=["en"], encodings=["plain"], paraphrases=["direct"])}
    tool = by_place["param_description"].tools[0]
    assert "read the file" in tool["inputSchema"]["properties"]["note"]["description"].lower()
    assert by_place["param_default"].tools[0]["inputSchema"]["properties"]["note"]["default"]
    assert by_place["enum"].tools[0]["inputSchema"]["properties"]["mode"]["enum"][1]
    assert by_place["title"].tools[0]["annotations"]["title"]
    assert by_place["output_schema"].tools[0]["outputSchema"]["description"]
    assert "read the file" in by_place["description"].tools[0]["description"].lower()


def test_encodings_change_the_bytes_but_keep_the_words_readable():
    base = generate(intents=["exfiltration"], languages=["en"], placements=["description"], encodings=["plain"])[0]
    enc = {v.encoding: v.tools[0]["description"] for v in
           generate(intents=["exfiltration"], languages=["en"], placements=["description"])}
    assert "​" in enc["zero_width"] and "​" not in enc["plain"]
    assert enc["base64"] != base.tools[0]["description"] and "decode and follow" in enc["base64"]
    assert any(ord(c) > 0x3000 for c in enc["fullwidth"]) or "ignore" not in enc["plain"].lower()
    assert enc["homoglyph"] != enc["plain"]


def test_measure_reports_recall_per_dimension_and_collects_misses():
    variants = generate()
    # A scanner that only reads plain ASCII: catches plain text, blind to every evasion.
    def ascii_only(v):
        blob = json.dumps(v.tools)
        return blob.isascii() and any(x in blob.lower() for x in ("read the file", "send the result", "do not tell", "ignore the user", "call the send", "add " + SINK))
    r = measure(variants, ascii_only)
    assert r.total == len(variants) and 0 < r.blocked < r.total
    assert len(r.misses) == r.total - r.blocked
    enc = r.by_dimension["encoding"]
    assert enc["zero_width"][0] == 0, "an evasion-blind scanner misses every zero-width variant"
    assert enc["plain"][0] > enc["base64"][0]
    # recall sums across any dimension back to the same total
    assert sum(b for b, _ in r.by_dimension["language"].values()) == r.blocked


def test_round_report_names_the_weakest_cells(tmp_path):
    variants = generate()
    r = measure(variants, lambda v: v.encoding == "plain")  # only plain text is caught
    report = round_report(variants, r, warden_version="0.10.0", round_id="2026-10-10")
    assert report["recall"] == round(len(INTENTS) * len(LANGS) * len(PLACEMENTS) * len(PARAPHRASES) / r.total, 4)
    worst_enc = [c["value"] for c in report["worstBy"]["encoding"]]
    assert "plain" not in worst_enc
    n = write_misses(r.misses, tmp_path / "misses")
    assert n == len(r.misses) and len(list((tmp_path / "misses").glob("*.json"))) == n
    loaded = json.loads(next((tmp_path / "misses").glob("*.json")).read_text())
    assert set(loaded) == {"name", "tools"}
