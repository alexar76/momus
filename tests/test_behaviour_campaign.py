from types import SimpleNamespace

import pytest
from momus.engine.behaviour_campaign import evaluate, generate, materialize, observe_case


def test_generation_is_replayable_and_changes_between_months(tmp_path):
    a = generate("2026-10")
    b = generate("2026-11")
    assert a == generate("2026-10") and len(a) == 72
    assert len({c["id"] for c in a}) == 72
    assert {c["id"] for c in a}.isdisjoint(c["id"] for c in b)
    assert {c["phase"] for c in a} == {"installScripts", "startup", "calls"}
    assert {c["channel"] for c in a} == {"http", "https", "smtp"}
    materialize(a[0], tmp_path)
    assert (tmp_path / "pkg/node_modules/momus-fixture/fixture.cjs").read_text() == a[0]["source"]


def test_no_fallback_to_host_execution_and_incomplete_is_not_detection():
    with pytest.raises(RuntimeError):
        observe_case(SimpleNamespace(traced_available=lambda: False), generate("test")[0])
    malicious = next(c for c in generate("test") if c["behaviour"] == "extra_recipient")
    assert evaluate(malicious, {"complete": False})["status"] == "missed"
    assert evaluate(malicious, {"unexpectedRecipients": ["copy@momus-trap.invalid"]})["detected"]
