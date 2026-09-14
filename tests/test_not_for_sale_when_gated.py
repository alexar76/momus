"""What is operator-gated must not be advertised with a price.

The failure this pins is quiet and asymmetric: the capability is listed, the hub holds the
buyer's money at its 402, the invoke comes back 403, and the hold is released. Nobody loses a
cent — but the marketplace carried an offer that could never be accepted, and the buyer found
out by trying.
"""

from __future__ import annotations

import pytest

from fastapi.testclient import TestClient

from momus.app import build_app
from momus.capabilities import MomusRuntime
from momus.config import MomusConfig

ACT = {"momus.scan@v1", "momus.scan.external@v1", "momus.selfaudit@v1", "momus.retest@v1"}


def _tools(tmp_path, monkeypatch, *, prod: bool):
    """The BUYER's view: read the published manifest, not internals."""
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_SIGNING_KEY_PATH", str(tmp_path / "k"))
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "offline")
    monkeypatch.setenv("AIFACTORY_PROD", "1" if prod else "0")
    monkeypatch.setenv("MOMUS_OPERATOR_TOKEN", "s3cret")
    monkeypatch.delenv("MOMUS_REQUIRE_OPERATOR", raising=False)
    app = build_app(MomusRuntime(MomusConfig.from_env()))
    with TestClient(app) as client:
        body = client.get("/ai-market/v2/manifest").json()
    return {t["capability_id"]: t for t in body["tools"]}


def test_gated_capabilities_are_published_unpriced(tmp_path, monkeypatch):
    tools = _tools(tmp_path, monkeypatch, prod=True)
    for cap in ACT:
        assert cap in tools, f"{cap} vanished from the manifest — the operator path needs it"
        assert tools[cap]["price_per_call_usd"] == 0.0, (
            f"{cap} is operator-gated and answers 403 to any hub caller, but is advertised at "
            f"${tools[cap]['price_per_call_usd']} — the hub will sell it and the buyer will be "
            f"refused")
        assert "operator" in tools[cap]["description"].lower()


def test_the_sellable_capability_keeps_its_price(tmp_path, monkeypatch):
    tools = _tools(tmp_path, monkeypatch, prod=True)
    assert tools["momus.report@v1"]["price_per_call_usd"] > 0, (
        "momus.report@v1 is not operator-gated and is the one capability that is actually "
        "sellable today — unpricing it would silently stop the node earning")


def test_without_the_gate_nothing_is_unpriced(tmp_path, monkeypatch):
    tools = _tools(tmp_path, monkeypatch, prod=False)
    assert tools["momus.scan.external@v1"]["price_per_call_usd"] > 0, (
        "with no operator gate the act-capabilities are servable, so they keep their price")
