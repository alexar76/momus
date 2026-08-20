"""Self-audit invariants and the FastAPI control routes."""

from __future__ import annotations

import httpx
import pytest

from momus.app import build_app
from momus.capabilities import MomusRuntime
from momus.config import MomusConfig
from momus.economics import KeyRing
from momus.engine.selfaudit import run_self_audit
from momus.findings import Outcome


def test_self_audit_all_invariants_hold(tmp_path):
    """With a proper (distinct) scanner + treasury key, every invariant self-check passes."""
    from momus.findings import FindingSigner
    scanner = FindingSigner(str(tmp_path / "scanner.key"))
    keyring = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    counter = {"n": 0}

    def ledger_path_factory():
        counter["n"] += 1
        return str(tmp_path / f"audit_{counter['n']}.jsonl")

    report = run_self_audit(scanner, keyring, ledger_path_factory)
    # No invariant FAILED -> zero meta-findings, all honest negatives.
    assert report.counts["findings"] == 0, [r.title for r in report.records if r.outcome == Outcome.FINDING.value]
    titles = {r.probe for r in report.records}
    assert "selfaudit_key_separation" in titles
    assert "selfaudit_self_verification" in titles
    assert "selfaudit_dedup_replay" in titles


def test_self_audit_no_treasury_reports_fail_closed(tmp_path):
    from momus.findings import FindingSigner
    scanner = FindingSigner(str(tmp_path / "scanner.key"))
    keyring = KeyRing(str(tmp_path / "scanner.key"))  # no treasury key
    counter = {"n": 0}

    def ledger_path_factory():
        counter["n"] += 1
        return str(tmp_path / f"audit_{counter['n']}.jsonl")

    report = run_self_audit(scanner, keyring, ledger_path_factory)
    assert report.counts["findings"] == 0  # fail-closed is a PASS, not a finding
    assert any(r.probe == "selfaudit_fail_closed" for r in report.records)


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_SIGNING_KEY_PATH", str(tmp_path / "key"))
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "offline")
    monkeypatch.setenv("AIFACTORY_PROD", "0")
    runtime = MomusRuntime(MomusConfig.from_env())
    app = build_app(runtime)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://momus.local")


@pytest.mark.asyncio
async def test_health_route(app_client):
    async with app_client as c:
        r = await c.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert body["service"] == "momus"
        assert body["scanner_pubkey"]
        assert body["holds_treasury_key"] is False  # MOMUS never holds the payout key


@pytest.mark.asyncio
async def test_providers_route(app_client):
    async with app_client as c:
        body = (await c.get("/providers")).json()
        assert body["selected"]["provider"] == "offline"
        assert any(ch["name"] == "deepseek" for ch in body["choices"])


@pytest.mark.asyncio
async def test_scan_self_route(app_client):
    async with app_client as c:
        r = await c.post("/scan", json={"target": "self"})
        assert r.status_code == 200
        body = r.json()
        assert "counts" in body and "records" in body


@pytest.mark.asyncio
async def test_selfaudit_route(app_client):
    async with app_client as c:
        r = await c.post("/selfaudit")
        assert r.status_code == 200
        assert "counts" in r.json()


@pytest.mark.asyncio
async def test_intel_route(app_client):
    async with app_client as c:
        body = (await c.get("/intel")).json()
        assert "category_scores" in body and "intel_enabled" in body


@pytest.mark.asyncio
async def test_intel_refresh_requires_operator_token(app_client):
    async with app_client as c:
        r = await c.post("/intel/refresh")
        assert r.status_code == 403  # no operator token configured


@pytest.mark.asyncio
async def test_manifest_and_invoke_surface(app_client):
    async with app_client as c:
        man = (await c.get("/ai-market/v2/manifest")).json()
        assert man["capabilities_count"] >= 5
        inv = await c.post("/ai-market/v2/invoke", json={"capability_id": "momus.selfaudit@v1", "input": {}})
        assert inv.status_code == 200
