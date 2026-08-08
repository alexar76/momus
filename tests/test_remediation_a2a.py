"""The remediation loop (finding → ticket → retest deploy-gate) and the A2A surface."""

from __future__ import annotations

import httpx
import pytest
# Module level ON PURPOSE: this file uses `from __future__ import annotations`, so FastAPI resolves
# handler annotations against the MODULE globals. A `Request` imported inside a test function is
# invisible there, and FastAPI silently degrades it to a query parameter → 422.
from fastapi import FastAPI, Request

from momus.a2a import A2AClient, agent_card, remediation_task
from momus.app import build_app
from momus.capabilities import MomusRuntime
from momus.config import MomusConfig
from momus.engine.remediation import Retester, escalation_for, open_ticket
from momus.engine.scanner import Scanner
from momus.findings import Evidence, Finding, Outcome, Status
from momus.targets.oracle import OracleTarget


def _finding(scanner, target="oracles"):
    f = Finding(target=target, target_kind="oracle", probe="free_tier_ceiling_bypass",
                category="authz", severity="high", outcome=Outcome.FINDING.value,
                title="ceiling not enforced", detail="d",
                evidence=Evidence("sha256-a", "sha256-b"), status=Status.RAW.value)
    return scanner.sign_finding(f)


@pytest.mark.asyncio
async def test_retest_still_vulnerable_on_broken(scanner, broken_oracle_transport):
    r = Retester(scanner)
    tgt = OracleTarget("oracles", "http://broken.local", transport=broken_oracle_transport)
    v = await r.retest(tgt, "free_tier_ceiling_bypass", "mom-x")
    assert v.fixed is False and v.outcome == "finding"  # deploy must be BLOCKED
    assert v.signature.get("value")  # signed verdict


@pytest.mark.asyncio
async def test_retest_fixed_on_good(scanner, good_oracle_transport):
    r = Retester(scanner)
    tgt = OracleTarget("oracles", "http://good.local", transport=good_oracle_transport)
    v = await r.retest(tgt, "free_tier_ceiling_bypass", "mom-x")
    assert v.fixed is True and v.outcome == "no_finding"  # deploy may proceed


def test_escalation_routing():
    assert escalation_for("oracles", "oracle") == "auto"
    assert escalation_for("momus", "self") == "human-governance"
    assert escalation_for("treasury", "oracle") == "human-governance"


def test_open_ticket_signs_blame(scanner):
    f = _finding(scanner)
    ticket = open_ticket(f, scanner)
    assert ticket.route == "auto"
    assert ticket.probe == "free_tier_ceiling_bypass"
    assert ticket.blame.get("signature", {}).get("value")


def test_agent_card_advertises_skills():
    card = agent_card("http://momus.local")
    assert card["name"] == "MOMUS"
    skills = {s["id"] for s in card["skills"]}
    assert {"scan", "retest", "selfaudit"} <= skills
    assert card["endpoints"]["tasks"].endswith("/a2a/tasks")


def test_remediation_task_carries_gate():
    ticket = {"finding_id": "mom-1", "component": "oracles", "target": "oracles",
              "probe": "free_tier_ceiling_bypass", "severity": "high", "route": "auto"}
    task = remediation_task(ticket, to_agent="skopos")
    assert task.skill == "remediate" and task.to_agent == "skopos"
    assert task.input["gate"]["agent"] == "momus" and task.input["gate"]["skill"] == "retest"


@pytest.mark.asyncio
async def test_a2a_client_offline_safe():
    client = A2AClient("")  # no peer configured
    from momus.a2a import A2ATask
    out = await client.delegate(A2ATask(skill="remediate"))
    assert out["delivered"] is False and "no peer" in out["note"]


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
async def test_agent_card_route(app_client):
    async with app_client as c:
        card = (await c.get("/.well-known/agent-card.json")).json()
        assert card["protocolVersion"]
        assert any(s["id"] == "retest" for s in card["skills"])


@pytest.mark.asyncio
async def test_a2a_rejects_unknown_skill(app_client):
    async with app_client as c:
        r = await c.post("/a2a/tasks", json={"skill": "deploy", "input": {}})
        body = r.json()
        assert body["state"] == "rejected"


@pytest.mark.asyncio
async def test_a2a_scan_skill_runs(app_client):
    async with app_client as c:
        r = await c.post("/a2a/tasks", json={"skill": "scan", "input": {"target": "self"}})
        body = r.json()
        assert body["state"] == "completed"
        assert body["artifacts"][0]["type"] == "scan-report"


# ── AUDIT: the A2A client referenced a token it never set (AttributeError on the live path) ─────
@pytest.mark.asyncio
async def test_a2a_client_sends_the_peer_token(monkeypatch):
    """The offline path returns early, so a broken __init__ went unnoticed until a real delegate.
    This drives the CONFIGURED path against a stub peer and asserts the header actually arrives."""
    from momus.a2a import A2AClient, A2ATask

    seen: dict[str, str] = {}
    app = FastAPI()

    @app.post("/a2a/tasks")
    async def tasks(body: dict, request: Request):
        seen["token"] = request.headers.get("x-a2a-token", "")
        return {"state": "working"}

    monkeypatch.setenv("SKOPOS_A2A_TOKEN", "peer-secret")
    client = A2AClient("http://skopos.local", transport=httpx.ASGITransport(app=app))
    out = await client.delegate(A2ATask(skill="remediate", input={"ticket": {"finding_id": "x"}}))
    assert out["delivered"] is True, out
    assert seen["token"] == "peer-secret"


def test_conductor_rederives_route_and_ignores_the_claimed_one(tmp_path):
    """A peer could label a security-core finding as ordinary and walk it into the auto path."""
    from skopos.remediation.conductor import Conductor, RemediationConfig
    import asyncio as _aio
    cfg = RemediationConfig(data_dir=str(tmp_path / "rem"),
                            conductor_key_path=str(tmp_path / "rem" / "cond.key"), dry_run=True)
    conductor = Conductor(cfg)
    # The ticket LIES: it claims route=auto for a finding against the treasury (security core).
    ticket = {"finding_id": "mom-evil", "component": "treasury", "probe": "p",
              "severity": "critical", "route": "auto"}
    job = _aio.get_event_loop_policy().new_event_loop().run_until_complete(
        conductor.handle_ticket(ticket))
    assert job.route == "human-governance", "the claimed route must not win"
    assert job.state == "escalated"
