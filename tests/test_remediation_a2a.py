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
    assert escalation_for("hub", "hub") == "auto"
    assert escalation_for("momus", "self") == "human-governance"
    assert escalation_for("treasury", "oracle") == "human-governance"
    assert escalation_for("gate", "meta") == "human-governance"


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
    pytest.importorskip("skopos.remediation.conductor", reason="skopos not vendored in momus satellite")
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


def test_the_ticket_carries_the_defect_not_only_the_probe_name(tmp_path):
    """A fixer with an empty reproducer was left inferring the bug from a probe's NAME.

    Several probes legitimately record no reproducer — a signature check has nothing to curl.
    Measured live: three autonomous attempts each authored a different guess at what
    "conforming" meant, and the pre-promotion gate rejected all three.
    """
    from momus.engine.remediation import open_ticket
    from momus.findings import Evidence, Finding, FindingSigner

    signer = FindingSigner(str(tmp_path / "k"))
    finding = Finding(
        target="canary", target_kind="oracle", probe="manifest_signature_integrity",
        category="integrity", severity="high", outcome="finding",
        title="canary: manifest signature does not verify",
        detail="The published manifest's signature fails to verify against its declared key.",
        evidence=Evidence(request_digest="sha256-req", response_digest="sha256-abc",
                          status_code=200, reproducer=""),
    )
    ticket = open_ticket(finding, signer).to_dict()

    assert ticket["title"] == "canary: manifest signature does not verify"
    assert "fails to verify" in ticket["detail"]
    assert ticket["evidence"]["status_code"] == 200
    assert ticket["evidence"]["response_digest"] == "sha256-abc"
    # Empty fields are dropped rather than carried as noise.
    assert "reproducer" not in ticket["evidence"]
    # And the ticket still signs and verifies as before.
    assert ticket["blame"]["signature"]


def test_a_signature_probe_states_what_it_verifies():
    """"Your signature does not verify" without saying WHAT is signed is a guessing game.

    Live: three autonomous attempts each signed a different plausible string and the
    pre-promotion gate rejected all three. The canonical is derived from the manifest the
    target itself publishes, so naming it discloses nothing a reader could not compute.
    """
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1]
           / "momus" / "targets" / "oracle.py").read_text(encoding="utf-8")
    block = src[src.index("manifest signature does not verify"):]
    block = block[:block.index("# Tamper:")]
    assert "manifest_canonical" in block
    assert "tools_hash" in block and "by_hub_hash" in block
    assert "well-known" in block


def test_a_rediscovery_refreshes_the_stored_document(tmp_path):
    """A bug seen 39 times used to carry the evidence of sighting number one, weeks earlier.

    That is not a stale detail: the stored document is the whole payload a remediation ticket
    is built from, so a probe that learns to explain itself better could never reach whoever
    fixes the bug. Measured live — three autonomous attempts signed the wrong canonical
    because the contract the probe had started publishing never left the scanner.
    """
    from momus.findings import Evidence, Finding, FindingSigner
    from momus.store import FindingStore

    signer = FindingSigner(str(tmp_path / "k"))
    store = FindingStore(str(tmp_path))

    def _finding(snippet: str, severity: str = "high") -> Finding:
        f = Finding(
            target="canary", target_kind="oracle", probe="manifest_signature_integrity",
            category="integrity", severity=severity, outcome="finding",
            title="canary: manifest signature does not verify", detail="d",
            evidence=Evidence(request_digest="sha256-a", response_digest="sha256-b",
                              response_snippet=snippet),
        )
        return signer.sign_finding(f)

    first = store.record_finding(_finding("verify(canonical, value, BBBB…) = False"))
    assert first["new"] is True

    again = store.record_finding(_finding("Ed25519 over manifest_canonical = 'capabilities_count:…'"))
    assert again["new"] is False
    assert again["seen_count"] == 2

    row = store.get(again["finding_id"]) or {}
    assert "manifest_canonical" in (row.get("evidence") or {}).get("response_snippet", "")
    # The identity and the history survive the refresh.
    assert row["finding_id"] == first["finding_id"]
    assert row["seen_count"] == 2
    assert row["first_seen_at"] <= row["last_seen_at"]


def test_a_rediscovery_does_not_reset_a_curated_status(tmp_path):
    """status is workflow state the corpus owns; a scanner must not walk it back to raw."""
    from momus.findings import Evidence, Finding, FindingSigner
    from momus.store import FindingStore

    signer = FindingSigner(str(tmp_path / "k"))
    store = FindingStore(str(tmp_path))
    f = signer.sign_finding(Finding(
        target="canary", target_kind="oracle", probe="p", category="integrity",
        severity="high", outcome="finding", title="t", detail="d",
        evidence=Evidence(request_digest="a", response_digest="b")))
    rec = store.record_finding(f)
    store.set_status(rec["finding_id"], "confirmed")

    store.record_finding(f)
    assert (store.get(rec["finding_id"]) or {}).get("status") == "confirmed"


def test_every_reader_agrees_on_the_freshest_observation(tmp_path):
    """`get()` learned to serve the newest sighting and `recent()` kept serving the first.

    The reader that builds a remediation ticket went through `recent()`, so the fix that was
    supposed to reach the fixer never did — measured by rendering the real prompt on the live
    host and finding the three-week-old snippet in it.
    """
    from momus.findings import Evidence, Finding, FindingSigner
    from momus.store import FindingStore

    signer = FindingSigner(str(tmp_path / "k"))
    store = FindingStore(str(tmp_path))

    def _f(snippet: str) -> Finding:
        return signer.sign_finding(Finding(
            target="canary", target_kind="oracle", probe="manifest_signature_integrity",
            category="integrity", severity="high", outcome="finding", title="t", detail="d",
            evidence=Evidence(request_digest="a", response_digest="b", response_snippet=snippet)))

    first = store.record_finding(_f("verify(canonical, value, BBBB…) = False"))
    store.record_finding(_f("Ed25519 over manifest_canonical = 'capabilities_count:…'"))

    by_id = store.get(first["finding_id"]) or {}
    by_recent = next(r for r in store.recent(20) if r["finding_id"] == first["finding_id"])
    for name, row in (("get", by_id), ("recent", by_recent)):
        snippet = (row.get("evidence") or {}).get("response_snippet", "")
        assert "manifest_canonical" in snippet, f"{name}() served the first sighting"
    assert by_recent["seen_count"] == 2
