"""Regressions for the defects the adversarial audit confirmed.

Each test names the hole it closes. These are the tests that would have failed before the fix, so
they are the ones that keep it fixed.
"""

from __future__ import annotations

import httpx
import pytest

from momus.app import build_app
from momus.capabilities import MomusRuntime
from momus.config import MomusConfig

ACT_CAPS = ["momus.scan@v1", "momus.selfaudit@v1", "momus.retest@v1", "momus.scan.external@v1"]
READ_CAPS = ["momus.findings@v1", "momus.intel@v1"]


def _client(tmp_path, monkeypatch, *, prod: bool, token: str | None = None) -> httpx.AsyncClient:
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_SIGNING_KEY_PATH", str(tmp_path / "k"))
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "offline")
    monkeypatch.setenv("AIFACTORY_PROD", "1" if prod else "0")
    monkeypatch.delenv("MOMUS_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("MOMUS_REQUIRE_OPERATOR", raising=False)
    if token is not None:
        monkeypatch.setenv("MOMUS_OPERATOR_TOKEN", token)
    app = build_app(MomusRuntime(MomusConfig.from_env()))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://momus.local")


# ── AUDIT: the operator gate was bypassable through the marketplace invoke path ───────────────
@pytest.mark.asyncio
async def test_act_capabilities_are_gated_on_the_invoke_path(tmp_path, monkeypatch):
    """The audit reproduced POST /scan → 503 while the SAME action succeeded via
    POST /ai-market/v2/invoke {"capability_id": "momus.scan@v1"}. Both must be gated."""
    async with _client(tmp_path, monkeypatch, prod=True) as c:
        assert (await c.post("/scan", json={"target": "self"})).status_code == 503
        for cap in ACT_CAPS:
            r = await c.post("/ai-market/v2/invoke", json={"capability_id": cap, "input": {}})
            assert r.status_code == 503, f"{cap} bypassed the gate: {r.status_code}"


@pytest.mark.asyncio
async def test_act_capabilities_reject_wrong_token_on_invoke_path(tmp_path, monkeypatch):
    async with _client(tmp_path, monkeypatch, prod=True, token="s3cret") as c:
        r = await c.post("/ai-market/v2/invoke", json={"capability_id": "momus.scan@v1", "input": {}},
                         headers={"x-momus-operator": "nope"})
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_act_capabilities_work_with_the_token(tmp_path, monkeypatch):
    async with _client(tmp_path, monkeypatch, prod=True, token="s3cret") as c:
        r = await c.post("/ai-market/v2/invoke",
                         json={"capability_id": "momus.selfaudit@v1", "input": {}},
                         headers={"x-momus-operator": "s3cret"})
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_read_only_capabilities_stay_open_on_the_invoke_path(tmp_path, monkeypatch):
    """The marketplace must keep working for anonymous discovery — only the ACT-y caps are gated."""
    async with _client(tmp_path, monkeypatch, prod=True, token="s3cret") as c:
        for cap in READ_CAPS:
            r = await c.post("/ai-market/v2/invoke", json={"capability_id": cap, "input": {}})
            assert r.status_code == 200, f"{cap} should stay public, got {r.status_code}"
        assert (await c.get("/ai-market/v2/manifest")).status_code == 200


@pytest.mark.asyncio
async def test_gate_off_in_dev_leaves_invoke_open(tmp_path, monkeypatch):
    async with _client(tmp_path, monkeypatch, prod=False) as c:
        r = await c.post("/ai-market/v2/invoke", json={"capability_id": "momus.selfaudit@v1", "input": {}})
        assert r.status_code == 200


# ── AUDIT: recursive self-scan (one request → ~100 nested scans) ──────────────────────────────
def test_probes_never_invoke_momus_own_act_capabilities():
    """A probe that invokes momus.scan@v1 while scanning MOMUS itself recurses. _safe_tools drops
    exactly those capabilities, so the self-target can be probed without amplification."""
    from momus.targets.oracle import _SELF_ACT_CAPABILITIES, _safe_tools
    tools = [
        {"capability_id": "momus.scan@v1"},
        {"capability_id": "momus.selfaudit@v1"},
        {"capability_id": "momus.retest@v1"},
        {"capability_id": "momus.scan.external@v1"},
        {"capability_id": "momus.findings@v1"},      # read-only — safe to invoke
        {"capability_id": "gaia.weather.read@v1"},   # someone else's — safe
    ]
    safe = {t["capability_id"] for t in _safe_tools(tools)}
    assert safe == {"momus.findings@v1", "gaia.weather.read@v1"}
    assert _SELF_ACT_CAPABILITIES.isdisjoint(safe)


@pytest.mark.asyncio
async def test_self_scan_does_not_recurse(tmp_path, monkeypatch):
    """Scan the self-target through the real app and assert the scan count stays at 1 — before the
    fix this produced ~100 nested Scanner.scan executions."""
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_SIGNING_KEY_PATH", str(tmp_path / "k"))
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "offline")
    monkeypatch.setenv("AIFACTORY_PROD", "0")
    runtime = MomusRuntime(MomusConfig.from_env())
    app = build_app(runtime)
    transport = httpx.ASGITransport(app=app)

    # Point the self-target's HTTP client at this very app, so a recursive invoke would really recurse.
    from momus.targets.oracle import OracleTarget
    real_self_target = runtime.self_target

    def patched():
        return OracleTarget("momus-self", "http://momus.local", transport=transport)
    runtime.self_target = patched  # type: ignore[method-assign]

    calls = {"n": 0}
    original_scan = runtime.scanner.scan

    async def counting_scan(*a, **kw):
        calls["n"] += 1
        return await original_scan(*a, **kw)
    runtime.scanner.scan = counting_scan  # type: ignore[method-assign]

    async with httpx.AsyncClient(transport=transport, base_url="http://momus.local") as c:
        r = await c.post("/scan", json={"target": "self"})
        assert r.status_code == 200
    assert calls["n"] == 1, f"self-scan recursed {calls['n']} times"
    runtime.self_target = real_self_target  # type: ignore[method-assign]


# ── AUDIT: dedup key was nondeterministic — the same bug paid again on every rescan ────────────
def test_dedup_key_is_stable_across_volatile_responses(scanner):
    """The old basis digested the full response body, which carries a fresh nonce/timestamp per
    call — so the "identity of the bug" changed every scan and the replay guard never matched."""
    from momus.findings import Evidence, Finding, Outcome, Status

    def mk(resp_digest: str, snippet: str):
        f = Finding(target="oracles", target_kind="oracle", probe="free_tier_ceiling_bypass",
                    category="authz", severity="high", outcome=Outcome.FINDING.value,
                    title="t", detail="d",
                    evidence=Evidence("sha256-req", resp_digest, response_snippet=snippet,
                                      status_code=200),
                    status=Status.RAW.value)
        return scanner.sign_finding(f)

    a = mk("sha256-aaaa", '{"nonce":"1","ts":"12:00:00"}')
    b = mk("sha256-bbbb", '{"nonce":"2","ts":"12:00:05"}')   # same flaw, different response instance
    assert a.dedup_key == b.dedup_key, "dedup must not depend on volatile response content"
    # but a genuinely different flaw still gets its own identity
    c = mk("sha256-cccc", "x")
    c.probe = "manifest_signature_integrity"
    assert c.compute_dedup_key() != a.dedup_key


def test_treasury_recomputes_dedup_and_refuses_a_declared_mismatch(tmp_path, scanner, verifier_a, verifier_b):
    """The scanner signs `dedup_key`, so trusting the declared value let the party being paid pick
    its own dedup identity and escape the replay guard entirely."""
    from momus.economics import BountyLedger, KeyRing, PayoutGate, PayoutState
    from momus.findings import Evidence, Finding, Outcome, Status, Verdict, finding_digest

    kr = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    gate = PayoutGate(kr, BountyLedger(str(tmp_path / "l.jsonl")), crypto_enabled=True, prod=False,
                      cooldown_s=0, external_verifiers={verifier_a.pubkey})

    def mk():
        f = Finding(target="oracles", target_kind="oracle", probe="p", category="authz",
                    severity="high", outcome=Outcome.FINDING.value, title="t", detail="d",
                    evidence=Evidence("sha256-a", "sha256-b", status_code=200),
                    status=Status.RAW.value)
        return scanner.sign_finding(f)

    def conf(vs, f):
        return vs.sign_verdict(Verdict(f.finding_id, finding_digest(f), "confirmed", "replay",
                                       0.95, "r", vs.pubkey[:6], subject_target=f.target, subject_probe=f.probe))

    first = mk()
    d1 = gate.authorize(first, [conf(verifier_a, first), conf(verifier_b, first)], deposit_posted_usd=25)
    assert d1.state == PayoutState.PAID.value

    # Same bug, but the claimant declares a different dedup identity to dodge the replay guard.
    again = mk()
    again.dedup_key = "dedup-i-choose-my-own-identity"
    scanner.sign_finding(again)          # re-signed, so the signature is valid
    d2 = gate.authorize(again, [conf(verifier_a, again), conf(verifier_b, again)], deposit_posted_usd=25)
    assert d2.state == PayoutState.REFUSED.value
    assert any("declared dedup identity does not match" in r for r in d2.reasons)

    # And an honest resubmission of the same bug is refused as a duplicate, not paid twice.
    honest = mk()
    d3 = gate.authorize(honest, [conf(verifier_a, honest), conf(verifier_b, honest)], deposit_posted_usd=25)
    assert d3.state == PayoutState.REFUSED.value
    assert any("already paid" in r for r in d3.reasons)


# ── AUDIT: an UNSIGNED fix verdict released the fixer and conductor shares ─────────────────────
def test_unsigned_fix_verdict_withholds_the_fixer_share(tmp_path, scanner, verifier_a, verifier_b):
    from momus.economics import BountyLedger, KeyRing, PayoutGate
    from momus.findings import Evidence, Finding, Outcome, Status, Verdict, finding_digest

    kr = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    gate = PayoutGate(kr, BountyLedger(str(tmp_path / "l.jsonl")), crypto_enabled=True, prod=False,
                      cooldown_s=0, external_verifiers={verifier_a.pubkey})
    f = Finding(target="oracles", target_kind="oracle", probe="p", category="authz", severity="high",
                outcome=Outcome.FINDING.value, title="t", detail="d",
                evidence=Evidence("sha256-a", "sha256-b", status_code=200), status=Status.RAW.value)
    scanner.sign_finding(f)
    vs = [verifier_a.sign_verdict(Verdict(f.finding_id, finding_digest(f), "confirmed", "replay",
                                          0.95, "r", "a", subject_target=f.target, subject_probe=f.probe)),
          verifier_b.sign_verdict(Verdict(f.finding_id, finding_digest(f), "confirmed", "replay",
                                          0.95, "r", "b", subject_target=f.target, subject_probe=f.probe))]

    for bad_fix, why in [
        ({"finding_id": f.finding_id, "fixed": True}, "unsigned"),
        ({"finding_id": f.finding_id, "fixed": True, "signature": {"value": ""}}, "empty signature"),
    ]:
        out = gate.authorize_split(
            f, vs, participants={"finder": scanner.pubkey, "fixer": "factory", "conductor": "skopos"},
            deposit_posted_usd=25, fix_verdict=bad_fix, deploy_ack={"accepted": True},
            momus_pubkey=verifier_a.pubkey)
        roles = {s["role"]: s for s in out["shares"]}
        assert roles["fixer"]["state"] == "refused", f"{why} fix verdict paid the fixer"
        assert roles["conductor"]["state"] == "refused"
        # and with no momus_pubkey at all it must also withhold
    out = gate.authorize_split(
        f, vs, participants={"finder": scanner.pubkey, "fixer": "factory"},
        deposit_posted_usd=25, fix_verdict={"finding_id": f.finding_id, "fixed": True},
        deploy_ack={"accepted": True}, momus_pubkey="")
    assert {s["role"]: s for s in out["shares"]}["fixer"]["state"] == "refused"


# ── AUDIT: authorize_split settled the finder twice (full pool, then 50%) ──────────────────────
def test_split_settles_each_share_exactly_once(tmp_path, scanner, verifier_a, verifier_b):
    """With a vault this was a real double debit: the base decision paid the whole pool, then the
    finder share paid 50% again."""
    from momus.economics import BountyLedger, KeyRing, PayoutGate
    from momus.findings import Evidence, Finding, Outcome, Status, Verdict, finding_digest
    from momus.settlement import SettlementBackend, SettlementMode
    from momus.vault import UniVault

    vault = UniVault(str(tmp_path / "vault.jsonl"))
    vault.fund(1000.0)
    kr = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    gate = PayoutGate(kr, BountyLedger(str(tmp_path / "l.jsonl")), crypto_enabled=False, prod=False,
                      cooldown_s=0, external_verifiers={verifier_a.pubkey},
                      settlement=SettlementBackend(SettlementMode.UNI, "uni",
                                                   uni_ledger_path=str(tmp_path / "uni.jsonl"),
                                                   vault=vault))
    f = Finding(target="oracles", target_kind="oracle", probe="p", category="authz", severity="high",
                outcome=Outcome.FINDING.value, title="t", detail="d",
                evidence=Evidence("sha256-a", "sha256-b", status_code=200), status=Status.RAW.value)
    scanner.sign_finding(f)
    vault.reserve(f.finding_id, 50.0)
    import json as _json
    fixv = {"finding_id": f.finding_id, "fixed": True}
    fixv["signature"] = verifier_a._signer.sign_payload(
        _json.dumps(fixv, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    out = gate.authorize_split(
        f, [verifier_a.sign_verdict(Verdict(f.finding_id, finding_digest(f), "confirmed", "replay", 0.95, "r", "a", subject_target=f.target, subject_probe=f.probe)),
            verifier_b.sign_verdict(Verdict(f.finding_id, finding_digest(f), "confirmed", "replay", 0.95, "r", "b", subject_target=f.target, subject_probe=f.probe))],
        participants={"finder": scanner.pubkey, "fixer": "factory", "conductor": "skopos"},
        deposit_posted_usd=25, fix_verdict=fixv, deploy_ack={"accepted": True},
        momus_pubkey=verifier_a.pubkey)
    assert out["total_released_usd"] == 50.0
    # exactly $50 left the vault — not $75 (the old double-settle) and not $100
    assert vault.balance == 950.0
    releases = [t for t in vault.journal(50) if t["kind"] == "release"]
    assert sorted(r["amount_usd"] for r in releases) == [7.5, 17.5, 25.0]


# ── AUDIT: probes graded "the contract held" without ever reaching the target ───────────────────
@pytest.mark.asyncio
async def test_rate_limited_probe_is_inconclusive_not_a_pass(scanner):
    """A 429 means the target's own limiter turned the probe away, so nothing was tested. Grading
    that as NO_FINDING let an attacker flood a target's shared bucket and forge a deploy-gate pass."""
    from fastapi import FastAPI, Response
    from momus.engine.scanner import Scanner
    from momus.targets.oracle import OracleTarget

    app = FastAPI()
    manifest = {"protocol_version": "v2", "capabilities_count": 1, "generated_at": "t",
                "tools": [{"name": "c", "capability_id": "c@v1", "product_id": "p", "description": "d",
                           "input_schema": {"type": "object"}, "output_schema": {"type": "object"},
                           "price_per_call_usd": 0.0, "p50_latency_ms": 1, "success_rate_30d": 1.0}],
                "signature": {"algorithm": "ed25519", "value": "AAAA", "public_key": "BBBB"}}

    @app.get("/ai-market/v2/manifest")
    async def m():
        return manifest

    @app.get("/.well-known/ai-market.json")
    async def wk():
        return {"signer_public_key": "BBBB"}

    @app.post("/ai-market/v2/invoke")
    async def inv(body: dict):
        return Response(content='{"detail":"rate limited"}', status_code=429,
                        media_type="application/json")

    tgt = OracleTarget("limited", "http://limited.local", transport=httpx.ASGITransport(app=app))
    report = await Scanner(scanner, llm=None).scan([tgt], only_probes=["malformed_input_hardening"])
    rec = next(r for r in report.records if r.probe == "malformed_input_hardening")
    assert rec.outcome == "inconclusive", f"a fully rate-limited probe must not pass: {rec.title}"


@pytest.mark.asyncio
async def test_injection_probe_refusal_is_inconclusive(scanner):
    """The deployed Metis requires a bearer token on /v1/verify, so 401/404 used to fall through to
    'boundary held' — a pass for a test that never reached the model."""
    from fastapi import FastAPI, Response
    from momus.engine.scanner import Scanner
    from momus.targets.injection import InjectionTarget

    app = FastAPI()

    @app.post("/v1/verify")
    async def verify(body: dict):
        return Response(content='{"detail":"unauthorized"}', status_code=401,
                        media_type="application/json")

    @app.post("/ai-market/v2/invoke")
    async def inv(body: dict):
        return Response(content='{"detail":"unauthorized"}', status_code=401,
                        media_type="application/json")

    tgt = InjectionTarget("gated", "http://gated.local", transport=httpx.ASGITransport(app=app))
    report = await Scanner(scanner, llm=None).scan([tgt])
    assert report.counts["no_finding"] == 0, "a refused injection probe must not be graded a pass"
    assert report.counts["inconclusive"] == report.counts["probes"]


# ── AUDIT: MOMUS_SELF_ATTACK was dead configuration ────────────────────────────────────────────
@pytest.mark.asyncio
async def test_self_attack_off_refuses_sibling_probing(tmp_path, monkeypatch):
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_SIGNING_KEY_PATH", str(tmp_path / "k"))
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "offline")
    monkeypatch.setenv("AIFACTORY_PROD", "0")
    monkeypatch.setenv("MOMUS_SELF_ATTACK", "0")
    monkeypatch.setenv("MOMUS_TARGET_ORACLES_URL", "http://oracles.local")
    runtime = MomusRuntime(MomusConfig.from_env())
    assert runtime.config.self_attack is False
    app = build_app(runtime)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://momus.local") as c:
        r = await c.post("/scan", json={"target": "oracles"})
        assert r.status_code == 403 and "MOMUS_SELF_ATTACK=0" in r.json()["detail"]
        # a SELF scan is still allowed — the switch is about probing siblings
        assert (await c.post("/scan", json={"target": "self"})).status_code == 200


# ── AUDIT: /health lied about holding the treasury key, and hit DeepSeek on every public request ─
@pytest.mark.asyncio
async def test_health_reports_the_real_treasury_key_state(tmp_path, monkeypatch):
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_SIGNING_KEY_PATH", str(tmp_path / "k"))
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "offline")
    monkeypatch.setenv("AIFACTORY_PROD", "0")
    monkeypatch.setenv("MOMUS_TREASURY_KEY_PATH", str(tmp_path / "treasury.key"))
    app = build_app(MomusRuntime(MomusConfig.from_env()))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://momus.local") as c:
        body = (await c.get("/health")).json()
        # Co-locating the key is a misconfiguration; /health must SAY so instead of hardcoding false.
        assert body["holds_treasury_key"] is True


@pytest.mark.asyncio
async def test_health_caches_the_provider_probe(tmp_path, monkeypatch):
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_SIGNING_KEY_PATH", str(tmp_path / "k"))
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "offline")
    monkeypatch.setenv("AIFACTORY_PROD", "0")
    runtime = MomusRuntime(MomusConfig.from_env())
    calls = {"n": 0}
    original = runtime.provider.health

    async def counting():
        calls["n"] += 1
        return await original()
    runtime.provider.health = counting  # type: ignore[method-assign]
    app = build_app(runtime)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://momus.local") as c:
        for _ in range(5):
            assert (await c.get("/health")).status_code == 200
    assert calls["n"] == 1, f"the provider was probed {calls['n']} times for 5 public health hits"


# ── AUDIT: the injection target was silently dropped by a name collision ───────────────────────
def test_injection_target_gets_a_distinct_name():
    from momus.config import TargetEndpoint
    from momus.targets import build_targets

    class _Cfg:
        targets = [TargetEndpoint(name="metis", base_url="http://metis:9100", kind="metis")]

    names = [t.name for t in build_targets(_Cfg())]
    assert len(names) == len(set(names)), f"a name collision silently drops a target: {names}"
    assert "metis-injection" in names


# ── AUDIT: unbounded in-memory maps (OOM through the public invoke route) ───────────────────────
def test_scan_and_finding_maps_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_SIGNING_KEY_PATH", str(tmp_path / "k"))
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "offline")
    runtime = MomusRuntime(MomusConfig.from_env())
    from momus.engine.scanner import ScanReport
    for i in range(runtime.SCANS_MAX + 25):
        runtime._store(ScanReport(scan_id=f"scan-{i}", started_at="t", finished_at="t",
                                  targets=["x"], findings=[], records=[], counts={}))
    assert len(runtime._scans) <= runtime.SCANS_MAX
    assert "scan-0" not in runtime._scans          # oldest evicted first
    assert f"scan-{runtime.SCANS_MAX + 24}" in runtime._scans


def test_deploy_gate_survives_a_momus_restart(tmp_path, monkeypatch):
    """A MOMUS restart must not make an open finding ungateable.

    `_findings_by_id` is a bounded in-process cache. When it is empty the gate used to answer
    `unknown_finding`, SKOPOS read that as "not fixed", retried to exhaustion and escalated — so a
    restart alone could permanently block a real remediation. The persistent corpus outlives the
    process, so the gate consults it. Found by running the live chain across a redeploy."""
    import asyncio

    from momus.capabilities import MomusRuntime
    from momus.config import MomusConfig
    from momus.findings import Evidence, Finding, FindingSigner

    data = tmp_path / "d"
    data.mkdir()
    monkeypatch.setenv("MOMUS_DATA_DIR", str(data))
    rt = MomusRuntime(MomusConfig.from_env())

    signer = FindingSigner(str(data / "k"))
    f = signer.sign_finding(Finding(
        target="canary", target_kind="oracle", probe="free_tier_ceiling_bypass",
        category="billing", severity="high", outcome="finding",
        title="ceiling not enforced", detail="d",
        evidence=Evidence(request_digest="r", response_digest="x", status_code=200)))
    rt.findings_db.record_finding(f)

    rt._findings_by_id.clear()          # exactly what a restart leaves behind
    assert rt._recall(f.finding_id) is not None, "the gate lost a finding the corpus still holds"

    # And the gate itself no longer reports 'unknown_finding' for it. The canary target is not
    # configured here, so it fails on the TARGET — which is the honest next error, not a lost bug.
    out = asyncio.run(rt.retest_finding(f.finding_id))
    assert out.get("error") != "unknown_finding"


# ── AUDIT: a split that released nothing still burned the claim ────────────────────────────────
def test_split_that_releases_nothing_stays_retryable(tmp_path, scanner, verifier_a, verifier_b):
    """The base decision was stamped PAID before any share settled, so a split with no payable
    recipient consumed the dedup identity and every retry was refused as a duplicate."""
    from momus.economics import BountyLedger, KeyRing, PayoutGate, PayoutState
    from momus.findings import Evidence, Finding, Outcome, Status, Verdict, finding_digest
    from momus.settlement import SettlementBackend, SettlementMode
    from momus.vault import UniVault

    vault = UniVault(str(tmp_path / "vault.jsonl"))
    vault.fund(1000.0)
    kr = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    gate = PayoutGate(kr, BountyLedger(str(tmp_path / "l.jsonl")), crypto_enabled=False, prod=False,
                      cooldown_s=0, external_verifiers={verifier_a.pubkey},
                      settlement=SettlementBackend(SettlementMode.UNI, "uni",
                                                   uni_ledger_path=str(tmp_path / "uni.jsonl"),
                                                   vault=vault))
    f = Finding(target="oracles", target_kind="oracle", probe="p", category="authz", severity="high",
                outcome=Outcome.FINDING.value, title="t", detail="d",
                evidence=Evidence("sha256-a", "sha256-b", status_code=200), status=Status.RAW.value)
    scanner.sign_finding(f)
    vs = [verifier_a.sign_verdict(Verdict(f.finding_id, finding_digest(f), "confirmed", "replay",
                                          0.95, "r", "a", subject_target=f.target, subject_probe=f.probe)),
          verifier_b.sign_verdict(Verdict(f.finding_id, finding_digest(f), "confirmed", "replay",
                                          0.95, "r", "b", subject_target=f.target, subject_probe=f.probe))]

    # No recipient for any role → nothing can be released.
    out = gate.authorize_split(f, vs, participants={}, deposit_posted_usd=25)
    assert out["total_released_usd"] == 0.0
    assert out["base_state"] == PayoutState.HELD.value, "an unsettled split must not report paid"

    # The claim survived: the same finding can be split again once a recipient exists.
    vault.reserve(f.finding_id, 50.0)
    retry = gate.authorize_split(f, vs, participants={"finder": scanner.pubkey},
                                 deposit_posted_usd=25)
    assert retry["total_released_usd"] > 0, "retry was refused as a duplicate"
    assert retry["base_state"] == PayoutState.PAID.value

    # …and only once — the second successful split is the one that consumed the identity.
    third = gate.authorize_split(f, vs, participants={"finder": scanner.pubkey},
                                 deposit_posted_usd=25)
    assert third["total_released_usd"] == 0.0
    assert third["base_state"] == PayoutState.REFUSED.value
