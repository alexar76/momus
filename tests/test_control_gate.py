"""Control routes must be operator-gated in production.

The public TLS edge proxies the MOMUS API on the same origin as the landing page, so anything that
makes MOMUS *act* — probe a sibling service, spend the LLM budget, open a remediation ticket that
can end in a redeploy, or accept a peer's A2A task — must not be triggerable by an anonymous caller.
Read-only routes stay public so the panel and the monitor still show live state to anyone.
"""

from __future__ import annotations

import httpx
import pytest

from momus.app import build_app
from momus.capabilities import MomusRuntime
from momus.config import MomusConfig

CONTROL_POSTS = ["/scan", "/selfaudit", "/retest", "/remediate", "/a2a/tasks"]
PUBLIC_GETS = ["/health", "/providers", "/findings", "/intel"]


def _client(tmp_path, monkeypatch, *, prod: bool, token: str | None = None,
            require: str | None = None) -> httpx.AsyncClient:
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_SIGNING_KEY_PATH", str(tmp_path / "k"))
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "offline")
    monkeypatch.setenv("AIFACTORY_PROD", "1" if prod else "0")
    monkeypatch.delenv("MOMUS_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("MOMUS_REQUIRE_OPERATOR", raising=False)
    if token is not None:
        monkeypatch.setenv("MOMUS_OPERATOR_TOKEN", token)
    if require is not None:
        monkeypatch.setenv("MOMUS_REQUIRE_OPERATOR", require)
    app = build_app(MomusRuntime(MomusConfig.from_env()))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://momus.local")


@pytest.mark.asyncio
async def test_dev_leaves_control_open(tmp_path, monkeypatch):
    """Local development stays frictionless — no token needed when not in prod."""
    async with _client(tmp_path, monkeypatch, prod=False) as c:
        assert (await c.get("/health")).json()["control_gated"] is False
        r = await c.post("/scan", json={"target": "self"})
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_prod_refuses_control_without_token(tmp_path, monkeypatch):
    """Prod + no token configured → fail CLOSED (503), never silently open."""
    async with _client(tmp_path, monkeypatch, prod=True) as c:
        assert (await c.get("/health")).json()["control_gated"] is True
        for path in CONTROL_POSTS:
            r = await c.post(path, json={"target": "self", "finding_id": "x", "skill": "scan"})
            assert r.status_code == 503, f"{path} should fail closed, got {r.status_code}"


@pytest.mark.asyncio
async def test_prod_rejects_wrong_token(tmp_path, monkeypatch):
    async with _client(tmp_path, monkeypatch, prod=True, token="s3cret") as c:
        for path in CONTROL_POSTS:
            r = await c.post(path, json={"target": "self", "finding_id": "x", "skill": "scan"},
                             headers={"x-momus-operator": "wrong"})
            assert r.status_code == 403, f"{path} should 403, got {r.status_code}"


@pytest.mark.asyncio
async def test_prod_accepts_correct_token(tmp_path, monkeypatch):
    async with _client(tmp_path, monkeypatch, prod=True, token="s3cret") as c:
        h = {"x-momus-operator": "s3cret"}
        assert (await c.post("/scan", json={"target": "self"}, headers=h)).status_code == 200
        assert (await c.post("/selfaudit", headers=h)).status_code == 200
        # unknown finding is a 200-with-error payload, not an auth failure
        assert (await c.post("/retest", json={"finding_id": "nope"}, headers=h)).status_code == 200


@pytest.mark.asyncio
async def test_read_only_routes_stay_public_in_prod(tmp_path, monkeypatch):
    """The landing panel and the Alien Monitor must keep working for anonymous viewers."""
    async with _client(tmp_path, monkeypatch, prod=True, token="s3cret") as c:
        for path in PUBLIC_GETS:
            r = await c.get(path)
            assert r.status_code == 200, f"{path} should stay public, got {r.status_code}"
        # the AIMarket surface stays public too — that is how the marketplace federates
        assert (await c.get("/ai-market/v2/manifest")).status_code == 200
        assert (await c.get("/.well-known/agent-card.json")).status_code == 200


@pytest.mark.asyncio
async def test_explicit_override_can_gate_dev_or_open_prod(tmp_path, monkeypatch):
    # force the gate ON outside prod
    async with _client(tmp_path, monkeypatch, prod=False, require="1") as c:
        assert (await c.get("/health")).json()["control_gated"] is True
        assert (await c.post("/scan", json={"target": "self"})).status_code == 503
    # and explicitly OFF inside prod (an operator's deliberate choice)
    async with _client(tmp_path, monkeypatch, prod=True, require="0") as c:
        assert (await c.get("/health")).json()["control_gated"] is False
        assert (await c.post("/scan", json={"target": "self"})).status_code == 200


@pytest.mark.asyncio
async def test_a2a_peer_needs_the_token_in_prod(tmp_path, monkeypatch):
    """A2A is agent-to-agent, not public: a peer authenticates with the shared operator token."""
    async with _client(tmp_path, monkeypatch, prod=True, token="s3cret") as c:
        anon = await c.post("/a2a/tasks", json={"skill": "scan", "input": {"target": "self"}})
        assert anon.status_code == 403
        ok = await c.post("/a2a/tasks", json={"skill": "scan", "input": {"target": "self"}},
                          headers={"x-momus-operator": "s3cret"})
        assert ok.status_code == 200 and ok.json()["state"] == "completed"


# --- 2026-09 re-audit: one of four comparisons of the same secret was not constant-time ---

def test_every_operator_token_comparison_is_constant_time():
    """Inventory guard over the source, because the odd one out is invisible by inspection.

    `_operator_ok` (the disclosure tier: do you see unredacted reproducers of still-unfixed
    findings?) compared MOMUS_OPERATOR_TOKEN with `==`, while `_require_operator`, the invoke
    middleware and `/intel/refresh` all used hmac.compare_digest for the very same secret.
    `==` short-circuits on the first differing byte, so an anonymous read turned into a
    prefix oracle for the token that unlocks /scan, /verify/replay, /remediate and /a2a/tasks.

    Asserted structurally rather than by timing: a timing test on a byte-compare is flaky and
    would be the kind of guard that quietly stops meaning anything.
    """
    import ast
    import pathlib

    src = pathlib.Path(__file__).resolve().parents[1] / "momus" / "app.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))

    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            continue
        rendered = ast.unparse(node)
        # Any equality whose either side is the operator token or the supplied header.
        if ("token" in rendered and "supplied" in rendered) or "MOMUS_OPERATOR_TOKEN" in rendered:
            offenders.append((node.lineno, rendered))
    assert not offenders, (
        "operator-token comparisons that are not hmac.compare_digest: " f"{offenders}"
    )
