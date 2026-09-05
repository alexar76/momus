"""Shared fixtures — throwaway keys and in-process oracle apps for probing over ASGI.

Every test uses tmp_path so no key or ledger touches the repo, and the whole suite runs offline:
no network, no real model, no live sibling service.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

from oracle_core import Capability, OracleSpec, create_app
from momus.findings import FindingSigner


@pytest.fixture
def scanner(tmp_path):
    return FindingSigner(str(tmp_path / "scanner.key"))


@pytest.fixture
def treasury_key_path(tmp_path):
    return str(tmp_path / "treasury.key")


@pytest.fixture
def verifier_a(tmp_path):
    return FindingSigner(str(tmp_path / "verifier_a.key"))


@pytest.fixture
def verifier_b(tmp_path):
    return FindingSigner(str(tmp_path / "verifier_b.key"))


def _good_oracle_app(tmp_path) -> FastAPI:
    """A well-behaved oracle-core oracle: enforces its ceiling, signs its receipts."""
    def handler(inp):
        return {"echo": inp}

    cap = Capability(
        capability_id="good.compute@v1", description="well-behaved",
        handler=handler, product_id="good", price_per_call_usd=0.0,
        input_schema={"type": "object", "properties": {"n": {"type": "integer", "maximum": 100}}},
        free_tier_max={"n": 100},
    )
    spec = OracleSpec(
        name="Good", product_id="good", description="test", public_url="http://good.local",
        categories=["test"], capabilities=[cap], signing_key_path=str(tmp_path / "good.key"),
    )
    return create_app(spec, cors_origins="*")


def _broken_oracle_app() -> FastAPI:
    """A broken oracle: unsigned/unverifiable manifest, serves over-ceiling unpaid, no receipt."""
    app = FastAPI()
    manifest = {
        "protocol_version": "v2", "capabilities_count": 1, "generated_at": "2026-01-01T00:00:00Z",
        "tools": [{
            "name": "c", "capability_id": "c@v1", "product_id": "p", "description": "d",
            "input_schema": {"type": "object", "properties": {"n": {"type": "integer", "maximum": 100}}},
            "output_schema": {"type": "object"}, "price_per_call_usd": 0.05, "p50_latency_ms": 1,
            "success_rate_30d": 1.0, "free_tier_max": {"n": 100},
        }],
        "signature": {"algorithm": "ed25519", "value": "AAAA", "public_key": "BBBB"},
    }

    @app.get("/ai-market/v2/manifest")
    async def m():
        return manifest

    @app.get("/.well-known/ai-market.json")
    async def wk():
        return {"signer_public_key": "BBBB"}

    @app.post("/ai-market/v2/invoke")
    async def inv(body: dict):
        return {"capability_id": body.get("capability_id"), "output": {"served": True}, "price_usd": 0.05}

    return app


@pytest.fixture
def good_oracle_transport(tmp_path):
    return httpx.ASGITransport(app=_good_oracle_app(tmp_path))


@pytest.fixture
def broken_oracle_transport():
    return httpx.ASGITransport(app=_broken_oracle_app())
