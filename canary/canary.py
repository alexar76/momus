"""MOMUS canary — a deliberately non-conforming service, for validating the detection pipeline.

Why this exists: the ecosystem's real components pass their own contract checks, which is the point
of building them carefully — but it means a clean MOMUS scan proves nothing about MOMUS. A detection
pipeline you have never seen fire is a detection pipeline you cannot trust. So this is the EICAR
file of the AI economy: a service that advertises a contract and then knowingly breaks it, so the
whole loop (find → verify → fix → re-test gate → deploy → split) can be exercised end to end
against a REAL finding.

Two things must stay true, and both are load-bearing for honesty:

  * The FINDING is genuine — MOMUS detects an actual contract violation with no special-casing, and
    signs it with its real scanner key. Nothing about the probe path is faked.
  * The TARGET is a purpose-built fixture, NOT a production service that was found broken. Any
    document reporting a canary cycle must say so plainly; presenting it as a real ecosystem
    vulnerability would be a lie.

The canary advertises `free_tier_max: {n: 100}` and a positive price, then serves over-ceiling
unpaid calls with an unsigned receipt — violations MOMUS's `free_tier_ceiling_bypass`,
`receipt_signature_integrity` and (for the hub probe) `unpaid_invoke_refused` strategies detect.

`POST /canary/fix` flips it to correct behaviour, standing in for "the AI-Factory shipped a patch
and the service was redeployed" — which is exactly what MOMUS's re-test gate must then confirm.
`POST /canary/break` puts it back. Both control routes are token-gated so the canary cannot be
flipped by a passer-by, and it binds to loopback only.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Header, HTTPException, Response

app = FastAPI(title="MOMUS canary (deliberately non-conforming fixture)")

# Starts BROKEN: the pipeline should find something on the very first scan.
STATE = {"fixed": False}

_CONTROL_TOKEN = os.environ.get("CANARY_TOKEN", "").strip()

MANIFEST = {
    "protocol_version": "v2",
    "capabilities_count": 1,
    "generated_at": "2026-01-01T00:00:00Z",
    "tools": [{
        "name": "canary.compute",
        "capability_id": "canary.compute@v1",
        "product_id": "canary",
        "description": "A deliberately non-conforming capability, for validating MOMUS end to end.",
        "input_schema": {"type": "object", "properties": {"n": {"type": "integer", "maximum": 100}}},
        "output_schema": {"type": "object"},
        "price_per_call_usd": 0.05,
        "p50_latency_ms": 1,
        "success_rate_30d": 1.0,
        # Declares a free-tier ceiling it does not enforce while broken.
        "free_tier_max": {"n": 100},
    }],
    # A signature that does not verify — deliberately, so manifest integrity fails too.
    "signature": {"algorithm": "ed25519", "value": "AAAA", "public_key": "BBBB"},
}


def _guard(token: str | None) -> None:
    if not _CONTROL_TOKEN or (token or "").strip() != _CONTROL_TOKEN:
        raise HTTPException(status_code=403, detail="canary control token required")


@app.get("/ai-market/v2/manifest")
async def manifest() -> dict:
    return MANIFEST


@app.get("/.well-known/ai-market.json")
async def well_known() -> dict:
    return {"signer_public_key": "BBBB", "name": "MOMUS canary", "protocol_version": "v2"}


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "momus-canary", "conforming": STATE["fixed"],
            "note": "purpose-built fixture for validating the MOMUS pipeline; not a real service"}


# response_model=None: this route returns either a plain dict or a raw Response (the 402 refusal),
# and FastAPI cannot build a response model from that union.
@app.post("/ai-market/v2/invoke", response_model=None)
async def invoke(body: dict):
    n = ((body or {}).get("input") or {}).get("n", 0)
    if STATE["fixed"]:
        # Conforming behaviour: refuse an unpaid over-ceiling call with 402, as oracle-core does.
        if isinstance(n, (int, float)) and not isinstance(n, bool) and n > 100:
            return Response(
                content='{"error":"free_tier_exceeded","detail":"n exceeds the free-tier ceiling of 100",'
                        '"ceiling":100}',
                status_code=402, media_type="application/json")
    # Broken behaviour: serve anything, unpaid, with no signed receipt.
    return {"capability_id": (body or {}).get("capability_id"), "output": {"served": True, "n": n},
            "price_usd": 0.05}


@app.post("/canary/fix")
async def fix(x_canary_token: str | None = Header(default=None)) -> dict:
    _guard(x_canary_token)
    STATE["fixed"] = True
    return {"conforming": True, "note": "stands in for 'the Factory shipped a patch and it redeployed'"}


@app.post("/canary/break")
async def break_it(x_canary_token: str | None = Header(default=None)) -> dict:
    _guard(x_canary_token)
    STATE["fixed"] = False
    return {"conforming": False}


def main() -> None:
    import uvicorn
    # Bind 0.0.0.0 *inside the container* so sibling containers (MOMUS) can reach it over the
    # Docker network. Keeping the canary off the public internet is the job of the PORT MAPPING
    # ("127.0.0.1:9450:9450" in the compose file), not of the app bind — binding 127.0.0.1 here
    # would make it unreachable from any other container, which is the bug this comment replaces.
    uvicorn.run(app, host=os.environ.get("CANARY_HOST", "0.0.0.0"),
                port=int(os.environ.get("CANARY_PORT", "9450")), log_level="warning")


if __name__ == "__main__":
    main()
