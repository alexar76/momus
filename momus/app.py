"""MOMUS FastAPI app — oracle-core AIMarket surface + red-team control routes.

The AIMarket v2 surface (/.well-known, /ai-market/v2/manifest, /ai-market/v2/invoke) comes for
free from oracle-core. On top we mount the live-panel routes the frontend and the Alien Monitor
poll: /health, /providers, /scan, /selfaudit, /findings, /scan/{id}. All of them are read-only or
run safe probes; none can move funds or authorize a payout (that is the separate Treasury service).
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from oracle_core import create_app
from oracle_core.app import client_key
from oracle_core.ratelimit import RateLimiter
from pydantic import BaseModel, Field

from momus import __version__
from momus.capabilities import MomusRuntime, build_spec
from momus.config import MomusConfig
from momus.providers import provider_choices
from momus.warden_feed import feed_enabled as warden_feed_enabled
from momus.warden_reports import ReportRefused
from momus.warden_reports import reports_enabled as warden_reports_enabled
from momus.warden_reports import validate as validate_report


class ScanRequest(BaseModel):
    target: str = Field("self", description="allowlisted target id, or 'self'")
    probes: list[str] | None = None


def build_app(runtime: MomusRuntime | None = None) -> FastAPI:
    runtime = runtime or MomusRuntime(MomusConfig.from_env())
    spec = build_spec(runtime)
    cfg = runtime.config

    scan_limiter = RateLimiter(cfg.scan_rate_limit)
    aux_limiter = RateLimiter(cfg.invoke_rate_limit)

    def _limit(limiter: RateLimiter, request: Request) -> None:
        if not limiter.allow(client_key(request)):
            raise HTTPException(status_code=429, detail="rate limited")

    # Control routes (anything that makes MOMUS *act*: probe a sibling, spend LLM budget, open a
    # remediation ticket, accept a peer's task) are operator-gated in production. Read-only routes
    # stay public so the landing panel and the monitor can show live state to anyone.
    #
    # This matters because the public TLS edge proxies the API on the same origin: without this
    # gate an anonymous caller could make the deployed MOMUS scan sibling services in a loop, burn
    # the DeepSeek key, or dispatch a remediation task that ends in a redeploy. Fail-closed: in
    # prod, no token configured means the control routes are refused outright rather than open.
    def _control_gated() -> bool:
        explicit = os.environ.get("MOMUS_REQUIRE_OPERATOR", "").strip().lower()
        if explicit in ("1", "true", "yes", "on"):
            return True
        if explicit in ("0", "false", "no", "off"):
            return False
        return cfg.prod

    def _require_operator(request: Request) -> None:
        if not _control_gated():
            return
        token = os.environ.get("MOMUS_OPERATOR_TOKEN", "").strip()
        supplied = (request.headers.get("x-momus-operator") or "").strip()
        if not token:
            raise HTTPException(
                status_code=503,
                detail="control routes are operator-gated in production but MOMUS_OPERATOR_TOKEN "
                       "is unset — refusing (fail-closed)")
        if supplied != token:
            raise HTTPException(status_code=403, detail="operator token required")

    # Capability ids that make MOMUS ACT (probe siblings, spend LLM budget, re-test). They are
    # reachable through oracle-core's /ai-market/v2/invoke, which bypassed the route-level operator
    # gate entirely — the audit reproduced `POST /ai-market/v2/invoke {"capability_id":
    # "momus.scan@v1", …}` succeeding while `POST /scan` correctly 503'd. A capability handler only
    # receives the input dict, never the request, so the check has to live at the HTTP boundary.
    _ACT_CAPABILITIES = {
        "momus.scan@v1", "momus.scan.external@v1", "momus.selfaudit@v1", "momus.retest@v1",
    }

    def extra(app: FastAPI, proto) -> None:
        app.state.runtime = runtime

        @app.middleware("http")
        async def gate_act_capabilities(request: Request, call_next):
            """Enforce the operator gate on the marketplace invoke path, not just the convenience
            routes. Reads the body, checks the capability id, and re-injects the body so the
            downstream handler still sees it."""
            if request.method != "POST" or not request.url.path.endswith("/ai-market/v2/invoke"):
                return await call_next(request)
            if not _control_gated():
                return await call_next(request)
            body = await request.body()

            async def _receive() -> dict[str, Any]:
                return {"type": "http.request", "body": body, "more_body": False}

            request._receive = _receive  # type: ignore[attr-defined]  (re-injection)
            try:
                import json as _json
                cap = str((_json.loads(body or b"{}") or {}).get("capability_id") or "")
            except (ValueError, TypeError):
                cap = ""
            if cap in _ACT_CAPABILITIES:
                token = os.environ.get("MOMUS_OPERATOR_TOKEN", "").strip()
                supplied = (request.headers.get("x-momus-operator") or "").strip()
                from fastapi.responses import JSONResponse
                if not token:
                    return JSONResponse(status_code=503, content={
                        "detail": f"{cap} is operator-gated in production but MOMUS_OPERATOR_TOKEN "
                                  f"is unset — refusing (fail-closed)"})
                if supplied != token:
                    return JSONResponse(status_code=403, content={
                        "detail": f"{cap} makes MOMUS act (probes siblings / spends budget) and "
                                  f"requires the operator token in production"})
            return await call_next(request)

        # Cache the provider health: /health used to fire an authenticated DeepSeek request on
        # EVERY public hit, so anyone could turn MOMUS into a proxy that hammers the ecosystem's
        # shared API key at their own request rate.
        _prov_cache: dict[str, Any] = {"at": 0.0, "value": None}
        _PROV_TTL = 60.0

        @app.get("/health")
        async def health(request: Request) -> dict[str, Any]:
            _limit(aux_limiter, request)
            import time as _t
            if _prov_cache["value"] is None or (_t.monotonic() - _prov_cache["at"]) > _PROV_TTL:
                _prov_cache["value"] = await runtime.provider.health()
                _prov_cache["at"] = _t.monotonic()
            prov = _prov_cache["value"]
            return {
                "status": "ok", "service": "momus", "version": __version__,
                "targets": runtime.target_names(),
                "provider": prov,
                "crypto_enabled": cfg.crypto,
                "prod": cfg.prod,
                "self_attack": cfg.self_attack,
                # MOMUS holds ONLY the scanner key; it never holds the treasury key. Surfaced so a
                # viewer can confirm the separation from the outside.
                "scanner_pubkey": runtime.signer.pubkey,
                # The REAL condition. This was hardcoded to False (`… and False`), so an operator
                # who co-located the treasury key still saw "false" — hiding the exact
                # misconfiguration this field exists to expose.
                "holds_treasury_key": bool(os.environ.get("MOMUS_TREASURY_KEY_PATH", "").strip()),
                # MOMUS's own vulnerability corpus (SQLite by default, Postgres when a DSN is set).
                "corpus": runtime.corpus_stats(),
                # True when control routes need an operator token (the prod default) — the live
                # panel reads this to disable the action buttons instead of showing a 403.
                "control_gated": _control_gated(),
                "settlement": __import__("momus.settlement", fromlist=["x"]).SettlementBackend
                              .from_env(crypto_enabled=cfg.crypto).describe(),
            }

        @app.get("/providers")
        async def providers() -> dict[str, Any]:
            return {"selected": {"provider": runtime.provider.kind.value, "model": runtime.provider.model},
                    "choices": provider_choices()}

        @app.post("/scan")
        async def scan(body: ScanRequest, request: Request) -> dict[str, Any]:
            _require_operator(request)
            _limit(scan_limiter, request)
            # The HTTP control route only ever runs INTERNAL / self scans (the free tier). A paid
            # external scan goes through the metered /ai-market/v2/invoke path so it is billed and
            # rate-limited by the marketplace machinery, not this convenience endpoint.
            target = body.target
            if target not in ("self", "momus", "momus-self") and runtime.target(target) is None:
                raise HTTPException(status_code=404, detail=f"unknown target; known: {runtime.target_names()}")
            try:
                report = await runtime.run_scan([target], only_probes=body.probes)
            except PermissionError as exc:
                # The self-attack switch is off: a clear refusal, not a 500.
                raise HTTPException(status_code=403, detail=str(exc)) from None
            from momus.capabilities import _report_summary
            return _report_summary(report)

        @app.post("/selfaudit")
        async def selfaudit(request: Request) -> dict[str, Any]:
            _require_operator(request)
            _limit(scan_limiter, request)
            handler = None
            for cap in spec.capabilities:
                if cap.capability_id == "momus.selfaudit@v1":
                    handler = cap.handler
                    break
            if handler is None:
                raise HTTPException(status_code=500, detail="selfaudit capability missing")
            return await handler({})

        @app.get("/findings")
        async def findings(request: Request, limit: int = 50) -> dict[str, Any]:
            _limit(aux_limiter, request)
            return {"count": len(runtime.recent_findings(limit)),
                    "findings": runtime.recent_findings(limit),
                    "scanner_pubkey": runtime.signer.pubkey}

        @app.get("/intel")
        async def intel(request: Request) -> dict[str, Any]:
            _limit(aux_limiter, request)
            return runtime.intel_summary()

        @app.get("/warden/threat-feed", response_model=None)
        async def warden_threat_feed(request: Request):
            """The signed threat feed ARGUS's WARDEN firewall consumes — red team feeding blue team.

            Public and read-only ON PURPOSE: WARDEN verifies the document itself (Ed25519 over the
            RFC 8785 canonical form, plus a freshness window), so authenticity does not depend on who
            fetched it. Gating it behind a token would only mean fewer installs are protected while
            adding no security the signature does not already provide.

            Opt-in on BOTH sides. MOMUS publishes only when MOMUS_WARDEN_FEED=1, and ARGUS ships with
            no feed URL, so an operator must choose to trust this key. Nothing is pushed to anybody.
            """
            _limit(aux_limiter, request)
            if not warden_feed_enabled():
                # 404, not 403: an operator who did not enable publishing has no feed, and saying
                # "forbidden" would imply one exists behind a permission.
                raise HTTPException(status_code=404,
                                    detail="threat-feed publishing is disabled "
                                           "(set MOMUS_WARDEN_FEED=1 to publish)")
            return runtime.warden_threat_feed()

        @app.post("/warden/report", response_model=None)
        async def warden_report(body: dict, request: Request):
            """A field install (an ARGUS) reports a hostile third-party server it met.

            Accepts INFORMATION, grants NO authority. The lead is recorded, deduped and ranked; it
            reaches MOMUS's signed feed only after MOMUS confirms it with its own probes, and probing
            a new host still requires an operator to register it as a target. Without that boundary
            this endpoint would make MOMUS an open scanning relay any stranger could aim at any host.
            """
            _limit(scan_limiter, request)          # the tighter bucket: this one writes
            if not warden_reports_enabled():
                raise HTTPException(status_code=404,
                                    detail="threat reporting is disabled "
                                           "(set MOMUS_WARDEN_REPORTS=1 to accept reports)")
            try:
                suspicion = validate_report(
                    body or {}, first_party_targets=tuple(runtime.target_names()))
            except ReportRefused as exc:
                # 422 with the reason: a reporter that cannot see why it was refused will either
                # give up or retry the same broken payload forever.
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            return runtime.submit_warden_report(suspicion)

        @app.get("/warden/reports")
        async def warden_reports(request: Request, limit: int = 50) -> dict[str, Any]:
            """The triage queue, most-corroborated first. OPERATOR-ONLY, and not by habit.

            Every lead here is an UNVERIFIED accusation against a NAMED third party. Serving that
            publicly under our own domain would publish unproven claims about other people's
            services, and it would hand anybody a griefing tool: report a competitor and watch the
            allegation appear on MOMUS's public surface. Intake is public so any field install can
            report; the queue is private until MOMUS has confirmed something with its own probes.
            Caught by verifying the live deployment rather than by reading the code."""
            _require_operator(request)
            _limit(aux_limiter, request)
            if not warden_reports_enabled():
                raise HTTPException(status_code=404, detail="threat reporting is disabled")
            # Nest the stats: spreading them here clobbered the `leads` LIST with the leads
            # COUNT, because both dicts use that key. Caught by the queue test.
            # fence=True: the reporter's free text comes back marked as untrusted, so a
            # future consumer (a triage UI, an LLM summariser) cannot mistake it for ours.
            return {"leads": runtime.warden_report_leads(limit, fence=True),
                    "stats": runtime.warden_report_stats(),
                    "note": "every lead here is an UNVERIFIED report from the field; none of "
                            "them is in MOMUS's signed feed"}

        @app.get("/warden/threat-feed/summary")
        async def warden_threat_feed_summary(request: Request) -> dict[str, Any]:
            """What is in the feed, what was REFUSED and why, and the key to pin.

            The refusals are the interesting half: a finding silently missing from the feed is
            indistinguishable from MOMUS having found nothing."""
            _limit(aux_limiter, request)
            return runtime.warden_feed_summary()

        @app.post("/intel/refresh")
        async def intel_refresh(request: Request) -> dict[str, Any]:
            # Fetching the outside world is a deliberate, operator-gated action — never triggerable
            # by an anonymous caller. It requires the operator token AND MOMUS_THREAT_INTEL=1.
            _limit(scan_limiter, request)
            token = os.environ.get("MOMUS_OPERATOR_TOKEN", "").strip()
            supplied = (request.headers.get("x-momus-operator") or "").strip()
            if not token or supplied != token:
                raise HTTPException(status_code=403, detail="operator token required for intel refresh")
            return await runtime.refresh_intel()

        @app.get("/scan/{scan_id}")
        async def scan_report(scan_id: str, request: Request) -> dict[str, Any]:
            _limit(aux_limiter, request)
            rd = runtime.scan_report(scan_id)
            if rd is None:
                raise HTTPException(status_code=404, detail="unknown scan")
            return rd

        # ── Remediation loop + A2A (agent↔agent) ──────────────────────────────
        @app.get("/.well-known/agent-card.json")
        async def agent_card_route() -> dict[str, Any]:
            from momus.a2a import agent_card
            return agent_card(cfg.public_url)

        @app.post("/retest")
        async def retest(body: dict, request: Request) -> dict[str, Any]:
            # The deploy gate. A CI/deploy step calls this after redeploying a patched target.
            _require_operator(request)
            _limit(scan_limiter, request)
            fid = str((body or {}).get("finding_id") or "").strip()
            if not fid:
                raise HTTPException(status_code=400, detail="finding_id required")
            return await runtime.retest_finding(fid)

        @app.post("/remediate")
        async def remediate(body: dict, request: Request) -> dict[str, Any]:
            # Open a signed remediation ticket from a confirmed finding and delegate it to SKOPOS
            # over A2A (SKOPOS drives the Factory to fix; MOMUS re-tests as the gate). Operator-only:
            # this path can end in a real redeploy.
            _require_operator(request)
            _limit(scan_limiter, request)
            fid = str((body or {}).get("finding_id") or "").strip()
            if not fid:
                raise HTTPException(status_code=400, detail="finding_id required")
            return await runtime.open_remediation(fid)

        @app.post("/a2a/tasks")
        async def a2a_tasks(body: dict, request: Request) -> dict[str, Any]:
            # Receive an A2A task from a peer. MOMUS serves the read-only skills it advertises
            # (scan / retest / selfaudit); it refuses anything else — a task never grants authority.
            # Peers authenticate with the shared operator token: A2A is agent-to-agent, not public.
            _require_operator(request)
            _limit(scan_limiter, request)
            from momus.a2a import STATE_COMPLETED, STATE_REJECTED, A2ATask
            skill = str((body or {}).get("skill") or "").strip()
            inp = (body or {}).get("input") or {}
            task = A2ATask(skill=skill, input=inp, to_agent="momus",
                           from_agent=str((body or {}).get("from_agent") or "peer"),
                           task_id=str((body or {}).get("task_id") or "")) if body else A2ATask(skill=skill)
            if skill == "retest":
                fid = str(inp.get("finding_id") or "").strip()
                verdict = await runtime.retest_finding(fid) if fid else {"error": "finding_id required"}
                task.state = STATE_COMPLETED
                task.artifacts = [{"type": "fix-verdict", "data": verdict}]
                return task.to_dict()
            if skill == "scan":
                target = str(inp.get("target") or "self")
                if target not in ("self", "momus", "momus-self") and runtime.target(target) is None:
                    task.state = STATE_REJECTED
                    task.message = f"unknown target; known: {runtime.target_names()}"
                    return task.to_dict()
                report = await runtime.run_scan([target], only_probes=inp.get("probes"))
                from momus.capabilities import _report_summary
                task.state = STATE_COMPLETED
                task.artifacts = [{"type": "scan-report", "data": _report_summary(report)}]
                return task.to_dict()
            task.state = STATE_REJECTED
            task.message = f"MOMUS does not accept skill '{skill}'; it serves scan/retest/selfaudit only"
            return task.to_dict()

    app = create_app(
        spec,
        cors_origins=cfg.cors_origins,
        invoke_rate_limit=cfg.invoke_rate_limit,
        extra=extra,
    )
    return app
