"""MOMUS FastAPI app — oracle-core AIMarket surface + red-team control routes.

The AIMarket v2 surface (/.well-known, /ai-market/v2/manifest, /ai-market/v2/invoke) comes for
free from oracle-core. On top we mount the live-panel routes the frontend and the Alien Monitor
poll: /health, /providers, /scan, /selfaudit, /findings, /scan/{id}. All of them are read-only or
run safe probes; none can move funds or authorize a payout (that is the separate Treasury service).
"""

from __future__ import annotations

import os
import re
import time
import xml.etree.ElementTree as ET
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response
from oracle_core import create_app
from oracle_core.app import client_key
from oracle_core.ratelimit import RateLimiter
from pydantic import BaseModel, Field

from momus import __version__
from momus.bulletin import bulletin_enabled
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


# ── Atom 1.0 rendering of the bulletin ────────────────────────────────────────
# Built with ElementTree instead of an f-string template, and that is a security choice rather than
# a style one. An advisory summary is TEXT that came out of a probe or an operator's withdrawal
# reason, so a hand-written template publishes a bare `&` or `<` straight into the document: in the
# best case the feed stops parsing for every reader, in the worst it injects markup into whatever
# renders it. ElementTree escapes node text and attribute values itself, and _xml_text() removes the
# one class of input escaping cannot fix.
#
# Everything here consumes the ALREADY-REDACTED dicts (bulletin.Advisory.to_dict), never an
# Advisory, so this renderer cannot widen disclosure even by mistake: an `open` entry's reproducer is
# the empty string long before it arrives.
ATOM_NS = "http://www.w3.org/2005/Atom"
# Two spellings, deliberately. The `type` attribute of an Atom <link> is an advisory MEDIA TYPE
# (RFC 4287), so it carries no charset parameter; the HTTP response header does, because a reader
# that guesses the encoding of a document containing non-ASCII prose guesses wrong eventually.
ATOM_MEDIA_TYPE = "application/atom+xml"
ATOM_CONTENT_TYPE = f"{ATOM_MEDIA_TYPE}; charset=utf-8"

# XML 1.0 has no escape for most control characters — they are simply forbidden. A captured response
# snippet can carry one, and a single raw 0x00 makes the WHOLE feed unparseable rather than just its
# own entry, so they are dropped here instead of trusted not to appear.
_XML_ILLEGAL = re.compile(
    "[^\\u0009\\u000a\\u000d\\u0020-\\ud7ff\\ue000-\\ufffd\\U00010000-\\U0010ffff]")
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")


def _xml_text(value: Any) -> str:
    return _XML_ILLEGAL.sub("", "" if value is None else str(value))


def _atom_stamp(*candidates: Any) -> str:
    """The first candidate that is a real RFC 3339 instant.

    Atom REQUIRES ``<updated>`` on the feed and on every entry, and a malformed one is not cosmetic:
    a strict reader rejects the document. `now` is the last fallback on purpose — it is a worse
    answer than the advisory's own timestamps, so it is used only when none of them is usable.
    """
    for candidate in candidates:
        text = ("" if candidate is None else str(candidate)).strip()
        if text and _RFC3339.match(text):
            return text
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sub(parent: ET.Element, tag: str, text: Any = None, **attrs: Any) -> ET.Element:
    el = ET.SubElement(parent, tag, {k: _xml_text(v) for k, v in attrs.items()})
    if text is not None:
        el.text = _xml_text(text)
    return el


def _atom_entry_content(pub: dict[str, Any]) -> str:
    """The entry body, assembled ONLY from fields the redacted dict already chose to publish.

    `type="text"`, not html: an advisory detail is prose, and declaring it html would ask every
    reader to render markup we did not author. `reproducer` is present for a `fixed` advisory and the
    empty string for anything else — the store decided that, and this function does not re-decide it.
    """
    parts = [
        f"status: {pub.get('status') or ''}",
        f"disclosure: {pub.get('disclosure') or ''}",
        f"component: {pub.get('component') or ''}",
        f"category: {pub.get('category') or ''}",
        f"severity: {pub.get('severity') or ''}",
        "",
        str(pub.get("details") or ""),
    ]
    if pub.get("withdrawn_reason"):
        parts += ["", f"withdrawn: {pub['withdrawn_reason']}"]
    if pub.get("reproducer"):
        parts += ["", f"reproducer: {pub['reproducer']}"]
    return "\n".join(parts)


def atom_feed(advisories: list[dict[str, Any]], *, base_url: str) -> bytes:
    """An Atom 1.0 feed of already-redacted advisories, as UTF-8 bytes with an XML declaration."""
    base = (base_url or "").rstrip("/")
    feed = ET.Element("feed", {"xmlns": ATOM_NS})
    _sub(feed, "title", "MOMUS security bulletin")
    _sub(feed, "subtitle",
         "Advisories MOMUS publishes about the first-party services it audits. An `open` advisory "
         "carries no reproducer, no evidence and no target: coordinated disclosure, because MOMUS "
         "audits services we operate.")
    # A STABLE feed id. An id that changed per fetch would make every reader treat each poll as a
    # brand-new feed and re-notify on the whole bulletin.
    _sub(feed, "id", f"{base}/bulletin")
    _sub(feed, "link", None, rel="self", type=ATOM_MEDIA_TYPE, href=f"{base}/bulletin.atom")
    _sub(feed, "link", None, rel="alternate", type="application/json", href=f"{base}/bulletin")
    # The newest modification in the record. Our own stamps are all UTC `Z` (bulletin._now_z), so
    # the lexicographic maximum IS the chronological one; anything not RFC 3339 is ignored rather
    # than sorted, because a malformed stamp must not become the feed's authoritative date.
    known = sorted(s for s in (str(a.get("modified") or "").strip() for a in advisories)
                   if _RFC3339.match(s))
    _sub(feed, "updated", known[-1] if known else _atom_stamp())
    author = _sub(feed, "author")
    _sub(author, "name", "MOMUS")
    _sub(author, "uri", base or "https://momus.modelmarket.dev")
    _sub(feed, "generator", "MOMUS", version=__version__)

    for pub in advisories:
        advisory_id = str(pub.get("id") or "")
        entry = _sub(feed, "entry")
        _sub(entry, "title", f"{advisory_id}: {pub.get('summary') or ''}".strip(": "))
        # The per-entry id is stable across polls because readers dedupe on it: a churning id
        # republishes the entire bulletin as unread every time. The advisory NUMBER is already the
        # permanent handle for the bug, so the entry id is simply its URL.
        _sub(entry, "id", f"{base}/bulletin/{advisory_id}")
        _sub(entry, "link", None, rel="alternate", type="application/json",
             href=f"{base}/bulletin/{advisory_id}")
        # <updated> is the advisory's MODIFIED time: a re-publication, a fix or a withdrawal has to
        # surface as an update in a reader, which is why the record keeps both dates separately.
        _sub(entry, "updated", _atom_stamp(pub.get("modified"), pub.get("published")))
        _sub(entry, "published", _atom_stamp(pub.get("published"), pub.get("modified")))
        for term in (str(pub.get("category") or ""), f"severity:{pub.get('severity') or ''}",
                     f"status:{pub.get('status') or ''}"):
            if term.strip(": "):
                _sub(entry, "category", None, term=term)
        _sub(entry, "summary", pub.get("summary") or "", type="text")
        _sub(entry, "content", _atom_entry_content(pub), type="text")
    return ET.tostring(feed, encoding="utf-8", xml_declaration=True)



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

    def _operator_ok(request: Request) -> bool:
        """Did this request carry the operator token? A QUESTION, not a gate.

        Used by read-only routes that serve a redacted document to the world and the original to an
        operator. Independent of `_control_gated()` on purpose: that switch decides who may make MOMUS
        *act*, while this one decides who may *see* an unfixed bug's reproducer, and those must not
        share a knob. With no token configured this is False for everybody — no configuration, no
        disclosure.
        """
        token = os.environ.get("MOMUS_OPERATOR_TOKEN", "").strip()
        supplied = (request.headers.get("x-momus-operator") or "").strip()
        return bool(token) and supplied == token

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
            """The live findings ledger — PUBLIC, and therefore under the same coordinated-disclosure
            rule as the bulletin (momus/bulletin.py \u00a72).

            This route used to return whole finding documents straight from the corpus, so the
            `evidence.reproducer` and the in-cluster target URL of a still-unfixed finding were public
            on a rate-limited, unauthenticated GET. Withholding a reproducer in the bulletin while
            serving the same reproducer one route over is not coordinated disclosure, it is paperwork,
            so both surfaces now answer from ONE rule and one function.

            The disclosure test is deliberately NOT "is this prod?" but "is this bug already
            published as fixed?" — an env flag is not a property of the bug, and a dev box reachable
            on a LAN leaks exactly as well as a prod one. An operator who needs the verifiable
            original sends the operator token and gets the unredacted documents.
            """
            _limit(aux_limiter, request)
            rows = runtime.recent_findings(limit)
            if _operator_ok(request):
                return {"count": len(rows), "findings": rows,
                        "scanner_pubkey": runtime.signer.pubkey,
                        "disclosure": "full \u2014 operator token accepted; these are the signed originals",
                        # Naming the unsigned keys, because omitting them made the "verifiable
                        # offline" claim false in practice: the corpus adds these when it reads a row
                        # back, so a verifier that hashed the whole document minus `signature` got a
                        # failure every time and had no way to know why. See bulletin.signed_body().
                        "verify_note": "hash the fields of the Finding dataclass only; "
                                       "seen_count, first_seen_at, last_seen_at and known_before are "
                                       "corpus bookkeeping and were never signed",
                        "unsigned_fields": ["seen_count", "first_seen_at", "last_seen_at",
                                            "known_before"]}
            public = runtime.public_findings(rows)
            return {"count": len(public), "findings": public,
                    "scanner_pubkey": runtime.signer.pubkey,
                    "disclosure": "redacted per coordinated disclosure \u2014 a reproducer is served only "
                                  "for a bug already published as `fixed` in /bulletin. Each finding "
                                  "carries its own `disclosure` field"}

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

        # ── The public security bulletin ───────────────────────────────────────
        # MOMUS ingests CISA KEV, OSV and GHSA and published nothing of its own. These four routes
        # close that asymmetry in the SAME shape we consume — OSV records, a signed index, Atom — so
        # the tooling that reads the rest of the world reads us too.
        #
        # All four are PUBLIC and read-only, for the same reason the threat feed is: the index is
        # Ed25519-signed over its RFC 8785 canonical form, so authenticity does not depend on who
        # fetched it, and a bulletin nobody can fetch is not a public record. The key to pin is
        # MOMUS's scanner key, already published as `scanner_pubkey` on /health and in WARDEN's
        # encoding as `feed_public_key_spki_hex` on /warden/threat-feed/summary — one key, not a
        # third format to get wrong.
        #
        # Coordinated disclosure (bulletin.py §2) is applied by the STORE, not per route: every path
        # below serves Advisory.to_dict()'s redacted form, so an `open` advisory cannot ship a
        # reproducer even if a future route forgets to think about it. Nothing here mints, withdraws
        # or re-publishes an advisory — those are operator acts and are not exposed over HTTP at all.
        _BULLETIN_MAX = 500

        def _bulletin_or_404():
            """The bulletin, or a 404 explaining that there is none.

            404 and not 403, exactly as for the threat feed: an operator who did not enable
            publishing HAS no bulletin, and "forbidden" would tell a reader one exists behind a
            permission — an invitation to go looking for it.
            """
            if not bulletin_enabled():
                raise HTTPException(
                    status_code=404,
                    detail="MOMUS publishes no security bulletin here "
                           "(set MOMUS_BULLETIN=1 to publish one)")
            return runtime.bulletin

        @app.get("/bulletin")
        async def bulletin_index(request: Request) -> dict[str, Any]:
            """The signed index: {advisories, timestamp, signature} — WARDEN's envelope, reused.

            Deliberately takes no `limit`: the bulletin IS the record, and a paginated record signed
            per page would give two readers two different documents to cite. Capped at
            _BULLETIN_MAX so the response can never grow unbounded. Not cached either — signing is
            microseconds, and `timestamp` is a freshness claim, so a cached document would eventually
            publish a stale one (the mistake the WARDEN feed's short cache exists to avoid).
            """
            _limit(aux_limiter, request)
            return _bulletin_or_404().index(runtime.signer, limit=_BULLETIN_MAX)

        @app.get("/bulletin.atom", response_model=None)
        async def bulletin_atom(request: Request):
            """The same record as an Atom 1.0 feed, for readers that poll rather than parse JSON."""
            _limit(aux_limiter, request)
            store = _bulletin_or_404()
            body = atom_feed(store.list(limit=_BULLETIN_MAX), base_url=cfg.public_url)
            # The real Atom media type, not application/xml: a feed reader dispatches on it, and
            # `charset` is explicit because the document can carry non-ASCII prose.
            return Response(content=body, media_type=ATOM_CONTENT_TYPE)

        # DECLARED BEFORE /bulletin/{advisory_id}: Starlette matches routes in declaration order, so
        # the parameterised route would otherwise swallow "osv" and answer "no advisory 'osv'".
        @app.get("/bulletin/osv", response_model=None)
        async def bulletin_osv(request: Request):
            """The OSV export (§3), as the bare array an OSV consumer expects.

            Each record states the schema mismatch in `database_specific.note`: OSV describes
            vulnerable PACKAGE VERSIONS and a MOMUS advisory describes a DEPLOYED SERVICE with no
            version axis. Saying so is the difference between an honest export and one that lets a
            consumer believe a version range was checked.
            """
            _limit(aux_limiter, request)
            return _bulletin_or_404().osv(limit=_BULLETIN_MAX)

        @app.get("/bulletin/{advisory_id}")
        async def bulletin_advisory(advisory_id: str, request: Request) -> dict[str, Any]:
            """One advisory, redacted per its own status. 404 for an id that is not on the record."""
            _limit(aux_limiter, request)
            entry = _bulletin_or_404().get(advisory_id)
            if entry is None:
                # One answer for "never existed" and "malformed id": both are "not on the record",
                # and distinguishing them would let a caller enumerate which numbers are taken.
                raise HTTPException(
                    status_code=404,
                    detail=f"no advisory {advisory_id!r} on the record "
                           f"(an advisory id looks like MOMUS-2026-0001)")
            return entry

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
            """A completed scan report — REDACTED by the same rule the bulletin uses.

            This route served the full, unredacted finding for a bug whose advisory was still
            `open`: the reproducer (operator token and all), the in-cluster host, the bare IP and
            both raw snippets, to anyone, with no operator gate. So the entire coordinated-disclosure
            design could be walked around by fetching the scan the advisory came from — an attacker
            reading the bulletin learns the scan id and asks for the exploit directly.

            The lesson is the one the bulletin module already wrote down and this route did not
            inherit: a disclosure rule enforced in ONE renderer is not a rule, it is a habit. It now
            goes through the same `public_finding()` the bulletin serves, so a reproducer appears
            here only for a bug whose advisory is fully disclosed.
            """
            _limit(aux_limiter, request)
            rd = runtime.scan_report(scan_id)
            if rd is None:
                raise HTTPException(status_code=404, detail="unknown scan")
            return runtime.public_scan_report(rd)

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
