"""MOMUS AIMarket capabilities + the runtime that backs them.

MOMUS is itself a marketplace citizen: it sells red-team scans through the same oracle-core v2
surface every satellite uses. The capability set encodes the economics decoupling that keeps the
incentives honest — a scan is priced flat, whether or not it finds anything, so MOMUS is never
paid *for finding a bug*; finding bugs earns a separate, treasury-released, verifier-gated bounty
(momus.economics), not scan revenue.

    momus.scan@v1            FREE   scan an ecosystem-internal allowlisted target (self-audit / promo)
    momus.scan.external@v1   PAID   scan a customer's PRE-REGISTERED endpoint (B2B), flat per-scan
    momus.selfaudit@v1       FREE   run MOMUS's own invariant self-audit (transparency)
    momus.findings@v1        FREE   recent signed findings registry (read-only)
    momus.report@v1          PAID   a signed attestation bundle for one completed scan

Note the SSRF guard: an external scan names a target the OPERATOR pre-registered on the allowlist;
an invoke can never make MOMUS probe an arbitrary URL it was handed in the request body.
"""

from __future__ import annotations

import os
from typing import Any

from oracle_core import Capability, OracleSpec

from momus import __version__
from momus.config import MomusConfig
from momus.findings import FindingSigner
from momus.engine.scanner import ScanReport, Scanner
from momus.providers import create_provider, provider_choices
from momus.targets import build_targets
from momus.targets.base import Target

import logging

logger = logging.getLogger(__name__)


class MomusRuntime:
    """Holds the scanner key, target allowlist, LLM provider, and a bounded recent-findings store.
    Deliberately does NOT hold the treasury key — payouts are the Treasury service's job."""

    RECENT_MAX = 200

    def __init__(self, config: MomusConfig | None = None):
        self.config = config or MomusConfig.from_env()
        os.makedirs(self.config.data_dir, exist_ok=True)
        self.signer = FindingSigner(self.config.signing_key_path)
        self.provider = create_provider(self.config.llm)
        # Self-learning memory. Scans read it (probe ordering + seeds) and write to it (outcomes).
        from momus.intel import KnowledgeStore
        self.store = KnowledgeStore(os.path.join(self.config.data_dir, "intel"))
        self.scanner = Scanner(self.signer, llm=self.provider, store=self.store)
        # MOMUS's own vulnerability corpus — the persistent database of holes it has found.
        # SQLite by default (stdlib, real queries, atomic dedup); Postgres when a DSN is set.
        # Findings survive restarts, and a rediscovery bumps seen_count instead of duplicating.
        from momus.store import FindingStore
        self.findings_db = FindingStore(self.config.data_dir)
        self.verifier = self._build_verifier()
        # NOTE: MOMUS deliberately does NOT own the UNI vault. The balance is the TREASURY's — a
        # scanner that held the purse would defeat the separation this whole design rests on. The
        # vault and the security budget live in the treasury service (treasury/treasury/service.py)
        # with their own volume; MOMUS only ever reads their public state.
        self._targets: dict[str, Target] = {}
        for t in build_targets(self.config):
            self._targets.setdefault(t.name, t)
        self._recent: list[dict[str, Any]] = []      # recent findings (dicts)
        self._scans: dict[str, dict[str, Any]] = {}   # scan_id -> report dict
        self._findings_by_id: dict[str, dict[str, Any]] = {}  # finding_id -> finding dict
        # Both maps are BOUNDED. Unbounded, a stream of scans retained one full report dict each
        # for ever and an anonymous caller could OOM the container; the durable copy already lives
        # in the SQLite corpus and can be re-read by scan_id.
        self._scan_order: list[str] = []
        # Remediation: MOMUS re-tests fixes as a deploy gate (signed by its scanner key — a
        # regression check, not a payout), and delegates the fix itself to SKOPOS over A2A.
        from momus.a2a import A2AClient
        from momus.engine.remediation import Retester
        self.retester = Retester(self.signer)
        self.a2a = A2AClient(self.config.skopos_url)
        self._tickets: dict[str, dict[str, Any]] = {}  # finding_id -> remediation ticket

    # ── target allowlist ────────────────────────────────────────────────────
    def target(self, name: str) -> Target | None:
        return self._targets.get(name)

    def target_names(self) -> list[str]:
        return sorted(self._targets)

    def self_target(self) -> Target:
        """MOMUS's own AIMarket surface, for self-audit-by-probe."""
        from momus.targets.oracle import OracleTarget
        return OracleTarget("momus-self", self.config.public_url)

    # ── scans ────────────────────────────────────────────────────────────────
    async def run_scan(self, target_names: list[str], *, only_probes: list[str] | None = None,
                       scan_id: str | None = None) -> ScanReport:
        # Enforce the self-attack switch HERE — the single choke point every caller shares (HTTP
        # routes, A2A tasks, capability handlers). It used to be computed and reported in /health
        # but never consulted, so the prod default had no effect and siblings were probed anyway.
        internal = [n for n in target_names if n not in ("self", "momus", "momus-self")]
        if internal and not self.config.self_attack:
            raise PermissionError(
                f"probing ecosystem siblings is disabled (MOMUS_SELF_ATTACK=0): {internal}. "
                f"Set MOMUS_SELF_ATTACK=1 to allow safe read-only probes of internal targets.")
        targets: list[Target] = []
        for n in target_names:
            t = self.self_target() if n in ("self", "momus", "momus-self") else self.target(n)
            if t is not None:
                targets.append(t)
        if not targets:
            targets = [self.self_target()]
        report = await self.scanner.scan(targets, scan_id=scan_id, only_probes=only_probes)
        canonical = self._store(report)
        await self._independently_verify(report, canonical)
        return report

    #: How many findings one scan may send for independent verification. A scan that turns up
    #: forty findings should not fire forty LLM calls; the ones that matter are the ones the
    #: dispatch policy would act on, and the rest keep their sighting-count path.
    VERIFY_MAX_PER_SCAN = 6
    #: Which severities are worth an independent verdict at all.
    VERIFY_SEVERITIES = ("critical", "high")

    def _build_verifier(self):
        """An independent Verifier, or None — and None is a safe, unchanged loop.

        Refuses to exist unless its key genuinely differs from the scanner's. A verifier that
        signs with the scanner's key is not independent, it just looks it, and the payout gate
        compares public keys precisely because a component's own claim of independence is
        worth nothing.
        """
        url = (self.config.verifier_metis_url or "").strip()
        if not url:
            logger.info("independent verification is OFF (no MOMUS_VERIFIER_METIS_URL) — "
                        "findings keep the sighting-count path")
            return None
        try:
            from momus.engine.verify import Verifier
            signer = FindingSigner(self.config.verifier_key_path)
        except Exception as exc:  # noqa: BLE001
            logger.error("independent verification unavailable: %s", type(exc).__name__)
            return None
        if signer.pubkey == self.signer.pubkey:
            logger.error(
                "REFUSING to verify: the verifier key is the scanner key (%s). A scanner that "
                "signs its own verdicts is not evidence. Point MOMUS_VERIFIER_KEY_PATH at a "
                "different key.", self.config.verifier_key_path)
            return None
        logger.info("independent verification is ON via %s (verifier %s…)",
                    url, signer.pubkey[:16])
        return Verifier(signer, verifier_id="momus-metis-verifier")

    async def _replay_verdict(self, finding, bug_id: str):
        """Ask the replay peer to re-run this probe and sign what it saw.

        Returns None when there is no peer configured — no verdict at all is the honest state
        for a finding nobody independent has looked at, and it is the state the loop was
        already in. A fabricated "inconclusive" would only add noise to the corpus.
        """
        url = (self.config.replay_verifier_url or "").strip()
        if not url:
            return None
        import httpx
        from momus.findings import finding_digest
        headers = {"x-momus-operator": self.config.replay_verifier_token} \
            if self.config.replay_verifier_token else {}
        payload = {
            "finding_id": bug_id,
            "finding_digest": finding_digest(finding),
            "target": finding.target,
            "probe": finding.probe,
        }
        try:
            async with httpx.AsyncClient(timeout=180.0) as client:
                r = await client.post(url.rstrip("/") + "/verify/replay",
                                      json=payload, headers=headers)
                r.raise_for_status()
                data = r.json()
        except httpx.HTTPError as exc:
            logger.error("replay verifier unreachable (%s) — %s is left unverified",
                         type(exc).__name__, bug_id)
            return None
        if str(data.get("verifier_pubkey") or "") == self.signer.pubkey:
            # The peer signs with OUR key: it is this instance behind a different URL, or a
            # misconfiguration that copied the key. Either way it is not a second opinion.
            logger.error("replay verifier signs with the scanner's own key — not independent; "
                         "discarding its verdict on %s", bug_id)
            return None
        from momus.findings import Verdict
        return Verdict(**{k: v for k, v in data.items() if k in Verdict.__dataclass_fields__})

    async def _independently_verify(self, report, canonical: dict[str, str] | None = None) -> None:
        """Ask the independent verifier about this scan's findings. Never raises, never blocks.

        A verdict is additive: it can upgrade a finding from "seen twice" to "judged by a key
        that is not the scanner's". It can never downgrade the loop below where it was, because
        an unreachable or unsure verifier returns `inconclusive`, and the dispatch policy only
        ever looks for `confirmed`.
        """
        if self.verifier is None:
            return
        candidates = [f for f in report.findings
                      if str(getattr(f, "severity", "")).lower() in self.VERIFY_SEVERITIES]
        for finding in candidates[:self.VERIFY_MAX_PER_SCAN]:
            try:
                # File the verdict against the BUG, not this sighting of it. A rediscovery
                # mints a fresh finding_id while the corpus keeps the first as the bug's
                # identity; three real verdicts once sat in the table under ids no reader
                # ever looks up, and every projection honestly reported none.
                bug_id = (canonical or {}).get(finding.finding_id, finding.finding_id)
                from momus.engine.verify import _model_can_judge
                if _model_can_judge(finding):
                    verdict = await self.verifier.verify_via_metis(
                        finding, self.config.verifier_metis_url,
                        api_key=self.config.verifier_metis_key,
                        route=self.config.verifier_metis_route, timeout_s=180.0,
                        finding_id=bug_id)
                else:
                    # A deterministic contract probe has a ground truth. Ask a second instance
                    # to RUN it rather than asking a model to have an opinion about it.
                    verdict = await self._replay_verdict(finding, bug_id)
                    if verdict is None:
                        continue
            except Exception as exc:  # noqa: BLE001
                # A verification that throws must not take the scan down with it: the finding
                # is real whether or not a second opinion arrived.
                logger.warning("verification of %s failed: %s",
                               finding.finding_id, type(exc).__name__)
                continue
            if verdict.verdict == "inconclusive" and "refused the request" in (verdict.rationale or ""):
                # "Never a false confirmed" is the right safety property and it has a failure
                # mode: a misconfigured verifier is indistinguishable from a target that
                # behaves. The first live run answered 401 on every finding and recorded
                # honest, silent "inconclusive" verdicts. Say it at ERROR — this is broken,
                # not merely undecided.
                logger.error("independent verification is NOT working: %s", verdict.rationale)
            try:
                self.findings_db.record_verdict(verdict)
                logger.info("verdict %s for %s (score %.2f, method %s)",
                            verdict.verdict, finding.finding_id, verdict.score, verdict.method)
            except Exception as exc:  # noqa: BLE001
                logger.warning("could not record verdict for %s: %s",
                               finding.finding_id, type(exc).__name__)

    SCANS_MAX = 100
    FINDINGS_BY_ID_MAX = 500

    def _store(self, report: ScanReport) -> dict[str, str]:
        """Persist the scan, and return {this sighting's id -> the bug's canonical id}.

        The mapping already existed inside this method; it was applied to the report dict and
        then thrown away, so a caller that needed to file something against the BUG — an
        independent verdict, say — had no way to learn which id that is.
        """
        rd = report.to_dict()
        self._scans[report.scan_id] = rd
        self._scan_order.append(report.scan_id)
        while len(self._scan_order) > self.SCANS_MAX:          # FIFO eviction
            self._scans.pop(self._scan_order.pop(0), None)
        canonical_ids: dict[str, str] = {}
        # Persist to the corpus first, so a finding survives a restart even if the in-memory
        # cache is later evicted. A rediscovery returns new=False and bumps seen_count.
        try:
            self.findings_db.record_scan(report)
            for finding in report.findings:
                res = self.findings_db.record_finding(finding, scan_id=report.scan_id)
                for f in rd["findings"]:
                    if f.get("finding_id") == finding.finding_id:
                        f["known_before"] = not res["new"]
                        f["seen_count"] = res["seen_count"]
                        # A rediscovery mints a NEW finding_id, but the corpus keeps the FIRST
                        # one — that is what "same bug" means. Caching this sighting under the
                        # fresh id filed it where nobody looks: every reader asking for the
                        # canonical id kept getting the first sighting, so a probe that learned
                        # to explain itself better never reached the fixer.
                        canonical = res.get("finding_id")
                        if canonical and canonical != f["finding_id"]:
                            canonical_ids[finding.finding_id] = canonical
                            f["finding_id"] = canonical
        except Exception:  # noqa: BLE001 - persistence must never break a scan
            pass
        for f in rd["findings"]:
            self._recent.insert(0, f)
            if f.get("finding_id"):
                self._findings_by_id[f["finding_id"]] = f
        del self._recent[self.RECENT_MAX:]
        while len(self._findings_by_id) > self.FINDINGS_BY_ID_MAX:
            self._findings_by_id.pop(next(iter(self._findings_by_id)), None)
        return canonical_ids

    # ── public disclosure ────────────────────────────────────────────────────

    def public_scan_report(self, report: dict[str, Any]) -> dict[str, Any]:
        """Redact a scan report for public serving: reproducers only for disclosed bugs.

        Same rule, same function as the bulletin — deliberately not a second implementation. The
        route that used to return this raw is how an attacker could read an advisory, take the scan
        id, and fetch the exploit the advisory withheld."""
        from momus.bulletin import public_finding

        out = dict(report)
        findings = out.get("findings")
        if isinstance(findings, list):
            try:
                disclosed = self.bulletin.disclosed_dedup_keys()
            except Exception:      # a bulletin problem must never widen disclosure
                disclosed = set()
            out["findings"] = [public_finding(f, disclosed=disclosed)
                               if isinstance(f, dict) else f for f in findings]
        return out

    # ── threat feed for ARGUS's WARDEN firewall ──────────────────────────────
    def _warden_feed(self):
        """Build the feed from the persistent corpus. Cached, because WARDEN polls.

        The cache is short and the signature is recomputed with it: a cached document keeps its
        original `timestamp`, and WARDEN refuses a snapshot older than its freshness window — so a
        long cache would eventually publish a document its own consumer rejects.
        """
        import time as _time

        from momus.warden_feed import build_feed

        now = _time.time()
        cached = getattr(self, "_warden_cache", None)
        if cached and now - cached[0] < 300:
            return cached[1]
        try:
            findings = self.findings_db.recent(limit=500)
        except Exception:
            findings = list(self._recent)
        feed = build_feed(self.signer, findings,
                          first_party_targets=self.target_names())
        self._warden_cache = (now, feed)
        return feed

    def warden_threat_feed(self) -> dict[str, Any]:
        return self._warden_feed().document()

    def warden_feed_summary(self) -> dict[str, Any]:
        feed = self._warden_feed()
        out = feed.summary(public_url=getattr(self.config, "public_url", "") or "")
        out["enabled"] = True
        out["scanner_pubkey"] = self.signer.pubkey
        return out

    # ── the public security bulletin ─────────────────────────────────────────
    @property
    def bulletin(self):
        """MOMUS's advisory record, over the SAME corpus the findings live in (momus/bulletin.py).

        Lazily built, like the reports queue: an operator who never publishes touches no advisory
        machinery at all. Two arguments are the whole configuration, and both are deliberate:

        * ``verifier_pubkey`` is MOMUS's own scanner key, because the re-test deploy gate
          (engine/remediation.Retester) signs its fix verdicts with exactly that key — and a signed
          `fixed` verdict is the ONLY thing that unlocks full disclosure. Naming the key here means
          the bulletin checks the verdict against a pin, never against whatever key the verdict
          itself claims to be signed by.
        * ``public_url`` is the operator's configured public origin, so an advisory's links and the
          Atom entry ids are stable across restarts and redeploys.

        The store holds no signing key: signing the index is a call that takes a signer, so a
        bulletin that is only ever read cannot produce a signed document.
        """
        b = getattr(self, "_bulletin", None)
        if b is None:
            from momus.bulletin import BulletinStore
            b = BulletinStore(self.findings_db, verifier_pubkey=self.signer.pubkey,
                              public_url=self.config.public_url)
            self._bulletin = b
        return b

    def disclosed_bugs(self) -> set[str]:
        """Dedup identities a reader may already see in full. Never raises: a corpus problem must
        widen nothing, so the failure path is the empty set."""
        from momus.bulletin import bulletin_enabled
        if not bulletin_enabled():
            return set()
        try:
            return self.bulletin.disclosed_dedup_keys()
        except Exception:  # noqa: BLE001
            return set()

    def public_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """The findings ledger as an anonymous caller may see it — bulletin.py §2 applied to the live
        route, so a reproducer withheld in the bulletin is not served one route over."""
        from momus.bulletin import public_finding
        disclosed = self.disclosed_bugs()
        return [public_finding(f, disclosed=disclosed) for f in findings]

    # ── reported leads from the field ────────────────────────────────────────
    @property
    def warden_reports(self):
        """Lazily opened so an operator who never enables reporting gets no queue file at all."""
        q = getattr(self, "_warden_reports", None)
        if q is None:
            from momus.warden_reports import SuspicionQueue
            q = SuspicionQueue(os.path.join(self.config.data_dir, "warden_reports.jsonl"))
            self._warden_reports = q
        return q

    def submit_warden_report(self, suspicion) -> dict[str, Any]:
        return self.warden_reports.submit(suspicion)

    def warden_report_leads(self, limit: int = 50, *, fence: bool = False) -> list[dict[str, Any]]:
        return self.warden_reports.leads(limit, fence=fence)

    def warden_report_stats(self) -> dict[str, Any]:
        return self.warden_reports.stats()

    # ── remediation loop ─────────────────────────────────────────────────────
    def _recall(self, finding_id: str) -> dict[str, Any] | None:
        """Find a finding by id: the in-memory LRU first, then the persistent corpus.

        The fallback is not an optimisation, it is the difference between a working deploy gate and a
        broken one. `_findings_by_id` is a bounded in-process cache: a MOMUS restart, or simply
        enough newer findings, empties it — and then the gate answers `unknown_finding` for a bug
        that is still open. SKOPOS reads that as "not fixed", retries to exhaustion and escalates,
        so a MOMUS restart alone could permanently block a real remediation. The corpus outlives the
        process, so the gate should consult it. Found by running the live chain across a redeploy."""
        f = self._findings_by_id.get(finding_id)
        if f:
            return f
        try:
            stored = self.findings_db.get(finding_id)
        except Exception:      # a corpus problem must not turn into a bogus verdict
            return None
        if stored:
            self._findings_by_id[finding_id] = stored     # warm the cache for the retry
        return stored

    def candidate_target(self, tgt: Target) -> Target:
        """The same target, pointed at its CANDIDATE container.

        The caller never supplies a URL, a host or a port — this derives them from the target MOMUS
        was already configured with, by convention: ``<host>`` becomes ``<host>-candidate``, scheme
        and port unchanged. That is deliberate and load-bearing. ``SafeHttpClient`` has no SSRF
        guard (``momus/targets/base.py:61-74`` is a thin httpx wrapper), so a request-supplied URL
        would turn the deploy gate into an authenticated SSRF proxy that helpfully reports the
        response body back inside a signed verdict. A boolean cannot do that.

        The conductor's side of the convention is simply to have a container by that name on the
        network before asking for a candidate gate; if it does not, the probe is unreachable and the
        verdict is ``inconclusive``, which blocks the deploy — the safe direction.
        """
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(tgt.base_url)
        host = parts.hostname or ""
        netloc = f"{host}-candidate" + (f":{parts.port}" if parts.port else "")
        candidate_url = urlunsplit((parts.scheme, netloc, parts.path, "", ""))
        return type(tgt)(f"{tgt.name}-candidate", candidate_url,
                         transport=getattr(tgt, "transport", None))

    async def retest_finding(self, finding_id: str, *, candidate: bool = False) -> dict[str, Any]:
        """The DEPLOY GATE: re-run a stored finding's exact probe and return a signed
        fixed / still-vulnerable verdict.

        Two distinct jobs, and conflating them is what made this gate ceremonial:

        * ``candidate=True`` — **pre-promotion**. Probe the freshly built candidate container, so the
          verdict is about the image that is about to ship. Until a build step existed there was no
          candidate to probe, so the gate could only ever re-examine the *running* (unpatched)
          service, legitimately answer "still reproduces", and get the patch blamed for it.
        * ``candidate=False`` — **post-deploy**. Probe the live service, to confirm the promoted
          image really is clean in place.
        """
        f = self._recall(finding_id)
        if not f:
            return {"error": "unknown_finding", "finding_id": finding_id}
        target_name, probe = f.get("target"), f.get("probe")
        tgt = self.self_target() if target_name in ("momus", "momus-self", "self") else self.target(target_name)
        if tgt is None:
            return {"error": "unknown_target", "target": target_name}
        if candidate:
            tgt = self.candidate_target(tgt)
        # `gated` travels INSIDE the signed body (see FixVerdict) — the returned dict must stay
        # byte-identical to what was signed, because the node agent verifies the signature over
        # every field except `signature`. An extra unsigned key here would make every deploy order
        # fail verification.
        verdict = await self.retester.retest(tgt, probe, finding_id,
                                             gated="candidate" if candidate else "live")
        from dataclasses import asdict
        return asdict(verdict)

    async def open_remediation(self, finding_id: str) -> dict[str, Any]:
        """Turn a confirmed finding into a signed remediation ticket and delegate it to SKOPOS over
        A2A (which drives the Factory to fix it). Infra findings escalate to human governance and
        are NOT auto-dispatched — the auditor never auto-fixes itself."""
        from momus.a2a import remediation_task
        from momus.engine.remediation import open_ticket
        from momus.findings import Evidence, Finding
        fd = self._recall(finding_id)      # persistent corpus too: see _recall
        if not fd:
            return {"error": "unknown_finding", "finding_id": finding_id}
        ev = fd.get("evidence") or {}
        finding = Finding(**{k: fd.get(k) for k in Finding.__dataclass_fields__ if k in fd and k != "evidence"},
                          evidence=Evidence(**{k: ev.get(k) for k in Evidence.__dataclass_fields__ if k in ev}))
        ticket = open_ticket(finding, self.signer)
        # From the CORPUS, not from `_recall`: that helper answers from an in-process LRU first,
        # and the cached shape is the Finding the scanner built — `last_seen_at` is a store column
        # the corpus bumps on every rediscovery, so the cache never has it. Reading it through
        # `_recall` produced an empty string on every ticket, which silently disabled the
        # conductor's regression rule; the loop then answered a real regression with the old
        # "already deployed" job and did nothing at all.
        last_seen = ""
        try:
            row = self.findings_db.get(finding_id) or {}
            last_seen = str(row.get("last_seen_at") or "")
        except Exception:  # noqa: BLE001 - a corpus problem must not block a remediation
            last_seen = str(fd.get("last_seen_at") or "")
        ticket.last_seen_at = last_seen
        self._tickets[finding_id] = ticket.to_dict()
        if ticket.route == "human-governance":
            return {"ticket": ticket.to_dict(), "dispatched": False,
                    "note": "security-core finding — escalated to human governance + external "
                            "verifier; MOMUS never auto-remediates itself"}
        task = remediation_task(ticket.to_dict(), to_agent="skopos")
        delivery = await self.a2a.delegate(task)
        return {"ticket": ticket.to_dict(), "a2a_task": task.to_dict(), "delivery": delivery}

    def tickets(self) -> list[dict[str, Any]]:
        return list(self._tickets.values())

    def recent_findings(self, limit: int = 50, *, severity: str | None = None,
                        target: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        """Read from the persistent corpus, so history survives a restart. Falls back to the
        in-memory ring only if the database is unreadable."""
        try:
            rows = self.findings_db.recent(limit, severity=severity, target=target, status=status)
            if rows or severity or target or status:
                return rows
        except Exception:  # noqa: BLE001
            pass
        return self._recent[: max(0, min(limit, self.RECENT_MAX))]

    def corpus_stats(self) -> dict[str, Any]:
        """Summary of MOMUS's own vulnerability database (for /health, the panel and the monitor)."""
        try:
            return self.findings_db.stats()
        except Exception as exc:  # noqa: BLE001
            return {"backend": "unavailable", "error": type(exc).__name__}

    def scan_report(self, scan_id: str) -> dict[str, Any] | None:
        return self._scans.get(scan_id)

    # ── threat intel + self-learning ─────────────────────────────────────────
    async def refresh_intel(self, *, max_per_feed: int = 25) -> dict[str, Any]:
        """Fetch allowlisted security feeds, distil each report into a KnowledgeCard, and ingest
        it into the learning store. Opt-in (MOMUS_THREAT_INTEL=1) and host-allowlisted; a disabled
        or unreachable feed is a no-op, never an error. Fetched text is UNTRUSTED — it can only
        nudge probe weights/seeds, never add a target or authorize anything."""
        from momus.intel.distill import distill
        from momus.intel.sources import default_feeds, fetch_raw, intel_enabled
        if not intel_enabled():
            return {"enabled": False, "ingested": 0,
                    "note": "threat intel disabled — set MOMUS_THREAT_INTEL=1 to enable"}
        ingested = 0
        seen_feeds: list[str] = []
        for feed in default_feeds():
            seen_feeds.append(feed.feed_id)
            for item in await fetch_raw(feed, max_items=max_per_feed):
                card = await distill(item, self.provider, source=feed.feed_id)
                if card and self.store.ingest_card(card):
                    ingested += 1
        return {"enabled": True, "ingested": ingested, "feeds": seen_feeds,
                "summary": self.store.summary()}

    def ingest_peer_findings(self, findings: list[dict[str, Any]]) -> int:
        """Learn from OTHERS' work — a peer MOMUS's published findings (from momus.findings@v1)."""
        n = 0
        for f in findings or []:
            if isinstance(f, dict) and f.get("category"):
                self.store.ingest_peer_finding(f)
                n += 1
        return n

    def intel_summary(self) -> dict[str, Any]:
        from momus.intel.sources import intel_enabled
        return {"intel_enabled": intel_enabled(), "provider": self.provider.kind.value,
                **self.store.summary()}


# ── capability handlers ───────────────────────────────────────────────────────
def _scan_handler(runtime: MomusRuntime, *, external: bool):
    async def handler(input_data: dict[str, Any]) -> dict[str, Any]:
        target = str(input_data.get("target") or "self").strip()
        probes = input_data.get("probes")
        only = [str(p) for p in probes] if isinstance(probes, list) else None
        if external:
            # B2B: the named target must be a pre-registered, non-self allowlist entry.
            if target in ("self", "momus", "momus-self") or runtime.target(target) is None:
                return {"error": "unknown_target",
                        "detail": "External scans require a pre-registered target id; "
                                  f"known targets: {runtime.target_names()}",
                        "targets": runtime.target_names()}
        try:
            report = await runtime.run_scan([target], only_probes=only)
        except PermissionError as exc:
            return {"error": "self_attack_disabled", "detail": str(exc)}
        return _report_summary(report)
    return handler


def _selfaudit_handler(runtime: MomusRuntime):
    async def handler(input_data: dict[str, Any]) -> dict[str, Any]:
        from momus.economics import KeyRing
        from momus.engine.selfaudit import run_self_audit
        # A KeyRing with only the scanner key (no treasury) — the audit reports fail-closed as a
        # PASS, which is the honest state for a MOMUS box that does not itself hold the treasury.
        treasury_path = os.environ.get("MOMUS_TREASURY_KEY_PATH", "").strip() or None
        keyring = KeyRing(runtime.config.signing_key_path, treasury_path)
        # A throwaway ledger per run, in a temp dir that is deleted afterwards. Writing into the
        # key volume made every self-audit append to the same file and re-read all prior lines —
        # quadratic in the number of calls, and unbounded growth next to the signing key.
        import shutil
        import tempfile
        tmpdir = tempfile.mkdtemp(prefix="momus-selfaudit-")
        counter = {"n": 0}

        def ledger_path_factory() -> str:
            counter["n"] += 1
            return os.path.join(tmpdir, f"audit_{counter['n']}.jsonl")
        try:
            report = run_self_audit(runtime.signer, keyring, ledger_path_factory)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
        return _report_summary(report)
    return handler


def _findings_handler(runtime: MomusRuntime):
    async def handler(input_data: dict[str, Any]) -> dict[str, Any]:
        # Redacted UNCONDITIONALLY, unlike GET /findings, which serves the originals to an operator
        # token. A capability handler receives only the input dict — never the request — so it cannot
        # tell an operator from a stranger, and the marketplace invoke path is reachable by anybody.
        # Guessing "probably an operator" here would reopen the reproducer leak through /ai-market/v2,
        # which is exactly how the operator gate on the ACT capabilities was bypassed before.
        limit = int(input_data.get("limit", 50) or 50)
        findings = runtime.public_findings(runtime.recent_findings(limit))
        return {"count": len(findings), "findings": findings,
                "scanner_pubkey": runtime.signer.pubkey,
                "disclosure": "redacted per coordinated disclosure (momus/bulletin.py \u00a72): a "
                              "reproducer is served only for a bug already published as `fixed`"}
    return handler


def _intel_handler(runtime: MomusRuntime):
    async def handler(input_data: dict[str, Any]) -> dict[str, Any]:
        return runtime.intel_summary()
    return handler


def _retest_handler(runtime: MomusRuntime):
    async def handler(input_data: dict[str, Any]) -> dict[str, Any]:
        fid = str(input_data.get("finding_id") or "").strip()
        if not fid:
            return {"error": "finding_id required"}
        return await runtime.retest_finding(fid)
    return handler


def _report_handler(runtime: MomusRuntime):
    async def handler(input_data: dict[str, Any]) -> dict[str, Any]:
        scan_id = str(input_data.get("scan_id") or "").strip()
        rd = runtime.scan_report(scan_id)
        if rd is None:
            return {"error": "unknown_scan", "detail": f"No scan with id {scan_id!r}."}
        return rd
    return handler


def _report_summary(report: ScanReport) -> dict[str, Any]:
    rd = report.to_dict()
    return {
        "scan_id": rd["scan_id"],
        "targets": rd["targets"],
        "counts": rd["counts"],
        "provider": rd["provider"],
        "findings": rd["findings"],
        "records": [
            {"target": r["target"], "probe": r["probe"], "outcome": r["outcome"],
             "severity": r["severity"], "title": r["title"]}
            for r in rd["records"]
        ],
    }


# ── spec ────────────────────────────────────────────────────────────────────
_SCAN_IN = {"type": "object", "properties": {
    "target": {"type": "string", "description": "allowlisted target id, or 'self'"},
    "probes": {"type": "array", "items": {"type": "string"},
               "description": "optional subset of probe ids to run"},
}}
_SCAN_OUT = {"type": "object", "properties": {
    "scan_id": {"type": "string"}, "counts": {"type": "object"},
    "findings": {"type": "array"}, "records": {"type": "array"},
}}


def build_spec(runtime: MomusRuntime, public_url: str | None = None) -> OracleSpec:
    url = public_url or runtime.config.public_url
    product = "momus.redteam"
    caps = [
        Capability(
            capability_id="momus.scan@v1",
            description="Run a SAFE red-team scan against an ecosystem-internal allowlisted target "
                        "(or MOMUS itself). Read-only conformance/adversarial probes; no destructive "
                        "actions and no fund moves. Free — this is the self-audit / promotion tier.",
            handler=_scan_handler(runtime, external=False),
            product_id=product, input_schema=_SCAN_IN, output_schema=_SCAN_OUT,
            price_per_call_usd=0.0, p50_latency_ms=400,
        ),
        Capability(
            capability_id="momus.scan.external@v1",
            description="Run a full red-team scan against a customer's PRE-REGISTERED endpoint (B2B). "
                        "Priced flat per scan, NOT per finding, so MOMUS is never paid for finding a "
                        "bug — a confirmed bug earns a separate treasury-released, verifier-gated bounty.",
            handler=_scan_handler(runtime, external=True),
            product_id=product, input_schema=_SCAN_IN, output_schema=_SCAN_OUT,
            price_per_call_usd=0.05, p50_latency_ms=800,
        ),
        Capability(
            capability_id="momus.selfaudit@v1",
            description="Run MOMUS's own invariant self-audit (key separation, self-verification "
                        "rejection, fail-closed, dedup replay). Free — transparency about the auditor.",
            handler=_selfaudit_handler(runtime),
            product_id=product, input_schema={"type": "object", "properties": {}},
            output_schema=_SCAN_OUT, price_per_call_usd=0.0, p50_latency_ms=50,
        ),
        Capability(
            capability_id="momus.findings@v1",
            description="Recent signed findings registry (read-only). Findings for bugs already "
                        "published as `fixed` come through whole and verify offline against the "
                        "scanner key; the rest are redacted under coordinated disclosure (no "
                        "reproducer, no payload snippets, no target host) and say so in their own "
                        "`disclosure` field \u2014 a redacted document carries no signature rather than "
                        "one that cannot verify.",
            handler=_findings_handler(runtime),
            product_id=product,
            input_schema={"type": "object", "properties": {"limit": {"type": "integer", "maximum": 200}}},
            output_schema={"type": "object", "properties": {
                "count": {"type": "integer"}, "findings": {"type": "array"}}},
            price_per_call_usd=0.0, p50_latency_ms=10,
        ),
        Capability(
            capability_id="momus.retest@v1",
            description="DEPLOY GATE: re-run a specific finding's exact probe against its (patched) "
                        "target and return a signed fixed / still-vulnerable verdict. A deploy "
                        "pipeline calls this before promoting a container and refuses to ship while "
                        "the finding still reproduces. MOMUS gates; it never deploys.",
            handler=_retest_handler(runtime),
            product_id=product,
            input_schema={"type": "object", "properties": {"finding_id": {"type": "string"}},
                          "required": ["finding_id"]},
            output_schema={"type": "object", "properties": {
                "fixed": {"type": "boolean"}, "outcome": {"type": "string"},
                "detail": {"type": "string"}, "signature": {"type": "object"}}},
            price_per_call_usd=0.0, p50_latency_ms=400,
        ),
        Capability(
            capability_id="momus.intel@v1",
            description="MOMUS's self-learning state: distilled threat-intel cards ingested from "
                        "allowlisted public security feeds, and the per-(attack-class, target-kind) "
                        "posteriors MOMUS uses to decide which probes to run first. Read-only.",
            handler=_intel_handler(runtime),
            product_id=product,
            input_schema={"type": "object", "properties": {}},
            output_schema={"type": "object", "properties": {
                "cards_total": {"type": "integer"}, "category_scores": {"type": "object"},
                "recent_cards": {"type": "array"}}},
            price_per_call_usd=0.0, p50_latency_ms=10,
        ),
        Capability(
            capability_id="momus.report@v1",
            description="The full signed report for one completed scan (all probes, findings, and "
                        "honest negatives).",
            handler=_report_handler(runtime),
            product_id=product,
            input_schema={"type": "object", "properties": {"scan_id": {"type": "string"}},
                          "required": ["scan_id"]},
            output_schema=_SCAN_OUT, price_per_call_usd=0.002, p50_latency_ms=15,
        ),
    ]
    return OracleSpec(
        name="MOMUS — adversarial-audit satellite",
        product_id=product,
        description="Autonomous red team for the AI-economy: safe, read-only conformance and "
                    "adversarial probes against the ecosystem's own components (oracle free-tier "
                    "ceilings, manifest/receipt signatures, settlement gates, prompt-injection "
                    "surfaces), emitted as Ed25519-signed findings. MOMUS finds and signs; a "
                    "separate Treasury role — its own key — is the only thing that can pay a "
                    "bounty, and only on independent verification. The offensive complement to "
                    "ARGUS's defensive WARDEN.",
        public_url=url,
        categories=["security", "red-team", "audit", "conformance", "verification", "adversarial"],
        capabilities=caps,
        signing_key_path=runtime.config.signing_key_path,
        version=__version__,
        related=["argus", "metis", "gaia", "oracles"],
    )
