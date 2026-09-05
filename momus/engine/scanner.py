"""Scan runner — drives targets through their strategies and signs the findings.

The runner is intentionally boring: it discovers each target's contract, runs each strategy,
and turns every ``outcome == finding`` result into a scanner-signed :class:`Finding`. It records
NO_FINDING and INCONCLUSIVE outcomes too — an honest red team reports what held, not only what
broke, so the ledger cannot be gamed by only ever surfacing positives. Nothing here authorizes a
payout; that is the treasury's job behind a different key.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from momus.findings import (
    Evidence,
    Finding,
    FindingSigner,
    Outcome,
    Severity,
    Status,
)
from momus.targets.base import ProbeContext, ProbeResult, SafeHttpClient, Target


@dataclass
class ProbeRecord:
    """A single probe outcome — findings AND honest negatives, for a full audit trail."""

    target: str
    probe: str
    category: str
    outcome: str
    severity: str
    title: str
    detail: str
    status_code: int | None = None
    finding_id: str | None = None  # set when this became a signed Finding


#: Evidence excerpts are bounded, but wide enough to carry a probe's acceptance criterion
#: whole — see the note where it is applied. 500 was a cap for REDACTED payload excerpts and
#: cut the manifest probe's criterion mid-sentence.
MAX_SNIPPET_CHARS = 2000


@dataclass
class ScanReport:
    scan_id: str
    started_at: str
    finished_at: str
    targets: list[str]
    findings: list[Finding]
    records: list[ProbeRecord]
    provider: str = ""
    counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "targets": self.targets,
            "provider": self.provider,
            "counts": self.counts,
            "findings": [asdict(f) for f in self.findings],
            "records": [asdict(r) for r in self.records],
        }


class Scanner:
    def __init__(self, signer: FindingSigner, *, llm: Any = None, http_timeout_s: float = 8.0,
                 store: Any = None):
        self._signer = signer
        self._llm = llm
        self._timeout = http_timeout_s
        # Optional KnowledgeStore — when present, MOMUS orders probes by what it has learned pays
        # off (own + peer + external intel) and feeds learned adversarial-shape hints into probes.
        self._store = store

    async def scan(self, targets: list[Target], *, scan_id: str | None = None,
                   only_probes: list[str] | None = None) -> ScanReport:
        scan_id = scan_id or f"scan-{int(time.time())}-{id(targets) & 0xffff:04x}"
        started = _now_z()
        findings: list[Finding] = []
        records: list[ProbeRecord] = []
        for target in targets:
            client = SafeHttpClient(target.base_url, timeout_s=self._timeout,
                                    transport=getattr(target, "transport", None))
            strategies = list(target.strategies())
            categories = sorted({getattr(s, "category", "generic") for s in strategies})
            seeds = self._store.seed_hints(categories) if self._store is not None else []
            if self._store is not None:
                strategies = self._store.order_strategies(strategies, target.kind)
            ctx = ProbeContext(client=client, llm=self._llm, seed_hints=seeds)
            try:
                discovery = await target.discover(ctx)
                for strategy in strategies:
                    if only_probes and strategy.probe_id not in only_probes:
                        continue
                    try:
                        results = await strategy.run(target, ctx, discovery)
                    except Exception as exc:  # a probe bug must not abort the scan
                        results = [ProbeResult(
                            probe=strategy.probe_id, category=strategy.category,
                            outcome=Outcome.INCONCLUSIVE, severity=Severity.INFO,
                            title=f"{target.name}: probe '{strategy.probe_id}' errored",
                            detail=f"{type(exc).__name__}: {exc}",
                        )]
                    for res in results:
                        rec = self._record_of(target, res)
                        if res.outcome == Outcome.FINDING:
                            finding = self._sign_finding(target, res)
                            findings.append(finding)
                            rec.finding_id = finding.finding_id
                        records.append(rec)
            finally:
                await client.aclose()
        finished = _now_z()
        counts = _tally(records)
        if self._store is not None:
            # Learn from this scan (own work): fold every probe outcome into the posteriors.
            try:
                from types import SimpleNamespace
                self._store.record_scan_report(SimpleNamespace(records=records))
            except Exception:  # noqa: BLE001 - learning must never break a scan
                pass
        return ScanReport(
            scan_id=scan_id, started_at=started, finished_at=finished,
            targets=[t.name for t in targets], findings=findings, records=records,
            provider=getattr(self._llm, "kind", None).value if getattr(self._llm, "kind", None) else "offline",
            counts=counts,
        )

    def _sign_finding(self, target: Target, res: ProbeResult) -> Finding:
        req_d, resp_d = res.digests()
        finding = Finding(
            target=target.name,
            target_kind=target.kind,
            probe=res.probe,
            category=res.category,
            severity=res.severity.value if isinstance(res.severity, Severity) else str(res.severity),
            outcome=res.outcome.value if isinstance(res.outcome, Outcome) else str(res.outcome),
            title=res.title,
            detail=res.detail,
            evidence=Evidence(
                request_digest=req_d, response_digest=resp_d,
                request_snippet=res.request_summary[:MAX_SNIPPET_CHARS],
                # 500 was a cap for REDACTED payload excerpts. A probe's acceptance criterion
                # goes in the same field, and 500 characters cut the manifest one mid-sentence,
                # dropping the computed canonical it was there to show. A criterion that
                # arrives truncated is a criterion nobody can satisfy.
                response_snippet=res.response_summary[:MAX_SNIPPET_CHARS],
                status_code=res.status_code, reproducer=res.reproducer,
                reference_artifacts=tuple(getattr(res, "reference_artifacts", ()) or ()),
            ),
            status=Status.RAW.value,
        )
        return self._signer.sign_finding(finding)

    @staticmethod
    def _record_of(target: Target, res: ProbeResult) -> ProbeRecord:
        return ProbeRecord(
            target=target.name, probe=res.probe, category=res.category,
            outcome=res.outcome.value if isinstance(res.outcome, Outcome) else str(res.outcome),
            severity=res.severity.value if isinstance(res.severity, Severity) else str(res.severity),
            title=res.title, detail=res.detail, status_code=res.status_code,
        )


def _now_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _tally(records: list[ProbeRecord]) -> dict[str, int]:
    counts = {"probes": len(records), "findings": 0, "no_finding": 0, "inconclusive": 0}
    for r in records:
        if r.outcome == Outcome.FINDING.value:
            counts["findings"] += 1
        elif r.outcome == Outcome.NO_FINDING.value:
            counts["no_finding"] += 1
        else:
            counts["inconclusive"] += 1
    return counts
