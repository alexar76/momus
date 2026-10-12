"""SKOPOS security findings → MOMUS findings, so they reach the fix loop.

SKOPOS scans the fleet for real defects — publicly bound ports, expiring or missing
TLS, containers running as root, fail2ban not running, unexpected port knocks — and
then *draws* them. `skopos/skopos/ui_security.py` renders a gauge, a banner and a
sidebar badge, and that is the end of the line: nothing consumes those findings, so
every one of them waits for a human to notice.

MOMUS already owns the other half. Its findings become signed RemediationTickets,
route to "auto" or "human-governance" (`momus.engine.remediation.escalation_for`),
get fixed, and are re-probed by the deploy gate before the fix is accepted. That
machinery is target-agnostic — it only ever needed findings in MOMUS's shape.

So this is a translator, not a second scanner. It takes what SKOPOS already found
and hands it to the loop that already knows how to fix things.

Two deliberate refusals:

* `info` severity is dropped unless asked for. The fix loop costs an agent run per
  ticket; "SSH is listening on 22" is not worth one.
* every finding is routed through `escalation_for`, unchanged. A SKOPOS finding
  about a security-core host escalates to a human exactly like a MOMUS one — being
  imported must not become a way to get an automated patch onto an infra box.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from momus.findings import Evidence, Finding, Outcome, Severity

#: SKOPOS writes the same words MOMUS does, except "medium" vs "moderate" in places.
_SEVERITY = {
    "critical": Severity.CRITICAL.value,
    "high": Severity.HIGH.value,
    "medium": Severity.MEDIUM.value,
    "moderate": Severity.MEDIUM.value,
    "low": Severity.LOW.value,
    "info": Severity.INFO.value,
}

#: What a SKOPOS category means in MOMUS's vocabulary. Anything unmapped keeps its
#: own name rather than being forced into a bucket it does not belong in.
_CATEGORY = {
    "ports": "exposure",
    "tls": "transport",
    "docker": "isolation",
    "fail2ban": "hardening",
    "knocks": "reconnaissance",
    "packages": "supply-chain",
    "project": "supply-chain",
}


def _digest(payload: Any) -> str:
    return "sha256-" + hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()


def to_finding(raw: dict, *, server: str, observed_at: str = "") -> Finding | None:
    """One SKOPOS finding as a MOMUS finding. Returns None if it is not one."""
    severity = _SEVERITY.get(str(raw.get("severity", "")).lower())
    if severity is None:
        return None
    category = str(raw.get("category") or "unknown")
    title = str(raw.get("title") or "").strip()
    if not title:
        return None
    detail = str(raw.get("detail") or "").strip()
    recommendation = str(raw.get("recommendation") or "").strip()

    # Stable across re-scans: the same open port found hourly is ONE finding, so the
    # loop does not open a ticket — or pay a bounty — every hour for it.
    dedup = "skopos:" + hashlib.sha256(
        f"{server}|{category}|{title}|{detail}".encode()
    ).hexdigest()[:32]

    return Finding(
        target=server,
        target_kind="host",
        probe=f"skopos:{category}",
        category=_CATEGORY.get(category, category),
        severity=severity,
        outcome=Outcome.FINDING.value,
        title=title,
        detail=detail or title,
        dedup_key=dedup,
        evidence=Evidence(
            request_digest=_digest({"scan": "skopos", "server": server, "at": observed_at}),
            response_digest=_digest(raw),
            request_snippet=f"skopos security scan of {server}",
            response_snippet=detail[:400],
            # SKOPOS findings are observations of a host, not replayable HTTP calls.
            # The honest reproducer is the scan that saw it, not a fabricated curl.
            reproducer=f"skoposctl scan --server {server}  # category={category}",
        ),
    )


def import_findings(
    document: dict,
    *,
    include_info: bool = False,
) -> list[Finding]:
    """Convert a SKOPOS security export into MOMUS findings.

    ``document`` is ``{"server": str, "observed_at": str, "findings": [ ... ]}`` —
    the shape ``skopos.security.store.latest_findings_by_server`` already returns,
    wrapped with the server it belongs to.
    """
    server = str(document.get("server") or "").strip()
    if not server:
        raise ValueError("skopos export names no server; a finding with no host is unactionable")
    observed_at = str(document.get("observed_at") or "")
    raws: Iterable[dict] = document.get("findings") or []

    out: list[Finding] = []
    for raw in raws:
        if not isinstance(raw, dict):
            continue
        finding = to_finding(raw, server=server, observed_at=observed_at)
        if finding is None:
            continue
        if finding.severity == Severity.INFO.value and not include_info:
            continue
        out.append(finding)

    # Deduplicate within one import too: two snapshots of the same scan in one
    # document must not become two tickets.
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in out:
        if finding.dedup_key in seen:
            continue
        seen.add(finding.dedup_key)
        unique.append(finding)
    return unique
