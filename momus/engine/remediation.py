"""Remediation loop — the other half of a red team: from a confirmed finding to a fixed,
redeployed container, with the finder itself as the deploy gate.

A finding that no one fixes is a complaint, not a control. This module closes the loop:

    confirmed Finding
        └─▶ RemediationTicket  (signed Blame: which component, the reproducer, the probe to re-run)
              └─▶ (the AI-Factory or a human produces a patch — OUTSIDE MOMUS)
                    └─▶ retest()  — MOMUS re-runs the EXACT probe against the patched build
                          ├─ still reproduces → FixVerdict(fixed=False) → deploy is BLOCKED
                          └─ gone           → FixVerdict(fixed=True)  → deploy may proceed

Two design rules make this trustworthy and bounded:

1. **The finding is its own regression test.** A fix is not "done" because someone says so — it is
   done because the probe that found the bug can no longer find it, and that verdict is signed. The
   deploy pipeline calls :meth:`retest` as a PRE-PROMOTION gate and refuses to ship a build that
   still reproduces the finding.

2. **MOMUS holds no deploy keys** — the same containment as the Treasury. MOMUS emits a *verdict*,
   never a deploy action; the existing rsync + ``docker compose`` pipeline owns the redeploy and
   merely consults MOMUS. A compromised MOMUS can neither pay itself nor ship code.

Who fixes the fixer? A finding against the security core (MOMUS / Treasury / the gate) is routed by
:func:`escalation_for` to HUMAN governance plus an INDEPENDENTLY-OPERATED external verifier — never
auto-remediated by the instance that would be fixing itself. The regress is finite: one independent
party plus a human root checking signed, offline-verifiable evidence terminates it.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

from momus.economics import _INFRA_COMPONENTS
from momus.findings import Blame, Finding, FindingSigner, Outcome
from momus.targets.base import ProbeContext, SafeHttpClient, Target


@dataclass
class RemediationTicket:
    """A signed hand-off from a confirmed finding to whoever will fix it. Shaped as an AWR
    BlameAttestation plus the machine-actionable bits a fixer/CI needs."""

    finding_id: str
    component: str            # the at-fault target/capability
    target: str
    probe: str                # the exact probe to re-run as the fix gate
    severity: str
    reproducer: str
    route: str                # "auto" (ordinary component) | "human-governance" (security core)
    blame: dict[str, Any] = field(default_factory=dict)  # signed Blame attestation
    #: When the corpus last saw this finding reproduce. The conductor needs it to tell a duplicate
    #: ticket ("already fixed, someone asked twice") from a REGRESSION ("the fix shipped and the bug
    #: came back"). Without it a shipped remediation can never be re-opened, and a loop that cannot
    #: re-heal a regression is not self-healing.
    last_seen_at: str = ""
    #: What is actually wrong, in words. A ticket used to carry the probe's NAME and nothing
    #: else, so a fixer with an empty reproducer — which several probes legitimately produce,
    #: a signature check has nothing to curl — was left inferring the defect from the string
    #: "manifest_signature_integrity". Measured: three autonomous attempts in a row authored
    #: patches the pre-promotion gate rejected, each one a guess at what "conforming" meant.
    title: str = ""
    detail: str = ""
    #: Digests, status code and any captured snippets. Bounded by the caller, and empty when
    #: the probe recorded nothing.
    evidence: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FixVerdict:
    """The deploy gate's answer: does the finding still reproduce against the (patched) target?"""

    finding_id: str
    target: str
    probe: str
    fixed: bool
    outcome: str              # 'no_finding' (fixed) | 'finding' (still vulnerable) | 'inconclusive'
    detail: str
    #: WHAT was examined: the freshly built candidate container, or the live service.
    #: Inside the signed body on purpose. A verdict that does not say which build it looked at is
    #: ambiguous exactly where a deploy gate must not be — and if it said so only in an unsigned
    #: field, a pre-promotion "fixed" could be relabelled as a post-deploy confirmation on the wire.
    gated: str = "live"       # 'candidate' (pre-promotion) | 'live' (in place)
    checked_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    verifier_pubkey: str = ""
    signature: dict[str, Any] = field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("signature", None)
        return d


def escalation_for(component: str, target_kind: str = "") -> str:
    """Route a confirmed finding. The security core escalates to humans; everything else may take
    the automated fix→retest→redeploy path."""
    if component in _INFRA_COMPONENTS or target_kind in ("self", "meta"):
        return "human-governance"
    return "auto"


def open_ticket(finding: Finding, signer: FindingSigner) -> RemediationTicket:
    """Turn a finding into a signed remediation ticket (with a Blame attestation)."""
    route = escalation_for(finding.target, finding.target_kind)
    blame = Blame(
        finding_id=finding.finding_id, component=finding.target, severity=finding.severity,
        hop=f"{finding.target}:{finding.probe}",
        summary=f"{finding.title} — {route} remediation",
    )
    signer.sign_blame(blame)
    evidence = {}
    try:
        evidence = {k: v for k, v in asdict(finding.evidence).items() if v not in ("", None, {})}
    except Exception:  # noqa: BLE001 - evidence is a convenience, never a blocker
        evidence = {}
    return RemediationTicket(
        finding_id=finding.finding_id, component=finding.target, target=finding.target,
        probe=finding.probe, severity=finding.severity, reproducer=finding.evidence.reproducer,
        route=route, blame={**blame.canonical(), "signature": blame.signature},
        title=str(finding.title or ""), detail=str(finding.detail or ""), evidence=evidence,
    )


class Retester:
    """Re-runs a single finding's probe against a (patched, redeployed) target and signs the result.
    Signed by a VERIFIER key — the same independence principle as the payout: the party that says
    "fixed" should not be the party that shipped the fix."""

    def __init__(self, signer: FindingSigner, *, http_timeout_s: float = 8.0):
        self._signer = signer
        self._timeout = http_timeout_s

    async def retest(self, target: Target, probe_id: str, finding_id: str,
                     *, gated: str = "live") -> FixVerdict:
        client = SafeHttpClient(target.base_url, timeout_s=self._timeout,
                                transport=getattr(target, "transport", None))
        ctx = ProbeContext(client=client)
        try:
            discovery = await target.discover(ctx)
            strategy = next((s for s in target.strategies() if s.probe_id == probe_id), None)
            if strategy is None:
                return self._sign(FixVerdict(finding_id, target.name, probe_id, False,
                                             "inconclusive", f"probe {probe_id} not available on target",
                                             gated=gated))
            results = await strategy.run(target, ctx, discovery)
            still = any(r.outcome == Outcome.FINDING for r in results)
            incon = all(r.outcome == Outcome.INCONCLUSIVE for r in results) if results else True
            if incon:
                return self._sign(FixVerdict(finding_id, target.name, probe_id, False,
                                             "inconclusive", "target unreachable — cannot gate the deploy",
                                             gated=gated))
            if still:
                return self._sign(FixVerdict(finding_id, target.name, probe_id, False, "finding",
                                             "finding STILL reproduces — deploy must be blocked",
                                             gated=gated))
            return self._sign(FixVerdict(finding_id, target.name, probe_id, True, "no_finding",
                                         "finding no longer reproduces — fix verified, deploy may proceed",
                                         gated=gated))
        finally:
            await client.aclose()

    def _sign(self, v: FixVerdict) -> FixVerdict:
        import json
        v.verifier_pubkey = self._signer.pubkey
        canon = json.dumps(v.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        v.signature = self._signer._signer.sign_payload(canon)  # reuse the underlying Ed25519 signer
        return v
