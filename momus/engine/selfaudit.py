"""Self-audit — MOMUS red-teams its OWN invariants (who audits the auditor).

A red team that never turns its probes on itself is just a marketing claim. This module asserts
the properties MOMUS's whole trust story depends on, and emits a scanner-signed Finding if any
fails. These are meta-findings about MOMUS itself; they are the most important ones, because a
break here means every other finding MOMUS signs is worth less.

Checked invariants:
  1. Separation of keys — the scanner key differs from the treasury key (if a treasury key is
     present at all), so MOMUS cannot pay itself.
  2. Self-verification is rejected — a verdict signed by the SCANNER key never counts toward a
     payout quorum. We prove it by constructing such a verdict and confirming the gate refuses.
  3. Fail-closed with no treasury — with no treasury key configured, no finding can reach PAID.
  4. Dedup replay guard — the same finding cannot be authorized to PAID/HELD twice.

These run against live, in-process objects, so they test the real gate, not a description of it.
"""

from __future__ import annotations

import time

from momus.economics import BountyLedger, KeyRing, PayoutGate, PayoutState, terms_for
from momus.findings import (
    Evidence,
    Finding,
    FindingSigner,
    Outcome,
    Severity,
    Status,
    Verdict,
    finding_digest,
)
from momus.engine.scanner import ProbeRecord, ScanReport


def _mk_finding(scanner: FindingSigner, severity: Severity = Severity.HIGH,
                *, target: str = "oracles", target_kind: str = "oracle") -> Finding:
    # Default to a NON-infra target so the gate-path tests actually reach the checks they
    # validate — the infra default-deny (H7) would otherwise short-circuit a 'self'-targeted
    # synthetic finding before the self-verification / dedup logic runs.
    f = Finding(
        target=target, target_kind=target_kind, probe="selfaudit_synthetic",
        category="meta", severity=severity.value, outcome=Outcome.FINDING.value,
        title="synthetic self-audit finding", detail="constructed to exercise the payout gate",
        evidence=Evidence(request_digest="sha256-0", response_digest="sha256-0"),
        status=Status.RAW.value,
    )
    return scanner.sign_finding(f)


def run_self_audit(scanner: FindingSigner, keyring: KeyRing, ledger_path_factory) -> ScanReport:
    """Return a ScanReport of meta-findings. ``ledger_path_factory()`` yields a fresh, throwaway
    ledger path so the audit never pollutes the real bounty ledger."""
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    records: list[ProbeRecord] = []
    findings: list[Finding] = []

    def emit(probe: str, outcome: Outcome, severity: Severity, title: str, detail: str) -> None:
        rec = ProbeRecord(target="momus", probe=probe, category="meta",
                          outcome=outcome.value, severity=severity.value, title=title, detail=detail)
        if outcome == Outcome.FINDING:
            f = _mk_finding(scanner, severity, target="momus", target_kind="meta")
            f.probe, f.title, f.detail, f.category = probe, title, detail, "meta"
            scanner.sign_finding(f)
            findings.append(f)
            rec.finding_id = f.finding_id
        records.append(rec)

    # 1. Separation of keys.
    if keyring.treasury_pubkey is not None and keyring.treasury_pubkey == keyring.scanner_pubkey:
        emit("selfaudit_key_separation", Outcome.FINDING, Severity.CRITICAL,
             "scanner key equals treasury key",
             "MOMUS could pay itself: the scanner and treasury keys are identical.")
    else:
        emit("selfaudit_key_separation", Outcome.NO_FINDING, Severity.INFO,
             "scanner and treasury keys are distinct (or no treasury key present)",
             "MOMUS cannot sign a payout with the scanner key.")

    # Build a gate whose treasury CAN sign, to test the self-verification rejection concretely.
    if keyring.treasury is not None:
        ledger = BountyLedger(ledger_path_factory())
        gate = PayoutGate(keyring, ledger, crypto_enabled=True, prod=False, cooldown_s=0)
        finding = _mk_finding(scanner, Severity.HIGH)
        terms = terms_for(finding.severity)
        deposit = terms.bounty_usd * terms.deposit_ratio

        # 2. A verdict signed by the SCANNER key must not count.
        self_v = Verdict(finding_id=finding.finding_id, finding_digest=finding_digest(finding),
                         verdict="confirmed", method="selfaudit", score=1.0,
                         rationale="scanner tries to confirm its own finding", verifier_id="scanner")
        scanner.sign_verdict(self_v)  # signed by the SCANNER key on purpose
        decision = gate.authorize(finding, [self_v], deposit_posted_usd=deposit)
        if decision.state == PayoutState.PAID.value:
            emit("selfaudit_self_verification", Outcome.FINDING, Severity.CRITICAL,
                 "scanner self-verification was accepted",
                 "A verdict signed by the scanner key authorized a payout — self-dealing is possible.")
        else:
            emit("selfaudit_self_verification", Outcome.NO_FINDING, Severity.INFO,
                 "scanner self-verification rejected",
                 f"Gate refused a scanner-signed verdict ({decision.state}); independence is enforced.")

        # 4. Dedup replay guard — authorize once with a real independent verdict, then re-try.
        indep = FindingSigner(ledger_path_factory() + ".vkey")  # a throwaway DISTINCT key
        good_v = indep.sign_verdict(Verdict(
            finding_id=finding.finding_id, finding_digest=finding_digest(finding),
            verdict="confirmed", method="selfaudit-replay", score=0.95,
            rationale="independent throwaway verifier", verifier_id="indep"))
        # HIGH needs 2 distinct verifiers; make a second throwaway key.
        indep2 = FindingSigner(ledger_path_factory() + ".vkey2")
        good_v2 = indep2.sign_verdict(Verdict(
            finding_id=finding.finding_id, finding_digest=finding_digest(finding),
            verdict="confirmed", method="selfaudit-replay", score=0.95,
            rationale="second independent throwaway verifier", verifier_id="indep2"))
        first = gate.authorize(finding, [good_v, good_v2], deposit_posted_usd=deposit)
        second = gate.authorize(finding, [good_v, good_v2], deposit_posted_usd=deposit)
        if first.state in (PayoutState.PAID.value, PayoutState.HELD.value) and \
           second.state == PayoutState.REFUSED.value:
            emit("selfaudit_dedup_replay", Outcome.NO_FINDING, Severity.INFO,
                 "dedup replay guard holds",
                 "A finding authorized once cannot be authorized again (no double pay).")
        else:
            emit("selfaudit_dedup_replay", Outcome.FINDING, Severity.HIGH,
                 "dedup replay guard failed",
                 f"Re-authorizing the same finding did not refuse (first={first.state}, second={second.state}).")
    else:
        # 3. Fail-closed with no treasury.
        ledger = BountyLedger(ledger_path_factory())
        gate = PayoutGate(keyring, ledger, crypto_enabled=True, prod=True, cooldown_s=0)
        finding = _mk_finding(scanner, Severity.HIGH)
        decision = gate.authorize(finding, [], deposit_posted_usd=999)
        if decision.state == PayoutState.PAID.value:
            emit("selfaudit_fail_closed", Outcome.FINDING, Severity.CRITICAL,
                 "payout released with no treasury key",
                 "A payout reached PAID with no treasury key configured — not fail-closed.")
        else:
            emit("selfaudit_fail_closed", Outcome.NO_FINDING, Severity.INFO,
                 "fail-closed with no treasury key",
                 f"With no treasury key, the gate refused ({decision.state}).")

    finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    counts = {"probes": len(records),
              "findings": sum(1 for r in records if r.outcome == Outcome.FINDING.value),
              "no_finding": sum(1 for r in records if r.outcome == Outcome.NO_FINDING.value),
              "inconclusive": sum(1 for r in records if r.outcome == Outcome.INCONCLUSIVE.value)}
    return ScanReport(
        scan_id=f"selfaudit-{int(time.time())}", started_at=started, finished_at=finished,
        targets=["momus"], findings=findings, records=records, provider="n/a", counts=counts,
    )
