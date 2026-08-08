"""Independent verification — turns a raw Finding into a signed Verdict.

The whole payout model rests on a verdict coming from a key that is NOT the scanner and NOT the
treasury. Two independent verifier sources are supported:

* ``metis`` — route the finding to an external Metis ``/v1/verify`` endpoint and let its
  cognitive stack judge whether the described contract violation reproduces. Metis signs with
  its own key, so the verdict is genuinely independent of MOMUS.
* ``replay`` — re-execute the finding's probe from a SECOND MOMUS instance that holds a DIFFERENT
  verifier key (a distinct principal / second box). Deterministic contract probes (signature
  integrity, ceiling enforcement) reproduce exactly, which is what makes them safe to auto-verify.

A ``Verifier`` holds exactly one verifier key and signs verdicts with it. The economics layer
independently checks that this key differs from the scanner and treasury keys — a verifier that
lies about its own independence still cannot satisfy the gate, because the gate compares the
actual public keys, not the verifier's say-so.
"""

from __future__ import annotations

from typing import Any

import httpx

from momus.findings import Finding, FindingSigner, Verdict, finding_digest


class Verifier:
    def __init__(self, signer: FindingSigner, verifier_id: str):
        self._signer = signer
        self.verifier_id = verifier_id

    @property
    def pubkey(self) -> str:
        return self._signer.pubkey

    def _verdict(self, finding: Finding, verdict: str, method: str, score: float,
                 rationale: str) -> Verdict:
        v = Verdict(
            finding_id=finding.finding_id,
            finding_digest=finding_digest(finding),
            verdict=verdict, method=method, score=score, rationale=rationale,
            verifier_id=self.verifier_id,
        )
        return self._signer.sign_verdict(v)

    async def verify_via_metis(self, finding: Finding, metis_url: str,
                               *, timeout_s: float = 30.0) -> Verdict:
        """Ask an external Metis to judge the finding. Metis returning an error or being
        unreachable yields an ``inconclusive`` verdict — never a false ``confirmed``."""
        prompt = _finding_to_verify_input(finding)
        try:
            async with httpx.AsyncClient(timeout=timeout_s) as client:
                r = await client.post(metis_url.rstrip("/") + "/v1/verify", json={"input": prompt})
                r.raise_for_status()
                data = r.json()
        except (httpx.HTTPError, ValueError) as exc:
            return self._verdict(finding, "inconclusive", "metis:/v1/verify", 0.0,
                                 f"Metis unreachable/error: {type(exc).__name__}")
        # Metis envelopes vary; read a score and a verified flag defensively.
        score = _read_score(data)
        verified = bool(data.get("verified")) if isinstance(data, dict) else False
        # A verify score above threshold that the finding reproduces → confirmed.
        if verified or score >= 0.6:
            return self._verdict(finding, "confirmed", "metis:/v1/verify", max(score, 0.6),
                                 "Metis independently reproduced/agreed with the finding.")
        return self._verdict(finding, "refuted", "metis:/v1/verify", 1.0 - score,
                             "Metis could not reproduce the finding.")

    def verify_via_replay(self, finding: Finding, *, reproduced: bool,
                          detail: str = "") -> Verdict:
        """Record a verdict from a deterministic re-run done by a distinct verifier principal.

        The caller (a second MOMUS instance with its own key) re-ran the exact probe and reports
        whether the contract violation reproduced. Because the probe is deterministic, this is a
        strong, cheap independent confirmation — as long as the key really is a different one,
        which the economics gate verifies."""
        if reproduced:
            return self._verdict(finding, "confirmed", "replay", 0.95,
                                 detail or "Deterministic probe re-ran on an independent instance and reproduced.")
        return self._verdict(finding, "refuted", "replay", 0.9,
                             detail or "Deterministic probe did not reproduce on an independent instance.")


def _finding_to_verify_input(finding: Finding) -> str:
    return (
        f"A red-team probe reports a contract violation. Decide whether it is real and reproduces.\n"
        f"Target: {finding.target} ({finding.target_kind})\n"
        f"Probe: {finding.probe} / {finding.category}\n"
        f"Severity claimed: {finding.severity}\n"
        f"Title: {finding.title}\n"
        f"Detail: {finding.detail}\n"
        f"Reproducer: {finding.evidence.reproducer}\n"
        f"Observed status: {finding.evidence.status_code}\n"
    )


def _read_score(data: Any) -> float:
    if not isinstance(data, dict):
        return 0.0
    for key in ("verify_score", "score", "confidence"):
        v = data.get(key)
        if isinstance(v, (int, float)):
            return max(0.0, min(1.0, float(v)))
    # Some Metis envelopes nest under "verdict"/"result".
    for key in ("verdict", "result", "output"):
        inner = data.get(key)
        if isinstance(inner, dict):
            s = _read_score(inner)
            if s:
                return s
    return 0.0
