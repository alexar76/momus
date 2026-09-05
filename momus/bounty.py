"""Treasury client — how MOMUS asks the SEPARATE payer to release a bounty.

MOMUS never authorizes a payout in its own process. It gathers a scanner-signed finding plus
independent verifier verdicts and POSTs them to the Treasury service, which holds the only key
that can sign a release. If no Treasury is configured (``MOMUS_TREASURY_URL`` unset), MOMUS
cannot pay at all — the honest, fail-closed default for a box that is only a scanner.
"""

from __future__ import annotations

import os
from dataclasses import asdict
from typing import Any

import httpx

from momus.findings import Finding, Verdict


class TreasuryClient:
    def __init__(self, base_url: str | None = None, timeout_s: float = 20.0):
        self.base_url = (base_url or os.environ.get("MOMUS_TREASURY_URL", "")).strip().rstrip("/")
        self._timeout = timeout_s

    @property
    def configured(self) -> bool:
        return bool(self.base_url)

    async def authorize(self, finding: Finding, verdicts: list[Verdict], *,
                        deposit_posted_usd: float = 0.0) -> dict[str, Any]:
        """Submit a finding + verdicts to the Treasury. Returns the Treasury's signed Decision, or
        a fail-closed stub if no Treasury is configured or it is unreachable — never a local
        'paid', because MOMUS holds no key that could make that true."""
        if not self.configured:
            return {"state": "refused", "amount_usd": 0.0,
                    "reasons": ["no Treasury configured (MOMUS_TREASURY_URL unset) — MOMUS cannot pay itself"]}
        payload = {
            "finding": asdict(finding),
            "verdicts": [asdict(v) for v in verdicts],
            "deposit_posted_usd": deposit_posted_usd,
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                r = await client.post(self.base_url + "/authorize", json=payload)
                r.raise_for_status()
                return r.json()
        except (httpx.HTTPError, ValueError) as exc:
            return {"state": "refused", "amount_usd": 0.0,
                    "reasons": [f"Treasury unreachable/error: {type(exc).__name__} — fail-closed, no payout"]}

    async def adjudicate_deposit(self, finding: Finding, verdicts: list[Verdict], *,
                                deposit_posted_usd: float = 0.0) -> dict[str, Any]:
        if not self.configured:
            return {"ruling": "refund", "forfeited_usd": 0.0, "refunded_usd": deposit_posted_usd,
                    "reason": "no Treasury configured"}
        payload = {"finding": asdict(finding), "verdicts": [asdict(v) for v in verdicts],
                   "deposit_posted_usd": deposit_posted_usd}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                r = await client.post(self.base_url + "/deposit", json=payload)
                r.raise_for_status()
                return r.json()
        except (httpx.HTTPError, ValueError) as exc:
            return {"ruling": "refund", "forfeited_usd": 0.0, "refunded_usd": deposit_posted_usd,
                    "reason": f"Treasury unreachable: {type(exc).__name__}"}
