"""Hub target — probes the paid-invoke settlement path.

The hub is where payment is enforced: a *paid* capability invoked WITHOUT a payment channel
must be refused (402/401), not served for free. This is a real, historically-live gap in this
ecosystem — the school portal noted the live hub serving unpaid invokes with 200 instead of 402
— so it is exactly the kind of contract violation MOMUS exists to catch. Every probe here is
read-only: MOMUS never opens a channel, never settles, never moves funds. It only checks that
the hub REFUSES what it should refuse.
"""

from __future__ import annotations

from typing import Any

from momus.findings import Outcome, Severity
from momus.targets.base import ProbeContext, ProbeResult, ProbeStrategy, Target


class UnpaidInvokeRefused(ProbeStrategy):
    """A paid capability invoked with no payment context must not be served with a 200 + output."""

    probe_id = "unpaid_invoke_refused"
    category = "settlement"

    async def run(self, target: Target, ctx: ProbeContext, discovery: dict[str, Any]) -> list[ProbeResult]:
        # An unreachable hub is not a finding, and it is not a clean bill of health either — the
        # honest answer is inconclusive. (Same false-positive/false-negative trap as the oracle
        # probes; see momus/targets/oracle.py::_unreachable.)
        if not isinstance(discovery.get("manifest"), dict):
            return [ProbeResult(
                probe=self.probe_id, category=self.category, outcome=Outcome.INCONCLUSIVE,
                severity=Severity.INFO, title=f"{target.name}: no manifest retrieved",
                detail=f"Could not read a manifest (status={discovery.get('manifest_status')}) — the "
                       f"hub is unreachable or is not an AIMarket v2 surface.")]
        manifest = discovery.get("manifest") or {}
        # Never invoke MOMUS's own act-y capabilities (recursion guard — see oracle.py::_safe_tools).
        from momus.targets.oracle import _safe_tools
        tools = _safe_tools(manifest.get("tools") or [])
        paid = next((t for t in tools if float(t.get("price_per_call_usd", 0) or 0) > 0), None)
        if not paid:
            return [ProbeResult(
                probe=self.probe_id, category=self.category, outcome=Outcome.INCONCLUSIVE,
                severity=Severity.INFO, title=f"{target.name}: no priced capability advertised",
                detail="Could not find a capability with a positive price to test the unpaid-invoke gate.",
            )]
        cap_id = paid.get("capability_id")
        body = {"capability_id": cap_id, "input": {}}
        status, resp, err = await ctx.client.request("POST", "/ai-market/v2/invoke", json_body=body)
        if err or status is None:
            return [ProbeResult(
                probe=self.probe_id, category=self.category, outcome=Outcome.INCONCLUSIVE,
                severity=Severity.INFO, title=f"{target.name}/{cap_id}: hub unreachable",
                detail=f"Could not reach the hub invoke endpoint: {err or status}.",
            )]
        served = status == 200 and isinstance(resp, dict) and "output" in resp
        if served:
            return [ProbeResult(
                probe=self.probe_id, category=self.category, outcome=Outcome.FINDING,
                severity=Severity.HIGH, title=f"{target.name}/{cap_id}: paid capability served unpaid",
                detail=f"A capability priced at ${paid.get('price_per_call_usd')} returned 200 with output "
                       f"and no payment channel — the settlement gate is not enforced on this path.",
                status_code=status, raw_response=resp,
                reproducer=f"curl -X POST {target.base_url}/ai-market/v2/invoke "
                           f"-d '{{\"capability_id\":\"{cap_id}\",\"input\":{{}}}}'",
            )]
        return [ProbeResult(
            probe=self.probe_id, category=self.category, outcome=Outcome.NO_FINDING,
            severity=Severity.INFO, title=f"{target.name}/{cap_id}: unpaid invoke refused ({status})",
            detail=f"Paid capability correctly withheld without payment (status {status}).",
            status_code=status,
        )]


class HubTarget(Target):
    kind = "hub"

    def strategies(self) -> list[ProbeStrategy]:
        return [UnpaidInvokeRefused()]

    async def discover(self, ctx: ProbeContext) -> dict[str, Any]:
        # Hubs expose the same v2 manifest surface; try it, then the discovery doc.
        status, manifest, _ = await ctx.client.request("GET", "/ai-market/v2/manifest")
        if not isinstance(manifest, dict):
            status, manifest, _ = await ctx.client.request("GET", "/.well-known/ai-market.json")
        return {"manifest": manifest if isinstance(manifest, dict) else {}, "manifest_status": status}
