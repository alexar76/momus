"""Where the security budget comes from when the vault runs dry.

A vault that can run out is honest — but then someone has to refill it, and *who decides* is a
governance question with a security answer.

**The hub funds it, by a standing RULE rather than a decision.** The hub is where the ecosystem's
revenue actually lands (invoke fees, channel settlement), and security is a cost of running a
marketplace people trust — the same way fraud prevention is funded out of transaction fees. Whoever
benefits from trust should pay for it.

The critical part is that it is a rule, not a discretionary approval. If a human or an agent had to
approve each refill, that party could **starve the auditor exactly when the auditor finds something
embarrassing** — the same capture we designed the key separation to prevent. So:

    · PULL, not push — the Treasury requests a top-up when available funds fall below a threshold.
    · A STANDING RATE — the hub honours requests automatically up to `rate_bps` of settled invoke
      volume in the current period, capped by `period_cap_usd`. No approval needed inside the rule.
    · ESCALATE above the rule — a request that exceeds the standing allowance is refused with a
      reason and routed to human governance. The auditor is never silently defunded, and the funder
      is never silently drained.
    · FAIL-CLOSED — no allocator configured means the vault simply runs out and bounties become
      HELD intents. An exhausted budget must never be papered over: it is reported, not hidden.

In UNI everything here is simulated bookkeeping: the "hub revenue" is whatever the operator or the
simulation reports, and no value moves. The same shape is what a real allocation would use.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class AllocationRule:
    """The standing rule. Deliberately boring: a rate, a cap, and a trigger threshold."""

    # Share of settled invoke volume that flows to the security budget, in basis points.
    rate_bps: int = 200                  # 2.00% — a security line item, not a tax
    period_cap_usd: float = 500.0        # hard ceiling per period, whatever the volume says
    period_hours: int = 24
    top_up_threshold_usd: float = 50.0   # request a refill when AVAILABLE drops below this
    top_up_target_usd: float = 250.0     # and ask for enough to reach this

    @classmethod
    def from_env(cls) -> "AllocationRule":
        def _f(k: str, d: float) -> float:
            try:
                return float(os.environ.get(k, "").strip() or d)
            except ValueError:
                return d
        return cls(
            rate_bps=int(_f("MOMUS_BUDGET_RATE_BPS", 200)),
            period_cap_usd=_f("MOMUS_BUDGET_PERIOD_CAP_USD", 500.0),
            period_hours=int(_f("MOMUS_BUDGET_PERIOD_HOURS", 24)),
            top_up_threshold_usd=_f("MOMUS_BUDGET_THRESHOLD_USD", 50.0),
            top_up_target_usd=_f("MOMUS_BUDGET_TARGET_USD", 250.0),
        )


@dataclass
class AllocationResult:
    granted_usd: float
    approved: bool
    reason: str
    escalated: bool = False
    source: str = ""
    rule: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)


class SecurityBudget:
    """Requests top-ups for the UNI vault under the standing rule.

    ``hub_url`` is optional: when set, the settled invoke volume for the period is read from the hub
    so the rule is anchored to real economic activity. When unset (or unreachable) the rule falls
    back to ``fallback_volume_usd`` — which in a simulation is simply what the operator declares,
    and which is honestly reported as such in the result's ``source``.
    """

    def __init__(self, vault, rule: AllocationRule | None = None, *,
                 hub_url: str = "", fallback_volume_usd: float | None = None,
                 timeout_s: float = 8.0):
        self._vault = vault
        self.rule = rule or AllocationRule.from_env()
        self.hub_url = (hub_url or os.environ.get("MOMUS_BUDGET_HUB_URL", "")).strip().rstrip("/")
        # In a UNI simulation there may be no hub to read settled volume from. The operator can
        # DECLARE the volume the rule should apply to — and the result always reports that the
        # number was operator-declared rather than measured, so a granted allocation never looks
        # like it was anchored to real economic activity when it was not.
        if fallback_volume_usd is None:
            try:
                fallback_volume_usd = float(
                    os.environ.get("MOMUS_BUDGET_DECLARED_VOLUME_USD", "").strip() or 0.0)
            except ValueError:
                fallback_volume_usd = 0.0
        self.fallback_volume_usd = fallback_volume_usd
        self._timeout = timeout_s
        self._granted_this_period = 0.0
        self._period_started = time.time()

    def _roll_period(self) -> None:
        if time.time() - self._period_started >= self.rule.period_hours * 3600:
            self._period_started = time.time()
            self._granted_this_period = 0.0

    async def _settled_volume(self) -> tuple[float, str]:
        """Settled invoke volume for the period, and where the number came from."""
        if not self.hub_url:
            return self.fallback_volume_usd, "operator-declared (no hub configured)"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as c:
                r = await c.get(f"{self.hub_url}/api/v2/metrics/settled")
                r.raise_for_status()
                data = r.json()
            vol = float((data or {}).get("settled_usd") or 0.0)
            return vol, f"hub {self.hub_url}"
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            # Unreachable funder must not silently mean "unlimited" or "zero surprise" — say so.
            return self.fallback_volume_usd, f"hub unreachable ({type(exc).__name__}); operator-declared"

    def needs_top_up(self) -> bool:
        return self._vault.available < self.rule.top_up_threshold_usd

    async def request_top_up(self, *, force_amount: float | None = None) -> AllocationResult:
        """Ask for a refill under the standing rule. Grants automatically inside the allowance;
        refuses and ESCALATES above it — never silently starves, never silently drains."""
        self._roll_period()
        rule_d = {"rate_bps": self.rule.rate_bps, "period_cap_usd": self.rule.period_cap_usd,
                  "period_hours": self.rule.period_hours,
                  "threshold_usd": self.rule.top_up_threshold_usd,
                  "target_usd": self.rule.top_up_target_usd}

        want = force_amount if force_amount is not None else max(
            0.0, round(self.rule.top_up_target_usd - self._vault.available, 6))
        if want <= 0:
            return AllocationResult(0.0, False, "no top-up needed — available funds are above the target",
                                    source="", rule=rule_d)

        volume, source = await self._settled_volume()
        # The standing allowance: a share of settled volume, capped per period, minus what the
        # period already granted.
        by_rate = round(volume * self.rule.rate_bps / 10_000.0, 6)
        allowance = round(max(0.0, min(by_rate, self.rule.period_cap_usd) - self._granted_this_period), 6)

        if allowance <= 0:
            return AllocationResult(
                0.0, False,
                f"standing allowance exhausted for this {self.rule.period_hours}h period "
                f"(rule: {self.rule.rate_bps}bps of ${volume:.2f} settled = ${by_rate:.2f}, "
                f"cap ${self.rule.period_cap_usd:.2f}, already granted "
                f"${self._granted_this_period:.2f}) — escalating to human governance instead of "
                f"defunding the auditor silently",
                escalated=True, source=source, rule=rule_d)

        granted = round(min(want, allowance), 6)
        self._vault.fund(granted, note=f"security-budget allocation under the standing rule "
                                       f"({self.rule.rate_bps}bps of ${volume:.2f} settled, via {source})")
        self._granted_this_period = round(self._granted_this_period + granted, 6)
        escalated = granted < want
        reason = (f"granted ${granted:.2f} under the standing rule ({self.rule.rate_bps}bps of "
                  f"${volume:.2f} settled volume, source: {source})")
        if escalated:
            reason += (f" — but ${round(want - granted, 6):.2f} of the request exceeded the allowance "
                       f"and is escalated to human governance")
        return AllocationResult(granted, True, reason, escalated=escalated, source=source, rule=rule_d)

    def state(self) -> dict[str, Any]:
        self._roll_period()
        return {"rule": {"rate_bps": self.rule.rate_bps, "period_cap_usd": self.rule.period_cap_usd,
                         "period_hours": self.rule.period_hours,
                         "threshold_usd": self.rule.top_up_threshold_usd,
                         "target_usd": self.rule.top_up_target_usd},
                "granted_this_period_usd": self._granted_this_period,
                "period_started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._period_started)),
                "hub": self.hub_url or None,
                "needs_top_up": self.needs_top_up(),
                "vault": self._vault.state()}
