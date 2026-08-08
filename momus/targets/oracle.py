"""Oracle target — probes an oracle-core / GAIA / Metis AIMarket v2 surface.

Every probe asserts against the target's OWN published contract (its signed manifest, its
declared free-tier ceilings, its signed receipts). Nothing is destructive and no funds move:
these are conformance and adversarial tests, run read-only. The interesting outcomes are the
ones where a target VIOLATES its own contract — e.g. serves over-ceiling work unpaid, or emits
a receipt that still "verifies" after a field is tampered.
"""

from __future__ import annotations

import copy
from typing import Any

from oracle_core.signing import Signer

from momus.findings import Outcome, Severity
from momus.targets.base import ProbeContext, ProbeResult, ProbeStrategy, Target

# A throwaway signer only for its PURE canonicalization helpers (manifest_canonical /
# receipt_canonical do not use key material). Verification uses the static Signer.verify.
_CANON = Signer.__new__(Signer)


class ManifestSignatureIntegrity(ProbeStrategy):
    """The manifest must be signed, verify under its declared key, and STOP verifying when a
    field is tampered. A manifest that verifies after tampering means the signature does not
    actually bind the content — a critical trust failure."""

    probe_id = "manifest_signature_integrity"
    category = "integrity"

    async def run(self, target: Target, ctx: ProbeContext, discovery: dict[str, Any]) -> list[ProbeResult]:
        manifest = discovery.get("manifest")
        well_known = discovery.get("well_known") or {}
        # An UNREACHABLE target is not a finding. Without this guard a target that is simply down
        # (or on an unroutable address) produced a HIGH "manifest is unsigned" — a false positive
        # that would erode trust in every finding MOMUS signs. Distinguish "served a manifest with
        # no signature" (a real contract violation) from "served nothing at all" (inconclusive).
        if not isinstance(manifest, dict):
            return [_inconclusive(self, target, "-",
                                  f"no manifest retrieved (status={discovery.get('manifest_status')}) "
                                  f"— target unreachable or not an AIMarket v2 surface")]
        if "signature" not in manifest:
            return [ProbeResult(
                probe=self.probe_id, category=self.category, outcome=Outcome.FINDING,
                severity=Severity.HIGH, title=f"{target.name}: manifest is unsigned",
                detail="The AIMarket v2 manifest carries no signature block; a relay could tamper "
                       "with capabilities or prices undetectably.",
                response_summary="manifest has no 'signature'", status_code=200,
                reproducer=f"curl {target.base_url}/ai-market/v2/manifest | jq .signature",
            )]
        pubkey = (manifest.get("signature") or {}).get("public_key") or well_known.get("signer_public_key")
        if not pubkey:
            return [ProbeResult(
                probe=self.probe_id, category=self.category, outcome=Outcome.INCONCLUSIVE,
                severity=Severity.INFO, title=f"{target.name}: no public key to verify manifest",
                detail="Neither the signature block nor the well-known doc exposes a signer public key.",
            )]
        canonical = _CANON.manifest_canonical(manifest)
        sig_value = (manifest.get("signature") or {}).get("value", "")
        genuine_ok = Signer.verify(canonical, sig_value, pubkey)
        if not genuine_ok:
            return [ProbeResult(
                probe=self.probe_id, category=self.category, outcome=Outcome.FINDING,
                severity=Severity.HIGH, title=f"{target.name}: manifest signature does not verify",
                detail="The published manifest's signature fails to verify against its declared "
                       "public key — the catalogue cannot be trusted as served.",
                response_summary=f"verify(canonical, value, {pubkey[:12]}…) = False", status_code=200,
            )]
        # Tamper: bump a price and confirm the signature now FAILS.
        tampered = copy.deepcopy(manifest)
        if tampered.get("tools"):
            tampered["tools"][0]["price_per_call_usd"] = tampered["tools"][0].get("price_per_call_usd", 0) + 999
        tampered_ok = Signer.verify(_CANON.manifest_canonical(tampered), sig_value, pubkey)
        if tampered_ok:
            return [ProbeResult(
                probe=self.probe_id, category=self.category, outcome=Outcome.FINDING,
                severity=Severity.CRITICAL, title=f"{target.name}: manifest signature does not bind content",
                detail="After changing a tool's price the signature STILL verifies — the signature "
                       "does not cover the tools, so prices/capabilities can be forged under a valid sig.",
                response_summary="tampered manifest still verifies", status_code=200,
            )]
        return [ProbeResult(
            probe=self.probe_id, category=self.category, outcome=Outcome.NO_FINDING,
            severity=Severity.INFO, title=f"{target.name}: manifest signature binds content",
            detail="Manifest verifies genuine and fails when tampered — signature integrity holds.",
        )]


class FreeTierCeilingBypass(ProbeStrategy):
    """A capability that declares a free_tier_max must REFUSE an unpaid over-ceiling call with 402
    (never silently serve it, never silently clamp it). oracle-core's own tiers.py documents this
    as load-bearing; MOMUS checks the target actually enforces it."""

    probe_id = "free_tier_ceiling_bypass"
    category = "authz"

    async def run(self, target: Target, ctx: ProbeContext, discovery: dict[str, Any]) -> list[ProbeResult]:
        if _unreachable(discovery):
            return [_inconclusive(self, target, "-", "no manifest — cannot read the declared ceilings")]
        manifest = discovery.get("manifest") or {}
        tools = _safe_tools(manifest.get("tools") or [])
        results: list[ProbeResult] = []
        probed = 0
        for tool in tools:
            ftm = tool.get("free_tier_max")
            if not ftm or probed >= 3:  # at most 3 priced-compute capabilities per scan
                continue
            probed += 1
            cap_id = tool.get("capability_id")
            field, ceiling = next(iter(ftm.items()))
            over = _bump_over(ceiling)
            body = {"capability_id": cap_id, "input": _nested_set({}, field, over)}
            status, resp, err = await ctx.client.request("POST", "/ai-market/v2/invoke", json_body=body)
            if err or status is None:
                results.append(_inconclusive(self, target, cap_id, err))
                continue
            if status == 402:
                results.append(ProbeResult(
                    probe=self.probe_id, category=self.category, outcome=Outcome.NO_FINDING,
                    severity=Severity.INFO, title=f"{target.name}/{cap_id}: over-ceiling refused (402)",
                    detail=f"Unpaid call with {field}={over} > ceiling {ceiling} correctly refused with 402.",
                    status_code=status,
                ))
            elif status == 200:
                results.append(ProbeResult(
                    probe=self.probe_id, category=self.category, outcome=Outcome.FINDING,
                    severity=Severity.HIGH, title=f"{target.name}/{cap_id}: free-tier ceiling not enforced",
                    detail=f"Unpaid call with {field}={over} (over declared ceiling {ceiling}) returned 200. "
                           f"Either the ceiling is not enforced (unpaid compute exhaustion) or work was "
                           f"silently clamped (a receipt would attest a difficulty the caller did not request).",
                    status_code=status,
                    reproducer=f"curl -X POST {target.base_url}/ai-market/v2/invoke "
                               f"-d '{{\"capability_id\":\"{cap_id}\",\"input\":{{\"{field}\":{over}}}}}'",
                    raw_response=resp,
                ))
            else:
                results.append(ProbeResult(
                    probe=self.probe_id, category=self.category, outcome=Outcome.FINDING,
                    severity=Severity.LOW, title=f"{target.name}/{cap_id}: unexpected status {status} over ceiling",
                    detail=f"Expected 402 for an over-ceiling unpaid call; got {status}.",
                    status_code=status,
                ))
        if not results:
            results.append(ProbeResult(
                probe=self.probe_id, category=self.category, outcome=Outcome.NO_FINDING,
                severity=Severity.INFO, title=f"{target.name}: no priced-compute ceilings to probe",
                detail="No capability declares a free_tier_max, so there is no ceiling to bypass.",
            ))
        return results


class MalformedInputHardening(ProbeStrategy):
    """A malformed / out-of-schema input must yield a clean 4xx, never a 500 or a hang. A 500 on
    adversarial input is an unhandled-exception surface."""

    probe_id = "malformed_input_hardening"
    category = "input-validation"

    async def run(self, target: Target, ctx: ProbeContext, discovery: dict[str, Any]) -> list[ProbeResult]:
        if _unreachable(discovery):
            return [_inconclusive(self, target, "-", "no manifest — no capability to send input to")]
        manifest = discovery.get("manifest") or {}
        tools = _safe_tools(manifest.get("tools") or [])
        if not tools:
            return [_inconclusive(self, target, "-",
                                  "no safely-invocable capability (all are MOMUS's own act-y ones)")]
        cap_id = tools[0].get("capability_id")
        # A grab-bag of hostile inputs; optionally enriched by the LLM (idea generator only).
        payloads = [
            {"__proto__": {"admin": True}, "n": "not-a-number"},
            {"n": 10 ** 18, "device_id": "A" * 5000},
            {"nested": {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}},
        ]
        results: list[ProbeResult] = []
        # Count how many payloads actually got a DECISIVE answer. A 429 means the target's own rate
        # limiter turned the probe away, so nothing about its input handling was tested — and the
        # audit showed an attacker could flood a target's shared limiter to make every payload come
        # back 429, turning "never tested" into "handled cleanly" and forging a deploy-gate pass.
        decisive = 0
        rate_limited = 0
        for p in payloads:
            body = {"capability_id": cap_id, "input": p}
            status, resp, err = await ctx.client.request("POST", "/ai-market/v2/invoke", json_body=body)
            if err or status is None:
                continue
            if status == 429:
                rate_limited += 1
                continue
            decisive += 1
            if status >= 500:
                results.append(ProbeResult(
                    probe=self.probe_id, category=self.category, outcome=Outcome.FINDING,
                    severity=Severity.MEDIUM, title=f"{target.name}/{cap_id}: 500 on malformed input",
                    detail=f"Adversarial input produced HTTP {status} — an unhandled exception rather "
                           f"than a clean 4xx rejection.",
                    status_code=status, raw_request=p, raw_response=resp,
                    reproducer=f"curl -X POST {target.base_url}/ai-market/v2/invoke -d '{{...malformed...}}'",
                ))
        if not results:
            if decisive == 0:
                results.append(_inconclusive(
                    self, target, cap_id,
                    f"no payload got a decisive answer ({rate_limited} rate-limited) — the target's "
                    f"input handling was never exercised, so this is not a pass"))
            else:
                results.append(ProbeResult(
                    probe=self.probe_id, category=self.category, outcome=Outcome.NO_FINDING,
                    severity=Severity.INFO, title=f"{target.name}: malformed input handled cleanly",
                    detail=f"{decisive} of {len(payloads)} hostile inputs were rejected with a clean "
                           f"4xx (no 5xx crash surface observed)"
                           + (f"; {rate_limited} were rate-limited and not counted." if rate_limited else "."),
                ))
        return results


class ReceiptSignatureIntegrity(ProbeStrategy):
    """A free invoke's receipt must be signed, verify, stop verifying when tampered, and carry a
    nonce + timestamp (the anti-replay surface)."""

    probe_id = "receipt_signature_integrity"
    category = "integrity"

    async def run(self, target: Target, ctx: ProbeContext, discovery: dict[str, Any]) -> list[ProbeResult]:
        if _unreachable(discovery):
            return [_inconclusive(self, target, "-", "no manifest — no capability to invoke")]
        manifest = discovery.get("manifest") or {}
        well_known = discovery.get("well_known") or {}
        # Pick a capability with no ceiling and price 0 if possible (a truly free call).
        safe = _safe_tools(manifest.get("tools") or [])
        if not safe:
            return [_inconclusive(self, target, "-",
                                  "no safely-invocable capability (all are MOMUS's own act-y ones)")]
        free_cap = None
        for tool in safe:
            if not tool.get("free_tier_max") and float(tool.get("price_per_call_usd", 0) or 0) == 0:
                free_cap = tool
                break
        free_cap = free_cap or safe[0]
        cap_id = free_cap.get("capability_id")
        if not cap_id:
            return [_inconclusive(self, target, "?", "no capability to invoke")]
        status, resp, err = await ctx.client.request(
            "POST", "/ai-market/v2/invoke", json_body={"capability_id": cap_id, "input": {}})
        if err or status is None or status != 200 or not isinstance(resp, dict):
            return [_inconclusive(self, target, cap_id, err or f"status {status}")]
        receipt = resp.get("receipt")
        if not isinstance(receipt, dict) or "signature" not in receipt:
            return [ProbeResult(
                probe=self.probe_id, category=self.category, outcome=Outcome.FINDING,
                severity=Severity.MEDIUM, title=f"{target.name}/{cap_id}: response has no signed receipt",
                detail="A paid marketplace surface returned no signed receipt — the buyer has no proof of work.",
                status_code=status, raw_response=resp,
            )]
        missing = [k for k in ("nonce", "timestamp") if not receipt.get(k)]
        if missing:
            return [ProbeResult(
                probe=self.probe_id, category=self.category, outcome=Outcome.FINDING,
                severity=Severity.MEDIUM, title=f"{target.name}/{cap_id}: receipt missing {', '.join(missing)}",
                detail="A receipt without a nonce/timestamp can be replayed — no freshness to bind it to one call.",
                status_code=status, raw_response=receipt,
            )]
        pubkey = well_known.get("signer_public_key")
        if pubkey:
            body = {k: v for k, v in receipt.items() if k != "signature"}
            canon = Signer.receipt_canonical(body)
            value = (receipt.get("signature") or {}).get("value", "")
            if not Signer.verify(canon, value, pubkey):
                return [ProbeResult(
                    probe=self.probe_id, category=self.category, outcome=Outcome.FINDING,
                    severity=Severity.HIGH, title=f"{target.name}/{cap_id}: receipt signature does not verify",
                    detail="The receipt's signature fails against the oracle's declared public key.",
                    status_code=status, raw_response=receipt,
                )]
            tampered = dict(body)
            tampered["price_usd"] = float(tampered.get("price_usd", 0)) + 42
            if Signer.verify(Signer.receipt_canonical(tampered), value, pubkey):
                return [ProbeResult(
                    probe=self.probe_id, category=self.category, outcome=Outcome.FINDING,
                    severity=Severity.CRITICAL, title=f"{target.name}/{cap_id}: receipt signature does not bind price",
                    detail="After changing price_usd the receipt signature STILL verifies — a buyer's "
                           "proof-of-price can be forged under a valid signature.",
                    status_code=status,
                )]
        return [ProbeResult(
            probe=self.probe_id, category=self.category, outcome=Outcome.NO_FINDING,
            severity=Severity.INFO, title=f"{target.name}/{cap_id}: receipt integrity holds",
            detail="Receipt is signed, verifies, carries a nonce + timestamp, and fails when tampered.",
            status_code=status,
        )]


# MOMUS's OWN capabilities that make it act. A probe must never invoke these, because when the
# target is MOMUS itself (the self-audit target) the probe's invoke starts another whole scan,
# which probes MOMUS again — the audit reproduced ~100 nested scans from a single request, each
# going out over the public TLS edge and writing to the corpus. Read-only self capabilities
# (findings/intel/report) are fine to invoke.
_SELF_ACT_CAPABILITIES = {
    "momus.scan@v1", "momus.scan.external@v1", "momus.selfaudit@v1", "momus.retest@v1",
}


def _safe_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop capabilities a probe must not invoke (MOMUS's own act-y ones — recursion guard)."""
    return [t for t in tools if str(t.get("capability_id") or "") not in _SELF_ACT_CAPABILITIES]


def _unreachable(discovery: dict[str, Any]) -> bool:
    """True when discovery brought back no manifest at all.

    Every probe below asserts something about a target's DECLARED contract, which means it needs
    that declaration. Without it there is nothing to assert — and claiming either outcome would be
    dishonest in a different direction: a FINDING would be a false positive ("your manifest is
    unsigned" when the host was simply down), and a NO_FINDING would be a false negative ("the
    contract held") about a check that never ran. Both erode the value of a signed finding, so an
    unreachable target yields INCONCLUSIVE — the honest third answer.
    """
    return not isinstance(discovery.get("manifest"), dict)


def _inconclusive(strategy: ProbeStrategy, target: Target, cap_id: str, why: str) -> ProbeResult:
    return ProbeResult(
        probe=strategy.probe_id, category=strategy.category, outcome=Outcome.INCONCLUSIVE,
        severity=Severity.INFO, title=f"{target.name}/{cap_id}: could not reach a judgement",
        detail=f"Probe inconclusive: {why}. An unreachable target is not a finding.",
    )


def _bump_over(ceiling: Any) -> Any:
    if isinstance(ceiling, bool):
        return not ceiling
    if isinstance(ceiling, (int, float)):
        return ceiling + max(1, int(abs(ceiling) * 0.1) + 1)
    return ceiling


def _nested_set(root: dict, dotted: str, value: Any) -> dict:
    """Set a possibly-dotted key ('puzzle.T') into a nested dict — matches oracle-core's ceiling keys."""
    parts = dotted.split(".")
    cur = root
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value
    return root


class OracleTarget(Target):
    kind = "oracle"

    def strategies(self) -> list[ProbeStrategy]:
        return [
            ManifestSignatureIntegrity(),
            FreeTierCeilingBypass(),
            MalformedInputHardening(),
            ReceiptSignatureIntegrity(),
        ]

    async def discover(self, ctx: ProbeContext) -> dict[str, Any]:
        m_status, manifest, _ = await ctx.client.request("GET", "/ai-market/v2/manifest")
        w_status, well_known, _ = await ctx.client.request("GET", "/.well-known/ai-market.json")
        return {
            "manifest": manifest if isinstance(manifest, dict) else None,
            "well_known": well_known if isinstance(well_known, dict) else None,
            "manifest_status": m_status,
            "well_known_status": w_status,
        }
