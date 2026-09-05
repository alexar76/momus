"""Settlement backends for MOMUS bounties — a fail-closed ladder, UNI by default.

The remediation economy is meant to *run* — the whole find → verify → fix → deploy → pay loop
should be exercisable, observable and auditable without a cent moving. So the default settlement
tier is **UNI**: the simulated universe. Real money is the exception, and reaching it requires
climbing an explicit ladder where **enabling crypto is deliberately NOT enough**:

    UNI      (default)  simulated settlement inside the universe. The full pipeline runs, shares
                        are computed and recorded, the monitor shows them — nothing moves on chain.
    HELD                crypto is ON but on-chain bounty settlement was never explicitly enabled,
                        or its config is incomplete. Decisions are recorded as INTENTS only.
    BASE / SOLANA       real settlement. Requires ALL of:
                          AIFACTORY_CRYPTO_ENABLED=1   (ecosystem-wide crypto master switch)
                          MOMUS_BOUNTY_ONCHAIN=1       (a SEPARATE switch, just for bounty payouts)
                          MOMUS_BOUNTY_CHAIN=base|solana
                          MOMUS_BOUNTY_SPLITTER=0x…    (the deployed contract address)
                        Missing or malformed anything → falls back to HELD, never to "pay".

The second switch exists on purpose: turning crypto on for the ecosystem (channels, escrow, the
hub's own settlement) must not silently also start paying out red-team bounties. Those are separate
decisions with separate risk, so they get separate switches.

Even in BASE mode this module never broadcasts a transaction by itself. It PREPARES the call
(contract, function, args) for the Treasury operator to sign and send. An agent that could
broadcast its own payouts would defeat the whole separation-of-duties design.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class SettlementMode(str, Enum):
    UNI = "uni"            # simulated inside the universe — the default
    HELD = "held"          # authorized in principle, deliberately not settled
    BASE = "base"          # real: Base (USDC) via BountySplitter
    SOLANA = "solana"      # real: Solana escrow


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


@dataclass
class SettlementDecision:
    """What actually happened (or would happen) to the money for one share."""

    mode: str
    settled: bool                  # True when the mode considers this share settled (incl. simulated)
    simulated: bool                # True in UNI — no value moved anywhere
    reason: str
    reference: str = ""            # uni receipt id, or a prepared on-chain call reference
    prepared_call: dict[str, Any] | None = None  # BASE/SOLANA: the unsigned call for the operator

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def resolve_mode(*, crypto_enabled: bool | None = None) -> tuple[SettlementMode, str]:
    """Resolve the settlement tier from the environment. Returns (mode, human reason).

    An explicit MOMUS_SETTLEMENT wins, but it can never *escalate* past the ladder: asking for
    'base' without the crypto master switch AND the separate on-chain bounty switch lands on HELD.
    """
    crypto = _truthy(os.environ.get("AIFACTORY_CRYPTO_ENABLED")) if crypto_enabled is None else crypto_enabled
    onchain_optin = _truthy(os.environ.get("MOMUS_BOUNTY_ONCHAIN"))
    requested = (os.environ.get("MOMUS_SETTLEMENT") or "").strip().lower()
    chain = (os.environ.get("MOMUS_BOUNTY_CHAIN") or "base").strip().lower()
    splitter = (os.environ.get("MOMUS_BOUNTY_SPLITTER") or "").strip()

    # Explicit UNI, or nothing configured at all → the simulated universe.
    if requested in ("", "uni"):
        return SettlementMode.UNI, "UNI: simulated settlement in the universe — no value moves"
    if requested == "held":
        return SettlementMode.HELD, "HELD: settlement explicitly disabled; intents only"

    if requested in ("base", "solana", "onchain"):
        if not crypto:
            return SettlementMode.HELD, (
                "HELD: on-chain settlement requested but AIFACTORY_CRYPTO_ENABLED is off — fail-closed")
        if not onchain_optin:
            return SettlementMode.HELD, (
                "HELD: crypto is on, but on-chain BOUNTY settlement needs its own opt-in "
                "(MOMUS_BOUNTY_ONCHAIN=1) — enabling crypto alone never starts paying bounties")
        target = SettlementMode.SOLANA if (requested == "solana" or chain == "solana") else SettlementMode.BASE
        if target is SettlementMode.BASE and not splitter:
            return SettlementMode.HELD, (
                "HELD: MOMUS_BOUNTY_SPLITTER (deployed BountySplitter address) is not set — fail-closed")
        return target, f"{target.value.upper()}: real settlement enabled (crypto + explicit bounty opt-in)"

    return SettlementMode.UNI, f"UNI: unrecognized MOMUS_SETTLEMENT={requested!r} — defaulting to simulation"


def _finding_key(finding_id: str) -> str:
    """bytes32 key the BountySplitter uses — keccak-free: a plain sha256 of the finding id, hex."""
    return "0x" + hashlib.sha256(finding_id.encode()).hexdigest()


def _role_key(role: str) -> str:
    return "0x" + hashlib.sha256(role.encode()).hexdigest()


class SettlementBackend:
    """Settles (or simulates settling) one share. Never broadcasts anything on its own."""

    def __init__(self, mode: SettlementMode, reason: str, *, uni_ledger_path: str = "",
                 splitter: str = "", token: str = "", chain: str = "base",
                 vault: "UniVault | None" = None):
        self.mode = mode
        self.reason = reason
        self.splitter = splitter or (os.environ.get("MOMUS_BOUNTY_SPLITTER") or "").strip()
        self.token = token or (os.environ.get("MOMUS_BOUNTY_TOKEN") or "").strip()
        self.chain = chain
        self._uni_path = Path(uni_ledger_path) if uni_ledger_path else None
        if self._uni_path:
            self._uni_path.parent.mkdir(parents=True, exist_ok=True)
        # The UNI vault: a simulated treasury BALANCE. Without it a simulated treasury pays for
        # ever and the simulation proves nothing about the economics. With it, a bounty draws down a
        # funded balance, an underfunded vault refuses (fail-closed), and every movement lands in a
        # journal that explains what it means. Optional: when absent, UNI behaves as before.
        self.vault = vault

    @classmethod
    def from_env(cls, *, uni_ledger_path: str = "", crypto_enabled: bool | None = None) -> "SettlementBackend":
        mode, reason = resolve_mode(crypto_enabled=crypto_enabled)
        return cls(mode, reason, uni_ledger_path=uni_ledger_path,
                   chain=(os.environ.get("MOMUS_BOUNTY_CHAIN") or "base").strip().lower())

    @property
    def settles_value(self) -> bool:
        """True only for the real-money tiers."""
        return self.mode in (SettlementMode.BASE, SettlementMode.SOLANA)

    def settle_share(self, *, finding_id: str, role: str, recipient: str,
                     amount_usd: float) -> SettlementDecision:
        if self.mode is SettlementMode.UNI:
            ref = f"uni-{hashlib.sha256(f'{finding_id}|{role}'.encode()).hexdigest()[:16]}"
            # With a vault, the share must actually come OUT of a funded, reserved balance — an
            # underfunded vault refuses instead of paying, exactly as a real treasury would.
            if self.vault is not None:
                ok, why, tx = self.vault.release(finding_id, role, amount_usd)
                if not ok:
                    return SettlementDecision(
                        mode=self.mode.value, settled=False, simulated=True,
                        reason=f"UNI vault refused the release — {why}", reference=ref)
                ref = f"{ref}|vault-balance-{tx.balance_after}" if tx else ref
            rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": "uni_settlement",
                   "finding_id": finding_id, "role": role, "recipient": recipient,
                   "amount_usd": amount_usd, "reference": ref, "simulated": True}
            if self._uni_path:
                with self._uni_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            return SettlementDecision(
                mode=self.mode.value, settled=True, simulated=True,
                reason="settled in the UNI simulation — no value moved"
                       + (f"; vault balance now ${self.vault.balance:.2f}" if self.vault else ""),
                reference=ref)

        if self.mode is SettlementMode.HELD:
            return SettlementDecision(mode=self.mode.value, settled=False, simulated=False,
                                      reason=self.reason)

        if self.mode is SettlementMode.BASE:
            # Prepare, never broadcast. The Treasury operator signs and sends this.
            call = {
                "chain": "base",
                "contract": self.splitter,
                "function": "releaseShare(bytes32,bytes32,address,uint256)",
                "args": {
                    "findingId": _finding_key(finding_id),
                    "roleId": _role_key(role),
                    "recipient": recipient,
                    # USDC/USDT are 6-decimal on Base.
                    "amount": int(round(amount_usd * 1_000_000)),
                },
                "token": self.token,
                "note": "UNSIGNED — the Treasury operator must sign and broadcast this call",
            }
            return SettlementDecision(
                mode=self.mode.value, settled=False, simulated=False,
                reason="on-chain call PREPARED for the Treasury operator to sign (never auto-broadcast)",
                reference=f"base:{self.splitter}", prepared_call=call)

        # SOLANA — routed through the existing Solana escrow by the operator.
        return SettlementDecision(
            mode=self.mode.value, settled=False, simulated=False,
            reason="Solana settlement is routed through the existing Solana escrow by the operator",
            reference="solana", prepared_call={"chain": "solana", "finding_id": finding_id,
                                               "role": role, "recipient": recipient,
                                               "amount_usd": amount_usd})

    def describe(self) -> dict[str, Any]:
        return {"mode": self.mode.value, "reason": self.reason, "simulated": self.mode is SettlementMode.UNI,
                "moves_real_value": self.settles_value, "splitter": self.splitter or None,
                "chain": self.chain}
