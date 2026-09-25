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

THE REWARD FALLBACK, AND WHY IT EXISTS
--------------------------------------
A real rail can decline to settle for entirely ordinary reasons: the pool is not funded, the
Treasury operator has not signed yet, the chain is unreachable, the address is misconfigured.
Without a fallback every one of those leaves the share stuck at HELD — and an operator watching
the ledger sees a security auditor that stopped being paid.

`MOMUS_REWARD_FALLBACK=sandbox` (the default) says: when the real rail does not settle, settle the
share on the **sandbox rail** instead — the same simulated UNI vault, plainly marked
`simulated: true`, `rail: "sandbox"` and `fallback_from: "base"`. The unsigned call is still
attached, so an operator who *does* want to pay in USDC can still sign it.

This is a SUBSTITUTE, not a debt. The sandbox share is not a claim redeemable in USDC later, and it
never pretends to be. The bounty exists to make the security economy run, be observed and be
audited; a rail that cannot pay must not be allowed to stop that.

`MOMUS_REWARD_FALLBACK=held` restores the older behaviour for an operator who would rather see the
share stall than see a simulated one.

THE INVARIANT THIS MODULE MUST NEVER BREAK
-------------------------------------------
**Crypto off is never less secure than crypto on.** Nothing in this file is read by the scanner,
the verifier, the remediation ticket, the deploy gate or the retester. Settlement is strictly
DOWNSTREAM of the fix: MOMUS decides what is broken and whether a fix holds without ever consulting
a balance, a rail or a chain. An empty vault, a missing splitter address and a crypto master switch
set to 0 all produce exactly the same security behaviour as a fully funded mainnet rail — only the
payout record differs. `tests/test_settlement_rails.py` pins this and will fail if it regresses.
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

    mode: str                      # the CONFIGURED tier — what the operator asked for
    settled: bool                  # True when the mode considers this share settled (incl. simulated)
    simulated: bool                # True on the sandbox rail — no value moved anywhere
    reason: str
    reference: str = ""            # uni receipt id, or a prepared on-chain call reference
    prepared_call: dict[str, Any] | None = None  # BASE/SOLANA: the unsigned call for the operator
    #: The rail that ACTUALLY carried this share: "sandbox" | "base" | "solana" | "none".
    #: Distinct from `mode` on purpose — a BASE deployment whose pool is unfunded settles on the
    #: sandbox rail, and the record has to say so rather than implying USDC moved.
    rail: str = ""
    #: Set when this share reached the sandbox rail only because a real rail declined.
    fallback_from: str = ""

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
        if target is SettlementMode.BASE and not looks_like_evm_address(splitter):
            return SettlementMode.HELD, (
                f"HELD: MOMUS_BOUNTY_SPLITTER={splitter!r} is not a 0x-prefixed 20-byte address "
                "— fail-closed rather than preparing a call against a typo")
        return target, f"{target.value.upper()}: real settlement enabled (crypto + explicit bounty opt-in)"

    return SettlementMode.UNI, f"UNI: unrecognized MOMUS_SETTLEMENT={requested!r} — defaulting to simulation"


#: What to do when a REAL rail declines to settle a share.
FALLBACK_SANDBOX = "sandbox"   # settle on the simulated UNI vault instead — keep the loop running
FALLBACK_HELD = "held"         # leave the share unsettled, as an intent


def resolve_fallback() -> tuple[str, str]:
    """Resolve MOMUS_REWARD_FALLBACK. Returns (fallback, human reason).

    Defaults to `sandbox`: a security auditor that stops being paid because a treasury is empty is
    a security auditor that stops. The reward rail is an economic concern and must never become a
    reason to stop finding and fixing things.
    """
    raw = (os.environ.get("MOMUS_REWARD_FALLBACK") or "").strip().lower()
    if raw in ("", FALLBACK_SANDBOX, "uni", "simulate", "simulated"):
        return FALLBACK_SANDBOX, (
            "sandbox: when a real rail cannot settle, the share is paid on the simulated UNI vault "
            "so the audit/repair loop keeps running — marked simulated, never redeemable as USDC")
    if raw in (FALLBACK_HELD, "none", "off", "stall"):
        return FALLBACK_HELD, "held: a real rail that cannot settle leaves the share as an intent"
    return FALLBACK_SANDBOX, (
        f"sandbox: unrecognized MOMUS_REWARD_FALLBACK={raw!r} — defaulting to the resilient rail")


_ADDR_CHARS = set("0123456789abcdefABCDEF")


def looks_like_evm_address(value: str) -> bool:
    """0x + 40 hex chars. `resolve_mode` only ever checked EMPTINESS, so a typo'd splitter address
    resolved to BASE and surfaced as a failed transaction the first time a human signed one."""
    v = (value or "").strip()
    return len(v) == 42 and v[:2].lower() == "0x" and all(c in _ADDR_CHARS for c in v[2:])


def _finding_key(finding_id: str) -> str:
    """bytes32 key the BountySplitter uses — keccak-free: a plain sha256 of the finding id, hex."""
    return "0x" + hashlib.sha256(finding_id.encode()).hexdigest()


def _role_key(role: str) -> str:
    return "0x" + hashlib.sha256(role.encode()).hexdigest()


class SettlementBackend:
    """Settles (or simulates settling) one share. Never broadcasts anything on its own."""

    def __init__(self, mode: SettlementMode, reason: str, *, uni_ledger_path: str = "",
                 splitter: str = "", token: str = "", chain: str = "base",
                 vault: "UniVault | None" = None, fallback: str = FALLBACK_SANDBOX,
                 fallback_reason: str = ""):
        self.mode = mode
        self.reason = reason
        self.fallback = fallback if fallback in (FALLBACK_SANDBOX, FALLBACK_HELD) else FALLBACK_SANDBOX
        self.fallback_reason = fallback_reason
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
    def from_env(cls, *, uni_ledger_path: str = "", crypto_enabled: bool | None = None,
                 vault: "UniVault | None" = None) -> "SettlementBackend":
        """Build the backend the running service uses.

        THE VAULT IS OPT-IN, and that is a deliberate reversal. It used to be reachable only from
        tests — `from_env` never passed one — so the shipped service skipped the balance check and a
        simulated treasury paid for ever. The obvious fix, attaching a vault by default, is WORSE: a
        fresh vault starts at $0.00 and refuses every release, so wiring it in silently would turn
        "the loop always runs" into "nothing is ever paid" for every existing deployment. That is
        precisely the stall this module exists to avoid.

        So: set `MOMUS_UNI_VAULT_PATH` to opt into real balance accounting (fund it, watch it drain,
        watch it refuse when short — the simulation then proves something about the economics).
        Leave it unset and the sandbox rail settles unconditionally, as it always has.
        """
        mode, reason = resolve_mode(crypto_enabled=crypto_enabled)
        fallback, fallback_reason = resolve_fallback()
        data_dir = (os.environ.get("MOMUS_DATA_DIR") or "data").strip() or "data"
        ledger = uni_ledger_path or os.environ.get("MOMUS_UNI_LEDGER_PATH") or f"{data_dir}/uni_settlements.jsonl"
        vault_path = (os.environ.get("MOMUS_UNI_VAULT_PATH") or "").strip()
        if vault is None and vault_path:
            from momus.vault import UniVault

            vault = UniVault(vault_path)
        return cls(mode, reason, uni_ledger_path=ledger, vault=vault,
                   fallback=fallback, fallback_reason=fallback_reason,
                   chain=(os.environ.get("MOMUS_BOUNTY_CHAIN") or "base").strip().lower())

    @property
    def settles_value(self) -> bool:
        """True only for the real-money tiers."""
        return self.mode in (SettlementMode.BASE, SettlementMode.SOLANA)

    def _settle_sandbox(self, *, finding_id: str, role: str, recipient: str, amount_usd: float,
                        fallback_from: str = "") -> SettlementDecision:
        """Settle one share on the simulated UNI vault. Used both as the default tier and as the
        fallback rail when a real tier declines."""
        ref = f"uni-{hashlib.sha256(f'{finding_id}|{role}'.encode()).hexdigest()[:16]}"
        # With a vault, the share must actually come OUT of a funded, reserved balance — an
        # underfunded vault refuses instead of paying, exactly as a real treasury would.
        if self.vault is not None:
            ok, why, tx = self.vault.release(finding_id, role, amount_usd)
            if not ok:
                return SettlementDecision(
                    mode=self.mode.value, settled=False, simulated=True,
                    reason=f"UNI vault refused the release — {why}", reference=ref,
                    rail="sandbox", fallback_from=fallback_from)
            ref = f"{ref}|vault-balance-{tx.balance_after}" if tx else ref
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": "uni_settlement",
               "finding_id": finding_id, "role": role, "recipient": recipient,
               "amount_usd": amount_usd, "reference": ref, "simulated": True,
               "rail": "sandbox", "fallback_from": fallback_from or None}
        if self._uni_path:
            with self._uni_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        prefix = (f"real rail '{fallback_from}' did not settle, so the share was paid on the "
                  f"SANDBOX rail — " if fallback_from else "")
        return SettlementDecision(
            mode=self.mode.value, settled=True, simulated=True,
            reason=prefix + "settled in the UNI simulation — no value moved"
                   + (f"; vault balance now ${self.vault.balance:.2f}" if self.vault else ""),
            reference=ref, rail="sandbox", fallback_from=fallback_from)

    def _fall_back(self, real: SettlementDecision, *, finding_id: str, role: str, recipient: str,
                   amount_usd: float) -> SettlementDecision:
        """A real rail declined. Either keep the loop running on the sandbox rail, or stall."""
        if self.fallback != FALLBACK_SANDBOX:
            return real
        sandbox = self._settle_sandbox(finding_id=finding_id, role=role, recipient=recipient,
                                       amount_usd=amount_usd, fallback_from=self.mode.value)
        # The unsigned call survives the fallback: an operator who wants to pay in USDC still can.
        sandbox.prepared_call = real.prepared_call
        sandbox.reason = f"{sandbox.reason} (real rail said: {real.reason})"
        return sandbox

    def settle_share(self, *, finding_id: str, role: str, recipient: str,
                     amount_usd: float) -> SettlementDecision:
        if self.mode is SettlementMode.UNI:
            return self._settle_sandbox(finding_id=finding_id, role=role, recipient=recipient,
                                        amount_usd=amount_usd)

        if self.mode is SettlementMode.HELD:
            return SettlementDecision(mode=self.mode.value, settled=False, simulated=False,
                                      reason=self.reason, rail="none")

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
                # BountySplitter stores OPAQUE bytes32 — it hashes nothing itself, so fundPool and
                # releaseShare only agree if both sides derive the keys identically. Its NatSpec
                # says roleId is keccak256("finder"), but MOMUS holds no keccak (adding one would
                # mean a chain dependency this satellite deliberately does not have), so it derives
                # both keys with sha256 and SAYS SO here, with the preimages. An operator funding a
                # pool by the NatSpec would key it under keccak and the release would revert with
                # "pool not funded" — a silent footgun until this note existed.
                "key_derivation": {
                    "algorithm": "sha256",
                    "findingId_preimage": finding_id,
                    "roleId_preimage": role,
                    "note": "fundPool MUST use these exact keys; the contract stores opaque bytes32",
                },
                "note": "UNSIGNED — the Treasury operator must sign and broadcast this call",
            }
            prepared = SettlementDecision(
                mode=self.mode.value, settled=False, simulated=False,
                reason="on-chain call PREPARED for the Treasury operator to sign (never auto-broadcast)",
                reference=f"base:{self.splitter}", prepared_call=call, rail="base")
            return self._fall_back(prepared, finding_id=finding_id, role=role,
                                   recipient=recipient, amount_usd=amount_usd)

        # SOLANA — routed through the existing Solana escrow by the operator.
        prepared = SettlementDecision(
            mode=self.mode.value, settled=False, simulated=False,
            reason="Solana settlement is routed through the existing Solana escrow by the operator",
            reference="solana", rail="solana",
            prepared_call={"chain": "solana", "finding_id": finding_id,
                           "role": role, "recipient": recipient, "amount_usd": amount_usd})
        return self._fall_back(prepared, finding_id=finding_id, role=role,
                               recipient=recipient, amount_usd=amount_usd)

    def describe(self) -> dict[str, Any]:
        return {"mode": self.mode.value, "reason": self.reason, "simulated": self.mode is SettlementMode.UNI,
                "moves_real_value": self.settles_value, "splitter": self.splitter or None,
                "chain": self.chain,
                # Why a share ended up where it did, without reading the source.
                "reward_fallback": self.fallback,
                "reward_fallback_reason": self.fallback_reason,
                "vault_attached": self.vault is not None,
                "vault_balance_usd": (round(self.vault.balance, 2) if self.vault is not None else None),
                # Load-bearing, and stated in the status payload on purpose: no rail, no balance and
                # no chain switch changes what MOMUS scans, verifies, tickets or gates.
                "gates_security": False}
