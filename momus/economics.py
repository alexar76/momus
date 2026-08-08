"""Bounty economics — the part with a known vulnerability class, designed defensively.

The one non-negotiable property (the operator stated it twice): **MOMUS finds and signs, but
someone else pays.** The budget holder is a *separate role with its own key*. No single key may
both declare a finding valid AND release its payout. This module is the treasury's decision
logic; it is the only place money is authorized, and it never trusts an LLM.

Roles and keys — each a DISTINCT Ed25519 key, held by a DISTINCT principal:

    ┌───────────┬──────────────────────────┬─────────────────────────┬────────────────────────┐
    │ role      │ key                      │ MAY                     │ MUST NOT               │
    ├───────────┼──────────────────────────┼─────────────────────────┼────────────────────────┤
    │ scanner   │ momus_signing_key        │ probe, sign Finding,    │ sign Verdict, release  │
    │ (MOMUS)   │ (in the MOMUS process)   │ sign Blame              │ payout, hold treasury  │
    │ verifier  │ verifier key(s)          │ sign Verdict            │ sign Finding, release  │
    │           │ (Metis / a 2nd operator) │ (confirm / refute)      │ payout                 │
    │ treasury  │ MOMUS_TREASURY_KEY_PATH  │ authorize + release a   │ sign Finding or Verdict│
    │           │ (NOT in MOMUS's control) │ bounty from its budget  │                        │
    │ customer  │ their hub identity       │ fund a scan escrow,     │ —                      │
    │           │                          │ confirm on own system   │                        │
    └───────────┴──────────────────────────┴─────────────────────────┴────────────────────────┘

The payout gate enforces, before ANY authorization:
  1. the finding's scanner signature verifies, and its severity is payable (info never pays);
  2. it carries enough CONFIRMING verdicts from DISTINCT verifier keys — 1 for low/medium,
     ≥2 for high/critical (mirrors slashing-v2's ≥2-distinct-issuers rule for strong actions);
  3. NONE of those verifier keys equals the scanner key OR the treasury key (independence);
  4. the finding's dedup_key has not already been paid (no re-run-the-scan replay);
  5. a claim deposit is posted, proportional to the bounty (spam/false claims are not free);
  6. per-scanner cooldown + daily cap are not exceeded;
  7. crypto is enabled AND funds are available — otherwise the decision is HELD (intent only),
     never released. In production a missing/invalid verifier set is REFUSED, never waved through.

Pricing decoupling (removes the incentive to fabricate): a *scan* is priced flat / per-CPU and
is billed whether or not anything is found. A *finding bounty* is a separate, verifier-gated
payout. "Did MOMUS find something" and "does MOMUS get paid for the scan" are independent.
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from oracle_core.signing import Signer

from momus.findings import (
    SEVERITY_RANK,
    Finding,
    Severity,
    Status,
    Verdict,
    finding_digest,
    verify_document_signature,
)


# Ed25519 small-order / low-order point encodings (the libsodium blacklist). A "verifier key"
# equal to one of these is not a real key — nobody holds its private half — yet it encodes to a
# did:key/pubkey string that *differs* from the scanner's, so a naive string-inequality check
# would count it toward the independence quorum. AWR/2 SPEC §6.3 documents exactly this trap
# ("forged independence"), and two shipped Ed25519 verifiers diverged on it. We reject these keys
# outright before any verdict they signed can count. (Adversarial review finding H2.)
_SMALL_ORDER_HEX = {
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
}


def is_valid_ed25519_pubkey(pub_b64: str) -> bool:
    """True iff the base64 key decodes to a canonical 32-byte, non-small-order Ed25519 point."""
    if not pub_b64:
        return False
    raw = None
    for decoder in (lambda s: base64.b64decode(s, validate=True),
                    lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))):
        try:
            raw = decoder(pub_b64)
            break
        except (ValueError, base64.binascii.Error):  # type: ignore[attr-defined]
            continue
    if raw is None or len(raw) != 32:
        return False
    return raw.hex() not in _SMALL_ORDER_HEX


# Infra components MOMUS must never AUTO-pay a bounty against — a bug in the auditor, the treasury,
# the verifier or the settlement gate is the exact lever to disable the payout controls, so those
# findings route to human review regardless of what label the claim carries. The set is checked
# SERVER-SIDE (here), never trusted from the claim text. (Adversarial review finding H7.)
_INFRA_COMPONENTS = {"momus", "momus-self", "self", "treasury", "verifier", "gate", "escrow"}


class Role(str, Enum):
    SCANNER = "scanner"
    VERIFIER = "verifier"
    TREASURY = "treasury"


class PayoutState(str, Enum):
    PAID = "paid"        # released on-chain / via escrow (crypto enabled + funded)
    HELD = "held"        # authorized in principle but not released (crypto off / unfunded) — intent
    REFUSED = "refused"  # gate failed — will never pay as-is


# Bounty schedule (USD). Severity → (base bounty, deposit ratio, distinct-verifier quorum).
# Deposit ratio is the fraction of the bounty a CLAIMANT must escrow to file a claim; it is
# slashed if the claim is refuted. info is unpayable and unclaimable, so griefing has no $0 path.
@dataclass(frozen=True)
class SeverityTerms:
    bounty_usd: float
    deposit_ratio: float
    quorum: int  # distinct confirming verifier keys required


_SCHEDULE: dict[Severity, SeverityTerms] = {
    Severity.INFO: SeverityTerms(0.0, 0.0, 0),          # never pays, never claimable
    Severity.LOW: SeverityTerms(2.0, 0.25, 1),
    Severity.MEDIUM: SeverityTerms(10.0, 0.25, 1),
    Severity.HIGH: SeverityTerms(50.0, 0.5, 2),          # strong action → ≥2 distinct verifiers
    Severity.CRITICAL: SeverityTerms(200.0, 0.5, 2),
}


def terms_for(severity: str) -> SeverityTerms:
    try:
        return _SCHEDULE[Severity(severity)]
    except (ValueError, KeyError):
        return _SCHEDULE[Severity.INFO]


# A confirmed-and-fixed vulnerability is not found into value — it is found, fixed and deployed.
# The bounty is a POOL split across the verified contributors, and every share is released by the
# Treasury on an OBJECTIVE, SIGNED signal — never on a participant's say-so, so no one grades or
# pays their own work. Fractions of the severity bounty; they sum to 1.0.
#
# Only ECONOMIC SUBJECTS get a share — parties that exercise independent JUDGMENT that must be
# verified and incentivised. The SKOPOS node agents that perform the redeploy are NOT subjects:
# they verify a signed chain and run one allowlisted command, so their correctness is guaranteed
# by cryptography, not by an incentive. They keep an operational identity key (to verify the
# DeployOrder) but earn nothing — the deployment share folds into the conductor (SKOPOS owns its
# limbs). Verifiers earn reputation, not a per-verdict cash drip (that channel is a drain vector).
SPLIT_SCHEDULE: dict[str, float] = {
    "finder": 0.50,      # MOMUS — gated on the finding being independently confirmed
    "fixer": 0.35,       # AI-Factory — gated on MOMUS's signed 'fixed' re-test verdict
    "conductor": 0.15,   # SKOPOS — gated on a completed job (fixed verdict + deploy ack)
}


@dataclass
class Decision:
    """The treasury's ruling on one finding. Carries every reason so it is auditable."""

    finding_id: str
    dedup_key: str
    severity: str
    state: str                       # PayoutState
    amount_usd: float
    reasons: list[str] = field(default_factory=list)
    distinct_verifiers: list[str] = field(default_factory=list)
    authorized_by: str = ""          # treasury pubkey (never the scanner)
    authorized_at: str = ""
    # What the settlement tier did with the money (UNI simulation / HELD intent / prepared on-chain
    # call). Part of the signed decision so the audit tail records HOW it settled, not just that it did.
    settlement: dict[str, Any] = field(default_factory=dict)
    signature: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "dedup_key": self.dedup_key,
            "severity": self.severity,
            "state": self.state,
            "amount_usd": self.amount_usd,
            "settlement": self.settlement,
            "reasons": self.reasons,
            "distinct_verifiers": self.distinct_verifiers,
            "authorized_by": self.authorized_by,
            "authorized_at": self.authorized_at,
        }


class KeyRing:
    """Holds the role keys, and REFUSES to exist if the separation is violated.

    The scanner key always lives in the MOMUS process. The treasury key normally does NOT — it is
    injected only in a deployment where MOMUS is *also* trusted to run the treasury (e.g. a local
    demo). When both are present we hard-assert they are different keys, so even a misconfigured
    single-box demo cannot collapse the roles into one key.
    """

    def __init__(self, scanner_key_path: str, treasury_key_path: str | None = None):
        self.scanner = Signer(scanner_key_path)
        if not is_valid_ed25519_pubkey(self.scanner.public_key_b64):
            raise ValueError("scanner key is not a canonical Ed25519 public key")
        self.treasury: Signer | None = None
        if treasury_key_path:
            self.treasury = Signer(treasury_key_path)
            if not is_valid_ed25519_pubkey(self.treasury.public_key_b64):
                raise ValueError("treasury key is not a canonical Ed25519 public key")
            if self.treasury.public_key_b64 == self.scanner.public_key_b64:
                raise ValueError(
                    "Treasury key must differ from the scanner key — MOMUS may not pay itself. "
                    "Point MOMUS_TREASURY_KEY_PATH at a key held by a different principal."
                )

    @property
    def scanner_pubkey(self) -> str:
        return self.scanner.public_key_b64

    @property
    def treasury_pubkey(self) -> str | None:
        return self.treasury.public_key_b64 if self.treasury else None


class BountyLedger:
    """Append-only JSONL ledger of claims, decisions and payments. The dedup index is the replay
    guard: a dedup_key that already reached PAID or HELD cannot be paid again."""

    def __init__(self, path: str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._paid_dedup: set[str] = set()
        self._daily: dict[str, float] = {}  # "scanner|YYYY-MM-DD" -> total authorized today
        self._last_claim_ts: dict[str, float] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.is_file():
            return
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Only a PAID decision consumes a bug's dedup identity. A HELD decision is an INTENT
            # that never settled (crypto off, or the vault was short) — treating it as spent would
            # let a temporary funding shortfall permanently burn a legitimate bounty, which a test
            # caught the moment the vault could actually run out. When funds arrive the claim is
            # payable again, and the resulting PAID entry is what blocks every later duplicate.
            if rec.get("kind") == "decision" and rec.get("state") == PayoutState.PAID.value:
                dk = rec.get("dedup_key")
                if dk:
                    self._paid_dedup.add(dk)
                day = (rec.get("authorized_at") or "")[:10]
                scanner = rec.get("scanner", "")
                if day and scanner:
                    self._daily[f"{scanner}|{day}"] = self._daily.get(f"{scanner}|{day}", 0.0) + float(rec.get("amount_usd", 0))

    def already_paid(self, dedup_key: str) -> bool:
        return dedup_key in self._paid_dedup

    def daily_total(self, scanner_pubkey: str, day: str) -> float:
        return self._daily.get(f"{scanner_pubkey}|{day}", 0.0)

    def seconds_since_last_claim(self, scanner_pubkey: str, now: float) -> float:
        last = self._last_claim_ts.get(scanner_pubkey)
        return float("inf") if last is None else now - last

    def append(self, kind: str, payload: dict[str, Any]) -> None:
        rec = {"kind": kind, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **payload}
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def record_decision(self, decision: Decision, scanner_pubkey: str) -> None:
        # Only PAID consumes the dedup identity — see _load for why HELD must stay retryable.
        if decision.state == PayoutState.PAID.value:
            self._paid_dedup.add(decision.dedup_key)
            day = decision.authorized_at[:10]
            self._daily[f"{scanner_pubkey}|{day}"] = self._daily.get(f"{scanner_pubkey}|{day}", 0.0) + decision.amount_usd
        self.append("decision", {**decision.to_dict(), "scanner": scanner_pubkey})

    def record_claim(self, scanner_pubkey: str, now: float, payload: dict[str, Any]) -> None:
        self._last_claim_ts[scanner_pubkey] = now
        self.append("claim", payload)

    def entries(self, limit: int = 200) -> list[dict[str, Any]]:
        if not self._path.is_file():
            return []
        lines = self._path.read_text(encoding="utf-8").splitlines()
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out


# Per-scanner rate controls (mirror slashing-v2's cooldown + daily cap).
DEFAULT_CLAIM_COOLDOWN_S = float(os.environ.get("MOMUS_CLAIM_COOLDOWN_S", "5"))
DEFAULT_DAILY_CAP_USD = float(os.environ.get("MOMUS_DAILY_CAP_USD", "1000"))


class PayoutGate:
    """The treasury's authorization logic. Owns the treasury key; consumes findings + verdicts;
    emits a signed Decision. This is the single chokepoint where money is authorized."""

    def __init__(self, keyring: KeyRing, ledger: BountyLedger, *,
                 crypto_enabled: bool, prod: bool,
                 daily_cap_usd: float = DEFAULT_DAILY_CAP_USD,
                 cooldown_s: float = DEFAULT_CLAIM_COOLDOWN_S,
                 external_verifiers: set[str] | None = None,
                 settlement: "SettlementBackend | None" = None):
        self._keys = keyring
        self._ledger = ledger
        self._crypto = crypto_enabled
        self._prod = prod
        # The settlement tier decides what "paid" actually means: a UNI simulation (the default —
        # the whole loop runs, no value moves), a HELD intent, or a real on-chain settlement that
        # needs its OWN opt-in beyond the crypto master switch. See momus.settlement.
        from momus.settlement import SettlementBackend, SettlementMode
        self._settlement = settlement or SettlementBackend.from_env(crypto_enabled=crypto_enabled)
        self._SettlementMode = SettlementMode
        self._daily_cap = daily_cap_usd
        self._cooldown = cooldown_s
        # Pre-registered pubkeys of verifiers operated by a DIFFERENT principal (e.g. Metis).
        # Distinct did:keys prove distinct keys, not distinct parties (adversarial review H1) —
        # so a high/critical payout additionally requires at least one confirmation from a
        # registered EXTERNAL verifier, an operator-custody assumption made explicit and gated.
        self._external = {k for k in (external_verifiers or set()) if is_valid_ed25519_pubkey(k)}

    @classmethod
    def external_verifiers_from_env(cls) -> set[str]:
        raw = os.environ.get("MOMUS_EXTERNAL_VERIFIERS", "")
        return {k.strip() for k in raw.split(",") if k.strip()}

    def _distinct_confirming(self, finding: Finding, verdicts: list[Verdict]) -> tuple[list[str], list[str]]:
        """Return (distinct_confirming_verifier_pubkeys, reasons_for_rejections).

        A verdict counts toward quorum only if ALL hold:
          * verdict == "confirmed" with score high enough,
          * its signature verifies under its verifier_pubkey,
          * it binds to THIS finding's digest (no transplant),
          * the verifier key is NOT the scanner key and NOT the treasury key (independence),
          * each distinct verifier key counts at most once (no ballot-stuffing one key).
        """
        reasons: list[str] = []
        digest = finding_digest(finding)
        scanner = finding.scanner_pubkey or self._keys.scanner_pubkey
        treasury = self._keys.treasury_pubkey
        seen: set[str] = set()
        distinct: list[str] = []
        for v in verdicts:
            if v.finding_id != finding.finding_id:
                continue
            if v.verdict != "confirmed":
                continue
            if v.finding_digest != digest:
                reasons.append(f"verdict {v.verifier_id}: digest mismatch (stale/transplanted) — ignored")
                continue
            if v.score < 0.5:
                reasons.append(f"verdict {v.verifier_id}: score {v.score} below 0.5 — ignored")
                continue
            if not v.verifier_pubkey:
                reasons.append(f"verdict {v.verifier_id}: unsigned — ignored")
                continue
            if not is_valid_ed25519_pubkey(v.verifier_pubkey):
                reasons.append(f"verdict {v.verifier_id}: malformed/small-order verifier key — ignored")
                continue
            if not verify_document_signature(v.canonical(), v.signature, v.verifier_pubkey):
                reasons.append(f"verdict {v.verifier_id}: bad signature — ignored")
                continue
            if v.verifier_pubkey == scanner:
                reasons.append("verdict rejected: verifier key == scanner key (self-verification)")
                continue
            if treasury and v.verifier_pubkey == treasury:
                reasons.append("verdict rejected: verifier key == treasury key (self-dealing)")
                continue
            if v.verifier_pubkey in seen:
                continue  # one key, one vote
            seen.add(v.verifier_pubkey)
            distinct.append(v.verifier_pubkey)
        return distinct, reasons

    def authorize(self, finding: Finding, verdicts: list[Verdict], *,
                  deposit_posted_usd: float = 0.0, now: float | None = None,
                  settle: bool = True) -> Decision:
        """Decide (and by default settle) a single finder payout.

        ``settle=False`` decides without moving anything — used by :meth:`authorize_split`, which
        settles each share itself. Without that split, the base decision settled the FULL pool for
        role="finder" and then the finder share settled 50% again: two settlement records and, with
        a vault, a genuine double debit."""
        now = time.time() if now is None else now
        authorized_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        scanner = finding.scanner_pubkey or self._keys.scanner_pubkey
        terms = terms_for(finding.severity)
        # ALWAYS recompute the dedup identity from the finding's content. Taking the declared
        # `dedup_key` off the document let the claimant choose its own dedup identity: the scanner
        # signs the field, so a scanner that wants to be paid twice for one bug just varies it and
        # the ledger's replay guard never matches. A mismatch is refused outright below.
        computed_dedup = finding.compute_dedup_key()
        decision = Decision(
            finding_id=finding.finding_id,
            dedup_key=computed_dedup,
            severity=finding.severity,
            state=PayoutState.REFUSED.value,
            amount_usd=0.0,
            authorized_at=authorized_at,
        )

        # 0. The treasury key must exist and must not be the scanner key — the separation.
        if self._keys.treasury is None:
            decision.reasons.append("no treasury key configured — MOMUS cannot pay itself (fail-closed)")
            return self._finalize(decision, scanner, sign=False)
        decision.authorized_by = self._keys.treasury_pubkey or ""

        # 0b. Infra default-deny: a finding against MOMUS/treasury/verifier/gate/escrow is the
        # exact lever to disable the payout controls, so it NEVER auto-pays — human review only.
        # Checked server-side against the target, never trusting the claim's own label (H7).
        if finding.target in _INFRA_COMPONENTS or finding.target_kind in ("self", "meta"):
            decision.reasons.append(
                f"finding targets ecosystem infra ('{finding.target}') — routed to human review, "
                f"auto-payout denied"
            )
            return self._finalize(decision, scanner, sign=True)

        # 1. Finding must be a real, scanner-signed claim of a payable severity.
        if not verify_document_signature(finding.canonical(), finding.signature, scanner):
            decision.reasons.append("finding signature invalid — refused")
            return self._finalize(decision, scanner, sign=True)
        if terms.bounty_usd <= 0 or terms.quorum <= 0:
            decision.reasons.append(f"severity '{finding.severity}' is not payable")
            return self._finalize(decision, scanner, sign=True)
        if finding.outcome != "finding":
            decision.reasons.append(f"outcome '{finding.outcome}' is not a finding — nothing to pay")
            return self._finalize(decision, scanner, sign=True)

        # 2a. The declared dedup identity must match the computed one. A claimant that declares a
        # different key is trying to escape the replay guard, so this is a refusal, not a repair.
        if finding.dedup_key and finding.dedup_key != computed_dedup:
            decision.reasons.append(
                f"declared dedup identity does not match the finding's content "
                f"(declared {finding.dedup_key}, computed {computed_dedup}) — refused")
            return self._finalize(decision, scanner, sign=True)

        # 2b. Replay guard: a bug pays once, ever.
        if self._ledger.already_paid(decision.dedup_key):
            decision.reasons.append("dedup_key already paid/held — duplicate finding, no double pay")
            return self._finalize(decision, scanner, sign=True)

        # 3. Independent confirming quorum from DISTINCT verifier keys.
        distinct, vreasons = self._distinct_confirming(finding, verdicts)
        decision.reasons.extend(vreasons)
        decision.distinct_verifiers = distinct
        if len(distinct) < terms.quorum:
            decision.reasons.append(
                f"need {terms.quorum} distinct independent confirmation(s), have {len(distinct)}"
            )
            return self._finalize(decision, scanner, sign=True)

        # 3b. High/critical must include at least one confirmation from a pre-registered EXTERNAL
        # verifier (a different principal, e.g. Metis) — distinct keys are not distinct parties if
        # one operator holds them all (H1). In prod this is required; without any external verifier
        # configured, a strong payout fails CLOSED rather than trusting operator-held keys alone.
        if terms.quorum >= 2:
            has_external = any(k in self._external for k in distinct)
            if not has_external:
                if self._external:
                    decision.reasons.append(
                        "high/critical payout requires ≥1 confirmation from a registered external "
                        "verifier (none of the confirmations came from MOMUS_EXTERNAL_VERIFIERS)"
                    )
                    return self._finalize(decision, scanner, sign=True)
                if self._prod:
                    decision.reasons.append(
                        "high/critical payout requires a registered external verifier, but "
                        "MOMUS_EXTERNAL_VERIFIERS is empty in prod — fail-closed"
                    )
                    return self._finalize(decision, scanner, sign=True)
                decision.reasons.append(
                    "WARNING: no external verifier registered; strong payout rests on "
                    "operator key custody alone (set MOMUS_EXTERNAL_VERIFIERS + AIFACTORY_PROD)"
                )

        # 4. Anti-griefing deposit must be posted, proportional to the bounty.
        required_deposit = round(terms.bounty_usd * terms.deposit_ratio, 6)
        if deposit_posted_usd + 1e-9 < required_deposit:
            decision.reasons.append(
                f"claim deposit ${deposit_posted_usd} below required ${required_deposit} "
                f"({int(terms.deposit_ratio * 100)}% of bounty) — refused"
            )
            return self._finalize(decision, scanner, sign=True)

        # 5. Cooldown + daily cap per scanner identity.
        since = self._ledger.seconds_since_last_claim(scanner, now)
        if since < self._cooldown:
            decision.reasons.append(f"cooldown: {since:.1f}s since last claim < {self._cooldown}s")
            return self._finalize(decision, scanner, sign=True)
        day_total = self._ledger.daily_total(scanner, authorized_at[:10])
        if day_total + terms.bounty_usd > self._daily_cap:
            decision.reasons.append(
                f"daily cap ${self._daily_cap} would be exceeded (${day_total} + ${terms.bounty_usd})"
            )
            return self._finalize(decision, scanner, sign=True)

        # 6. All gates passed. What "paid" means now depends on the SETTLEMENT TIER:
        #    UNI  → settled in simulation (full loop runs, no value moves) → PAID + simulated
        #    HELD → recorded as an intent only (crypto off, or on-chain never opted in)
        #    BASE/SOLANA → an unsigned on-chain call prepared for the Treasury operator → HELD
        #                  until they broadcast it (MOMUS never broadcasts its own payout).
        decision.amount_usd = terms.bounty_usd
        if not settle:
            # Decision only — authorize_split settles each share itself, so settling here too
            # would debit the pool twice.
            decision.state = PayoutState.PAID.value
            decision.reasons.append(
                f"gates passed on {len(distinct)} independent confirmation(s); settlement deferred "
                f"to the per-share split")
            return self._finalize(decision, scanner, sign=True)
        s = self._settlement.settle_share(finding_id=finding.finding_id, role="finder",
                                          recipient=scanner, amount_usd=terms.bounty_usd)
        decision.settlement = s.to_dict()
        if s.settled:
            decision.state = PayoutState.PAID.value
            decision.reasons.append(
                f"gates passed on {len(distinct)} independent confirmation(s); {s.reason} "
                f"(authorized by treasury {decision.authorized_by[:12]}…)")
        else:
            decision.state = PayoutState.HELD.value
            decision.reasons.append(f"gates passed; not released — {s.reason}")
        return self._finalize(decision, scanner, sign=True)

    def authorize_split(self, finding: Finding, verdicts: list[Verdict], *,
                        participants: dict[str, str], deposit_posted_usd: float = 0.0,
                        fix_verdict: dict[str, Any] | None = None,
                        deploy_ack: dict[str, Any] | None = None,
                        momus_pubkey: str = "", now: float | None = None) -> dict[str, Any]:
        """Split the bounty pool across the VERIFIED contributors of the remediation pipeline.

        Every share is released by the Treasury and gated on an objective, signed signal — never on
        a participant's say-so:
          * finder    → the normal payout gate (finding independently confirmed);
          * fixer      → a MOMUS-signed ``fixed`` re-test verdict for THIS finding;
          * conductor  → fixer gate satisfied AND a deploy acknowledgement present;
          * deployer   → same as conductor (it executed the signed deploy).

        ``participants`` maps role → recipient identity (pubkey/address). Only roles present pay.
        Returns {"finder": Decision, "shares": [{role, recipient, amount_usd, released}], ...}.
        The finder share reuses ``authorize`` (so dedup/quorum/deposit/fail-closed all apply); the
        other shares only ever release if the finder share did (nothing pays for a non-bug)."""
        base = self.authorize(finding, verdicts, deposit_posted_usd=deposit_posted_usd, now=now,
                              settle=False)
        pool = base.amount_usd if base.state in (PayoutState.PAID.value, PayoutState.HELD.value) else 0.0
        shares: list[dict[str, Any]] = []
        released_state = base.state  # 'paid' | 'held' | 'refused'

        def _share(role: str, gated_ok: bool, reason: str) -> None:
            frac = SPLIT_SCHEDULE.get(role, 0.0)
            recipient = participants.get(role, "")
            amount = round(pool * frac, 6) if (pool > 0 and recipient) else 0.0
            eligible = bool(recipient and gated_ok and amount > 0
                            and base.state in (PayoutState.PAID.value, PayoutState.HELD.value))
            settlement: dict[str, Any] = {}
            if eligible:
                s = self._settlement.settle_share(finding_id=finding.finding_id, role=role,
                                                  recipient=recipient, amount_usd=amount)
                settlement = s.to_dict()
                state = PayoutState.PAID.value if s.settled else PayoutState.HELD.value
                reason = f"{reason} · {s.reason}"
            else:
                state = PayoutState.REFUSED.value
            shares.append({"role": role, "recipient": recipient, "fraction": frac,
                           "amount_usd": amount, "state": state, "reason": reason,
                           "settlement": settlement})

        # finder share — always mirrors the base decision (it IS the base gate).
        _share("finder", base.state != PayoutState.REFUSED.value,
               "confirmed finding" if pool else base.reasons[-1] if base.reasons else "not payable")

        # fixer share — needs a MOMUS-signed 'fixed' verdict bound to this finding.
        fix_ok, fix_reason = self._fix_verdict_ok(finding, fix_verdict, momus_pubkey)
        _share("fixer", fix_ok, fix_reason)

        # conductor — needs the fix verified AND a deploy acknowledgement (the node agent, SKOPOS's
        # limb, is not a subject and earns no separate share; its work is the conductor's).
        deploy_ok = bool(deploy_ack and deploy_ack.get("accepted"))
        gate2 = fix_ok and deploy_ok
        reason2 = "fixed + deployed" if gate2 else ("no deploy ack" if fix_ok else fix_reason)
        _share("conductor", gate2, reason2)

        total_released = round(sum(s["amount_usd"] for s in shares if s["state"] == PayoutState.PAID.value), 6)
        settle_info = self._settlement.describe()
        self._ledger.append("split", {"finding_id": finding.finding_id, "pool_usd": pool,
                                      "base_state": base.state, "total_released_usd": total_released,
                                      "settlement": settle_info, "shares": shares})
        return {"finder_decision": base.to_dict(), "pool_usd": pool, "base_state": released_state,
                "shares": shares, "total_released_usd": total_released, "settlement": settle_info}

    def _fix_verdict_ok(self, finding: Finding, fix_verdict: dict[str, Any] | None,
                        momus_pubkey: str) -> tuple[bool, str]:
        if not fix_verdict:
            return False, "no fix verdict — fixer share withheld"
        if not fix_verdict.get("fixed"):
            return False, "fix verdict is not 'fixed' — fixer share withheld"
        if fix_verdict.get("finding_id") != finding.finding_id:
            return False, "fix verdict is for a different finding"
        # FAIL CLOSED. The previous form was `if key and sig.get("value") and not verify(...)`,
        # which skipped verification whenever either operand was falsy — so an unsigned
        # {"fixed": true} (or a call with no momus_pubkey) released the fixer and conductor shares
        # on nothing at all. A missing key or a missing signature is now a refusal, not a pass.
        key = momus_pubkey or ""
        if not key:
            return False, "no MOMUS pubkey configured to verify the fix verdict — fixer share withheld"
        sig = fix_verdict.get("signature") or {}
        if not sig.get("value"):
            return False, "fix verdict is unsigned — fixer share withheld"
        body = {k: v for k, v in fix_verdict.items() if k != "signature"}
        if not verify_document_signature(body, sig, key):
            return False, "fix verdict signature does not verify — fixer share withheld"
        return True, "MOMUS-signed 'fixed' verdict"

    def adjudicate_deposit(self, finding: Finding, verdicts: list[Verdict],
                           deposit_posted_usd: float) -> dict[str, Any]:
        """Rule on a claim's DEPOSIT, separately from the bounty.

        The deposit is the per-claim, proportional anti-griefing collateral. A claim that
        independent verifiers REFUTE forfeits the WHOLE deposit — not a 5%-style reputation slash
        (adversarial review H9): the deposit already *is* the proportional collateral, so bleeding
        it 5% at a time would make spamming near-free. A claim that confirms, or that is genuinely
        inconclusive because the target was unreachable, refunds. This keeps the honest-but-
        unreproducible report cheap while making a *refuted* (i.e. wrong) claim actually cost."""
        refuting = 0
        confirming = 0
        digest = finding_digest(finding)
        scanner = finding.scanner_pubkey or self._keys.scanner_pubkey
        for v in verdicts:
            if v.finding_id != finding.finding_id or v.finding_digest != digest:
                continue
            if not is_valid_ed25519_pubkey(v.verifier_pubkey) or v.verifier_pubkey == scanner:
                continue
            if not verify_document_signature(v.canonical(), v.signature, v.verifier_pubkey):
                continue
            if v.verdict == "refuted":
                refuting += 1
            elif v.verdict == "confirmed":
                confirming += 1
        if refuting > confirming and refuting >= 1:
            self._ledger.append("deposit", {"finding_id": finding.finding_id, "ruling": "forfeit",
                                            "amount_usd": deposit_posted_usd, "refuting": refuting})
            return {"ruling": "forfeit", "forfeited_usd": deposit_posted_usd, "refunded_usd": 0.0,
                    "reason": f"{refuting} independent refutation(s) outweigh {confirming} confirmation(s)"}
        self._ledger.append("deposit", {"finding_id": finding.finding_id, "ruling": "refund",
                                        "amount_usd": deposit_posted_usd})
        return {"ruling": "refund", "forfeited_usd": 0.0, "refunded_usd": deposit_posted_usd,
                "reason": "not refuted — deposit refunded"}

    def _finalize(self, decision: Decision, scanner_pubkey: str, *, sign: bool) -> Decision:
        if sign and self._keys.treasury is not None:
            canon = json.dumps(decision.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            decision.signature = self._keys.treasury.sign_payload(canon)
        self._ledger.record_decision(decision, scanner_pubkey)
        return decision
