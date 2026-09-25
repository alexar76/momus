"""The UNI treasury vault — a simulated balance with a fully-explained transaction journal.

Without a balance, a simulated treasury "pays" forever: every bounty succeeds, nothing depletes,
and the simulation teaches you nothing about whether the economics actually work. So the UNI tier
gets a real vault: it is funded, it is debited, it refuses when short, and every movement is written
to a journal where each entry says **what it means in plain language** — not just an amount.

Six transaction kinds, and what each one means:

    FUND      an operator added simulated budget to the vault. Money enters the system here and
              nowhere else. In UNI this is a bookkeeping entry, not a transfer.
    RESERVE   a bounty passed the payout gate, so its pool is set aside. Reserved funds are still
              in the vault but are no longer available — this is what stops two concurrent claims
              from spending the same dollar.
    RELEASE   a contributor's share actually left the vault (finder / fixer / conductor). The
              reservation shrinks and the balance shrinks together.
    UNRESERVE a reservation was cancelled without paying — the claim was refused after reservation,
              or the release failed. Funds become available again.
    FORFEIT   a claimant's deposit was taken because independent verifiers refuted their claim.
              This is the only kind that INCREASES the vault from outside an operator top-up: spam
              funds the honest side.
    REFUND    a claimant's deposit came back because their claim was not refuted.

Fail-closed: a release the vault cannot cover is refused rather than allowed to go negative, and
the reason names the shortfall. The journal is append-only, so the history of a simulation run can
be replayed and audited exactly like a real ledger.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# What each transaction kind MEANS. Surfaced in the API and the docs so a reader never has to guess
# what a line in the journal represents.
TX_MEANING: dict[str, str] = {
    "fund": "an operator added simulated budget — the only way money enters the vault",
    "reserve": "a bounty cleared the payout gate; its pool is set aside and no longer available",
    "release": "a contributor's share left the vault (finder / fixer / conductor)",
    "unreserve": "a reservation was cancelled without paying; the funds are available again",
    "forfeit": "a refuted claimant's deposit was taken — spam funds the honest side",
    "refund": "a claimant's deposit returned because their claim was not refuted",
}


def _now_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class VaultTx:
    kind: str                 # one of TX_MEANING
    amount_usd: float         # always positive; `kind` says which way it moves
    balance_after: float
    reserved_after: float
    available_after: float
    means: str                # the plain-language meaning of THIS transaction
    finding_id: str = ""
    role: str = ""            # for a release: whose share
    note: str = ""
    ts: str = field(default_factory=_now_z)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class UniVault:
    """A simulated treasury balance for the UNI tier. Not a wallet: no keys, no chain, no transfer.

    ``balance`` is everything the vault holds. ``reserved`` is the part already promised to
    in-flight bounties. ``available`` (balance − reserved) is what a new bounty may draw on.
    """

    def __init__(self, path: str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self.balance = 0.0
        self.reserved = 0.0
        self._txs: list[VaultTx] = []
        self._reservations: dict[str, float] = {}   # finding_id -> still-reserved amount
        self._replay()

    # ── persistence: replay the journal, so state is always derivable from history ──
    def _replay(self) -> None:
        if not self._path.is_file():
            return
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            k, amt, fid = d.get("kind"), float(d.get("amount_usd") or 0), d.get("finding_id") or ""
            if k == "fund" or k == "forfeit":
                self.balance += amt
            elif k == "reserve":
                self.reserved += amt
                self._reservations[fid] = self._reservations.get(fid, 0.0) + amt
            elif k == "release":
                self.balance -= amt
                self.reserved -= amt
                self._reservations[fid] = max(0.0, self._reservations.get(fid, 0.0) - amt)
            elif k == "unreserve":
                self.reserved -= amt
                self._reservations[fid] = max(0.0, self._reservations.get(fid, 0.0) - amt)
            elif k == "refund":
                pass  # a deposit returning to its owner does not change the vault's own balance
            self._txs.append(VaultTx(**{k2: d.get(k2) for k2 in VaultTx.__dataclass_fields__ if k2 in d}))
        self.balance = round(self.balance, 6)
        self.reserved = round(max(0.0, self.reserved), 6)

    def _write(self, tx: VaultTx) -> VaultTx:
        self._txs.append(tx)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(tx.to_dict(), ensure_ascii=False) + "\n")
        return tx

    @property
    def available(self) -> float:
        return round(self.balance - self.reserved, 6)

    def _tx(self, kind: str, amount: float, *, finding_id: str = "", role: str = "",
            note: str = "") -> VaultTx:
        return self._write(VaultTx(
            kind=kind, amount_usd=round(amount, 6), balance_after=round(self.balance, 6),
            reserved_after=round(self.reserved, 6), available_after=self.available,
            means=TX_MEANING.get(kind, kind), finding_id=finding_id, role=role, note=note))

    # ── operations ─────────────────────────────────────────────────────────────
    def fund(self, amount_usd: float, note: str = "") -> VaultTx:
        """An operator adds simulated budget. The only inbound path besides a forfeited deposit."""
        if amount_usd <= 0:
            raise ValueError("fund amount must be positive")
        self.balance = round(self.balance + amount_usd, 6)
        return self._tx("fund", amount_usd, note=note or "operator top-up (simulated)")

    def reserve(self, finding_id: str, amount_usd: float) -> tuple[bool, str, VaultTx | None]:
        """Set a bounty's pool aside. Refuses (fail-closed) when the vault cannot cover it."""
        if amount_usd <= 0:
            return False, "nothing to reserve", None
        if amount_usd > self.available + 1e-9:
            return False, (f"insufficient available funds: need ${amount_usd:.2f}, "
                           f"available ${self.available:.2f} "
                           f"(balance ${self.balance:.2f} − reserved ${self.reserved:.2f})"), None
        self.reserved = round(self.reserved + amount_usd, 6)
        self._reservations[finding_id] = round(self._reservations.get(finding_id, 0.0) + amount_usd, 6)
        return True, "reserved", self._tx("reserve", amount_usd, finding_id=finding_id,
                                          note="pool set aside for a gate-approved bounty")

    def release(self, finding_id: str, role: str, amount_usd: float) -> tuple[bool, str, VaultTx | None]:
        """Pay one contributor's share out of that finding's reservation."""
        if amount_usd <= 0:
            return False, "nothing to release", None
        held = self._reservations.get(finding_id, 0.0)
        if amount_usd > held + 1e-9:
            return False, (f"share ${amount_usd:.2f} exceeds what is reserved for {finding_id} "
                           f"(${held:.2f}) — refusing rather than over-drawing"), None
        self.balance = round(self.balance - amount_usd, 6)
        self.reserved = round(self.reserved - amount_usd, 6)
        self._reservations[finding_id] = round(held - amount_usd, 6)
        return True, "released", self._tx("release", amount_usd, finding_id=finding_id, role=role,
                                          note=f"{role} share paid from the reservation")

    def unreserve(self, finding_id: str, note: str = "") -> VaultTx | None:
        """Give back whatever is still reserved for a finding (claim refused / release aborted)."""
        held = self._reservations.get(finding_id, 0.0)
        if held <= 0:
            return None
        self.reserved = round(self.reserved - held, 6)
        self._reservations[finding_id] = 0.0
        return self._tx("unreserve", held, finding_id=finding_id,
                        note=note or "reservation cancelled without paying")

    def forfeit_deposit(self, finding_id: str, amount_usd: float) -> VaultTx:
        """A refuted claimant's deposit is taken — the one inbound flow that is not an operator."""
        self.balance = round(self.balance + amount_usd, 6)
        return self._tx("forfeit", amount_usd, finding_id=finding_id,
                        note="deposit taken from a refuted claim")

    def refund_deposit(self, finding_id: str, amount_usd: float) -> VaultTx:
        """A non-refuted claimant's deposit returns to them (vault balance unchanged)."""
        return self._tx("refund", amount_usd, finding_id=finding_id,
                        note="deposit returned to a claimant whose finding was not refuted")

    # ── reporting ──────────────────────────────────────────────────────────────
    def state(self) -> dict[str, Any]:
        return {"balance_usd": round(self.balance, 6), "reserved_usd": round(self.reserved, 6),
                "available_usd": self.available, "transactions": len(self._txs),
                "open_reservations": {k: v for k, v in self._reservations.items() if v > 0}}

    def journal(self, limit: int = 50) -> list[dict[str, Any]]:
        """The transaction history, newest last, each line carrying its own plain-language meaning."""
        return [t.to_dict() for t in self._txs[-max(1, min(limit, 500)):]]

    @staticmethod
    def meanings() -> dict[str, str]:
        return dict(TX_MEANING)
