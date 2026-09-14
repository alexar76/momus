"""KnowledgeStore — MOMUS's self-learning memory.

This is where MOMUS learns from its own work, from peers' work, and from the outside world, and
turns that into which probes to run first next time. The mechanism is a principled bandit, not a
counter:

* Each ``(attack-category, target-kind)`` pair has a **Beta(α, β) posterior** over "does a probe
  of this class find a real bug here." A *confirmed* finding is a success (α += 1); a *refuted* or
  clean *no-finding* is a failure (β += 1); an *inconclusive* (target unreachable) is not signal
  and updates nothing.
* **Others' work** — a peer MOMUS's confirmed finding — updates the same posterior at a discount,
  so the fleet learns together without one peer being able to dominate the prior.
* **The outside world** — distilled threat-intel cards — fold in as **pseudo-successes on the
  prior** (α_eff = α + external_boost), recency-decayed. A vulnerability class the world just
  reported gets probed sooner, even before MOMUS has its own data on it.
* Probe ordering uses **UCB1** over the effective posterior mean, so MOMUS exploits what has paid
  off while still exploring classes it has little data on — and it is deterministic given the
  counts, which keeps scans reproducible and testable.

Nothing here can authorize a payout, add a target, or raise a severity. Learning steers *attention*
(order + seeds); the money and the allowlist live behind keys and code it never touches.
"""

from __future__ import annotations

import json
import math
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from momus.intel.cards import ATTACK_CATEGORIES, KnowledgeCard

# UCB exploration constant and external-intel influence cap.
_UCB_C = 1.4
_EXT_PRIOR_CAP = 3.0            # a category's external boost is capped so intel can't dominate data
_PEER_SUCCESS_WEIGHT = 0.5     # a peer's confirmed finding counts half of our own
_CARD_HALF_LIFE_DAYS = 30.0    # external card influence halves every 30 days


def _now() -> float:
    return time.time()


def _now_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class _Arm:
    alpha: float = 1.0   # successes + 1 (uniform prior)
    beta: float = 1.0    # failures + 1

    @property
    def n(self) -> float:
        return self.alpha + self.beta


class KnowledgeStore:
    def __init__(self, data_dir: str):
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._cards_path = self._dir / "knowledge_cards.jsonl"
        self._outcomes_path = self._dir / "learning_state.json"
        self._cards: dict[str, KnowledgeCard] = {}
        self._arms: dict[str, _Arm] = {}
        self._load()

    # ── persistence ──────────────────────────────────────────────────────────
    def _load(self) -> None:
        if self._cards_path.is_file():
            for line in self._cards_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    self._cards[d["card_id"]] = KnowledgeCard(**d)
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
        if self._outcomes_path.is_file():
            try:
                state = json.loads(self._outcomes_path.read_text(encoding="utf-8"))
                for k, v in (state.get("arms") or {}).items():
                    self._arms[k] = _Arm(alpha=float(v.get("alpha", 1.0)), beta=float(v.get("beta", 1.0)))
            except (json.JSONDecodeError, TypeError):
                pass

    def _persist_arms(self) -> None:
        state = {"updated_at": _now_z(),
                 "arms": {k: {"alpha": a.alpha, "beta": a.beta} for k, a in self._arms.items()}}
        self._outcomes_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    # ── learning updates ───────────────────────────────────────────────────────
    @staticmethod
    def _key(category: str, target_kind: str) -> str:
        return f"{category}|{target_kind}"

    def _arm(self, category: str, target_kind: str) -> _Arm:
        return self._arms.setdefault(self._key(category, target_kind), _Arm())

    def record_outcome(self, category: str, target_kind: str, outcome: str, *, weight: float = 1.0) -> None:
        """Update the posterior from one probe outcome. ``outcome`` is 'finding'|'no_finding'|
        'inconclusive' (raw scanner outcome) OR 'confirmed'|'refuted' (post-verification)."""
        if category not in ATTACK_CATEGORIES:
            return
        arm = self._arm(category, target_kind)
        if outcome in ("confirmed", "finding"):
            arm.alpha += weight
        elif outcome in ("refuted", "no_finding"):
            arm.beta += weight
        # inconclusive → no update; an unreachable target is not evidence either way.
        self._persist_arms()

    def record_scan_report(self, report: Any) -> None:
        """Fold a whole ScanReport's probe records into the posteriors (own work)."""
        for rec in getattr(report, "records", []):
            self.record_outcome(getattr(rec, "category", ""), _kind_of(rec), getattr(rec, "outcome", ""))

    def ingest_peer_finding(self, finding: dict[str, Any]) -> None:
        """Others' work: a peer's confirmed finding is a discounted success signal."""
        cat = finding.get("category", "")
        kind = finding.get("target_kind", "generic")
        status = finding.get("status", "")
        outcome = "confirmed" if status == "confirmed" else "finding"
        self.record_outcome(cat, kind, outcome, weight=_PEER_SUCCESS_WEIGHT)

    def ingest_card(self, card: KnowledgeCard) -> bool:
        """Store a distilled threat-intel card (dedup by id). Returns True if newly added."""
        if not card.is_actionable() or card.card_id in self._cards:
            return False
        self._cards[card.card_id] = card
        with self._cards_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(card.to_dict(), ensure_ascii=False) + "\n")
        return True

    # ── external-intel prior ───────────────────────────────────────────────────
    def _external_boost(self, category: str) -> float:
        """Recency-decayed sum of card weights for this category, capped."""
        boost = 0.0
        now = _now()
        for card in self._cards.values():
            if category not in card.mapped_categories:
                continue
            age_days = max(0.0, (now - _parse_ts(card.ingested_at)) / 86400.0)
            decay = 0.5 ** (age_days / _CARD_HALF_LIFE_DAYS)
            boost += card.weight * decay
        return min(_EXT_PRIOR_CAP, boost)

    # ── scoring + ordering ───────────────────────────────────────────────────
    def score(self, category: str, target_kind: str) -> float:
        """UCB1 score over the external-informed posterior. Higher → probe sooner.

        External intel raises the *exploitation* term (the posterior mean) as pseudo-successes on
        the prior, but the *exploration* term is based on REAL observation count only — a class the
        world just reported is not "well explored" by MOMUS, so intel must never suppress its own
        exploration bonus. (This split is what a naive `alpha_eff` in both terms gets wrong.)"""
        arm = self._arm(category, target_kind)
        alpha_eff = arm.alpha + self._external_boost(category)
        mean = alpha_eff / (alpha_eff + arm.beta)
        total = sum(a.n for a in self._arms.values()) + 1.0
        exploration = _UCB_C * math.sqrt(math.log(total + 1.0) / arm.n)  # arm.n = real pulls only
        return mean + exploration

    def order_strategies(self, strategies: list[Any], target_kind: str) -> list[Any]:
        """Reorder strategies most-promising-first for this target kind (self-learning)."""
        return sorted(strategies, key=lambda s: self.score(getattr(s, "category", "generic"), target_kind),
                      reverse=True)

    def seed_hints(self, categories: list[str]) -> list[str]:
        """Adversarial-shape hints drawn from cards mapped to the given categories (bounded)."""
        hints: list[str] = []
        for card in self._cards.values():
            if any(c in categories for c in card.mapped_categories):
                hints.extend(card.seed_hints)
        # stable de-dup, bounded
        seen: set[str] = set()
        out: list[str] = []
        for h in hints:
            if h not in seen:
                seen.add(h)
                out.append(h)
        return out[:12]

    # ── introspection (for the momus.intel@v1 capability + live panel) ─────────
    def summary(self, top_n: int = 8) -> dict[str, Any]:
        cards = sorted(self._cards.values(), key=lambda c: c.ingested_at, reverse=True)
        # Rank categories by their best score across target kinds.
        cat_scores = {}
        kinds = {k.split("|", 1)[1] for k in self._arms} or {"oracle"}
        for cat in ATTACK_CATEGORIES:
            cat_scores[cat] = round(max((self.score(cat, tk) for tk in kinds), default=0.0), 4)
        top_cats = sorted(cat_scores.items(), key=lambda kv: kv[1], reverse=True)
        return {
            "cards_total": len(self._cards),
            "recent_cards": [c.to_dict() for c in cards[:top_n]],
            "category_scores": dict(top_cats),
            "arms": {k: {"alpha": round(a.alpha, 3), "beta": round(a.beta, 3),
                         "mean": round(a.alpha / a.n, 3)} for k, a in self._arms.items()},
            "learned_pairs": len(self._arms),
        }


def _parse_ts(z: str) -> float:
    try:
        return time.mktime(time.strptime(z, "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, TypeError):
        return _now()


def _kind_of(rec: Any) -> str:
    # ProbeRecord has no target_kind; infer from target name where possible, else 'generic'.
    name = getattr(rec, "target", "") or ""
    if name in ("hub",):
        return "hub"
    if name in ("momus", "momus-self"):
        return "self"
    return "oracle"
