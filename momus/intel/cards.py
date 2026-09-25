"""KnowledgeCard — a distilled, structured security-report record.

A card is the ONLY thing a fetched report becomes. It is deliberately small and typed: no
free-form instruction text survives distillation, so nothing a report author writes can steer
MOMUS beyond nudging probe weights toward an attack class it already understands.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass, field
from typing import Any

# The closed set of attack categories MOMUS reasons about. A distilled report is mapped onto one
# or more of these; anything that maps to none is dropped (an unmappable report cannot influence
# a scan). These match the probe categories the engine already runs.
ATTACK_CATEGORIES = (
    "integrity",         # signature / manifest / receipt tampering
    "authz",             # free-tier / ceiling / permission bypass
    "input-validation",  # malformed / over-max / injection-of-shape
    "settlement",        # payment / escrow / double-spend / unpaid-serve
    "injection",         # prompt / instruction injection into LLM-backed nodes
    "replay",            # nonce / freshness / duplicate
    "dos",               # resource exhaustion / unbounded work
)


def _now_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class KnowledgeCard:
    """One distilled report. ``mapped_categories`` is the load-bearing field — it is the only
    channel by which the card touches a scan (as a weight nudge / seed hint)."""

    card_id: str
    source: str                      # feed id, e.g. "cisa-kev"
    title: str
    url: str
    published: str
    summary: str                     # a SHORT distilled summary (bounded); not executed, only shown
    mapped_categories: list[str]     # subset of ATTACK_CATEGORIES
    component_class: str = "generic"  # e.g. "api", "signing", "escrow", "llm"
    identifiers: list[str] = field(default_factory=list)  # CVE/CWE/GHSA ids
    seed_hints: list[str] = field(default_factory=list)   # short adversarial-shape hints, bounded
    weight: float = 1.0              # recency/severity-derived influence (0..3)
    ingested_at: str = field(default_factory=_now_z)
    provenance: dict[str, Any] = field(default_factory=dict)  # {source_digest, distiller}

    @staticmethod
    def make_id(source: str, url: str, title: str) -> str:
        return "card-" + hashlib.sha256(f"{source}|{url}|{title}".encode()).hexdigest()[:20]

    def sanitized(self) -> "KnowledgeCard":
        """Clamp every free-text field to a safe length and drop unmappable categories. Fetched
        text is untrusted, so it is bounded and never stored unbounded."""
        self.title = (self.title or "")[:200]
        self.summary = (self.summary or "")[:600]
        self.mapped_categories = [c for c in (self.mapped_categories or []) if c in ATTACK_CATEGORIES][:len(ATTACK_CATEGORIES)]
        self.seed_hints = [str(s)[:80] for s in (self.seed_hints or [])][:8]
        self.identifiers = [str(i)[:40] for i in (self.identifiers or [])][:12]
        self.weight = max(0.0, min(3.0, float(self.weight or 1.0)))
        if self.component_class not in ("generic", "api", "signing", "escrow", "llm", "oracle", "hub"):
            self.component_class = "generic"
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def is_actionable(self) -> bool:
        """A card only matters if it maps to at least one attack class MOMUS can probe."""
        return bool(self.mapped_categories)
