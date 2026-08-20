"""Signed findings — the AWR triad, native-signed with oracle-core.

A MOMUS finding is not a log line; it is a signed claim that another party can verify without
trusting MOMUS. We reuse the ecosystem's own signing primitive (``oracle_core.signing.Signer``,
Ed25519 over a canonical JSON form) so the minimal Docker image needs nothing beyond oracle-core.
The document shapes deliberately mirror the AWR/2 triad (awr/SPEC.md), so a finding can later be
re-issued as a full W3C Verifiable Credential when the ``awr`` package is present:

    Finding          ~ WorkReceipt        "MOMUS did this probe and observed this outcome"
    Verdict          ~ VerificationVerdict "an INDEPENDENT verifier reproduced (or refuted) it"
    Blame            ~ BlameAttestation    "this component is at fault, at this severity"

The security property that matters: the finding is signed by the SCANNER key, the verdict is
signed by a DIFFERENT (verifier) key, and neither key is the treasury key that releases a
bounty. momus.economics enforces that separation; this module only makes the documents.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from oracle_core.signing import Signer

# Severity ladder. Ordinal value doubles as a coarse bounty-weight input (economics applies the
# actual schedule and caps). "info" never pays; it exists so a probe can record "I checked and the
# contract held" — the honest negative that keeps a red team from only ever reporting positives.
class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Outcome(str, Enum):
    FINDING = "finding"          # the probe broke the target's declared contract
    NO_FINDING = "no_finding"    # the contract held — honest negative
    INCONCLUSIVE = "inconclusive"  # could not reach a judgement (target down, ambiguous)


class Status(str, Enum):
    RAW = "raw"                  # signed by the scanner, not yet independently verified
    CONFIRMED = "confirmed"      # an independent verifier reproduced it
    REFUTED = "refuted"          # an independent verifier could not reproduce it
    DISPUTED = "disputed"        # verifiers disagree — needs a second/tie-break verifier


def _now_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _digest(obj: Any) -> str:
    """sha256 SRI-style digest over a canonical JSON form — stable across processes."""
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256-" + hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class Evidence:
    """Enough to reproduce, never more than needed. Requests/responses are stored as DIGESTS
    plus a redacted snippet, so a finding is portable and privacy-preserving — it proves what
    happened without shipping raw payloads that might carry secrets."""

    request_digest: str
    response_digest: str
    request_snippet: str = ""
    response_snippet: str = ""
    status_code: int | None = None
    reproducer: str = ""  # a copy-pasteable curl / one-liner


@dataclass
class Finding:
    """A signed claim by the SCANNER. Shaped like an AWR WorkReceipt."""

    target: str
    target_kind: str
    probe: str            # strategy id, e.g. "free_tier_ceiling_bypass"
    category: str         # e.g. "authz", "input-validation", "replay", "settlement", "injection"
    severity: str
    outcome: str
    title: str
    detail: str
    evidence: Evidence
    finding_id: str = field(default_factory=lambda: f"mom-{uuid.uuid4().hex[:16]}")
    dedup_key: str = ""   # stable across identical re-discoveries; blocks paying twice for one bug
    created_at: str = field(default_factory=_now_z)
    status: str = Status.RAW.value
    scanner_pubkey: str = ""
    signature: dict[str, Any] = field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        """The signed core — everything except the signature block itself."""
        body = asdict(self)
        body.pop("signature", None)
        return body

    def compute_dedup_key(self) -> str:
        """Identity of the *bug*, not the *report* — and it must be DETERMINISTIC.

        The basis is contract-level facts only: which target, which probe, which category, and the
        observed HTTP status. It deliberately does NOT include the response digest: a target's body
        normally carries a fresh nonce, timestamp and latency on every call, so digesting it made
        the key change on every rescan — and a key that changes is no dedup at all. The audit
        confirmed that: the same real bug produced a new dedup key each scan and would have been
        payable again and again. Contract-level facts are stable precisely because they describe
        the *flaw*, not the *response instance*.
        """
        basis = {
            "target": self.target,
            "probe": self.probe,
            "category": self.category,
            "status_code": self.evidence.status_code,
        }
        return "dedup-" + hashlib.sha256(
            json.dumps(basis, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:24]


@dataclass
class Verdict:
    """An INDEPENDENT verifier's judgement. Shaped like an AWR VerificationVerdict. Signed by a
    key that MUST differ from the finding's scanner_pubkey (checked by the economics layer)."""

    finding_id: str
    finding_digest: str   # binds the verdict to the exact finding it judged
    verdict: str          # "confirmed" | "refuted" | "inconclusive"
    method: str           # how it was verified, e.g. "metis:/v1/verify", "replay", "human"
    score: float          # 0..1 confidence
    rationale: str
    verifier_id: str
    created_at: str = field(default_factory=_now_z)
    verifier_pubkey: str = ""
    signature: dict[str, Any] = field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        body = asdict(self)
        body.pop("signature", None)
        return body


@dataclass
class Blame:
    """Who is at fault, and how bad. Shaped like an AWR BlameAttestation. Emitted only for a
    CONFIRMED finding — a red team that assigns blame on an unverified claim is a rumour mill."""

    finding_id: str
    component: str        # the at-fault component (target name / capability id)
    severity: str
    hop: str              # where in the call chain the fault sits
    summary: str
    created_at: str = field(default_factory=_now_z)
    issuer_pubkey: str = ""
    signature: dict[str, Any] = field(default_factory=dict)

    def canonical(self) -> dict[str, Any]:
        body = asdict(self)
        body.pop("signature", None)
        return body


class FindingSigner:
    """Signs findings/verdicts/blame with an Ed25519 key. One instance per ROLE key — the scanner
    holds one, each verifier holds its own, and (critically) neither holds the treasury key."""

    def __init__(self, key_path: str):
        self._signer = Signer(key_path)

    @property
    def pubkey(self) -> str:
        return self._signer.public_key_b64

    def _canon_str(self, obj: dict[str, Any]) -> str:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def sign_finding(self, f: Finding) -> Finding:
        if not f.dedup_key:
            f.dedup_key = f.compute_dedup_key()
        f.scanner_pubkey = self.pubkey
        f.signature = self._signer.sign_payload(self._canon_str(f.canonical()))
        return f

    def sign_verdict(self, v: Verdict) -> Verdict:
        v.verifier_pubkey = self.pubkey
        v.signature = self._signer.sign_payload(self._canon_str(v.canonical()))
        return v

    def sign_blame(self, b: Blame) -> Blame:
        b.issuer_pubkey = self.pubkey
        b.signature = self._signer.sign_payload(self._canon_str(b.canonical()))
        return b


def finding_digest(f: Finding) -> str:
    """SRI digest a verdict binds to. Over the signed canonical (incl. scanner sig), so a verdict
    cannot be transplanted onto a differently-signed finding."""
    body = asdict(f)
    return _digest(body)


def verify_document_signature(canonical: dict[str, Any], signature: dict[str, Any],
                              pubkey: str) -> bool:
    """Offline signature check — no network, mirroring AWR's offline-verify guarantee."""
    canon = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return Signer.verify_signature_object(canon, signature, pubkey)
