"""MOMUS's own security bulletin — we publish in the shape we consume.

MOMUS already ingests CISA KEV, OSV and GHSA (momus/intel/sources.py) and publishes nothing of its
own. That asymmetry is not neutral: a red team that only reads other people's advisories is asking to
be trusted on the strength of documents it never has to write. This module closes it, and it exports
**OSV** — the same schema we ingest — so the tooling that reads the rest of the world reads us too.

## §1 The id is minted per BUG, not per report

``MOMUS-YYYY-NNNN``, assigned once per ``Finding.dedup_key`` — the deterministic identity of the bug
(contract-level facts only, see findings.py). A rediscovery of the same hole must come back with the
SAME number; a "stable id" that changes when the same bug is found twice is just a report id with a
prettier format. Monotonic per year from a high-water counter in the corpus, zero-padded to four,
never reused, gaps never filled. A number exists only once an advisory is PUBLISHED — most findings
never become advisories, and pre-allocating numbers for them would leak how much we are sitting on.

## §2 Coordinated disclosure — the rule the whole feature rests on

MOMUS audits **our own deployed services**. So a bulletin entry with a working reproducer against an
unfixed component is not a disclosure, it is an attack script published under our own signature,
against a host we operate, for an audience that includes whoever wants in.

    status ``open``       → id, published, component, category, severity, and a GENERATED
                            non-actionable one-liner. No reproducer, no evidence digests, no probe
                            parameters, no request/response snippets, no target URL, no references.
    status ``fixed``      → everything, reproducer included. It is a lesson now, not a weapon.
    status ``withdrawn``  → the entry STAYS, with a reason. Silent deletion is how a public record
                            stops being trustworthy; the actionable parts are withheld again because
                            a record we no longer stand behind must not carry a working exploit.

Every advisory states its status explicitly. A reader must never have to *infer* whether a hole is
still open. And the redaction is the DEFAULT: :meth:`Advisory.to_dict` is redacted, the unredacted
form is behind the deliberately awkward :meth:`Advisory.raw_dict`, and :func:`signed_index` re-checks
every entry before any bytes are signed — three chances to catch a caller who forgot.

  ⚠ Whoever wires the HTTP routes for this must fix ``GET /findings`` at the same time. It is
  public today (rate-limited, no operator token) and returns whole finding documents straight from
  the corpus — ``evidence.reproducer`` and the in-cluster target URL included, for findings that are
  still open. Withholding a reproducer in the bulletin while serving the same reproducer one route
  over is not coordinated disclosure, it is paperwork. This module cannot fix that from here; it is
  recorded so the gap is closed by the same change that publishes the bulletin.

## §3 OSV, with the mismatch said out loud

OSV describes vulnerable PACKAGE VERSIONS. Our findings describe DEPLOYED SERVICES, which have no
version axis at all. We map to ``affected[].package`` with ecosystem ``"AIMarket"`` and the service id
in ``package.name``, and we state the mismatch in ``database_specific.note`` — because an OSV consumer
reads a missing ``ranges`` as "all versions affected", and would otherwise believe a version range was
checked when none exists. Same reason ``severity`` stays empty: we hold a qualitative severity, not a
CVSS vector, and inventing a vector to fill a required-looking field is how bad data enters a feed.

## §4 The signed index reuses a contract somebody already hardened

``{"advisories": [...], "timestamp": <epoch ms int>, "signature": "<hex ed25519>"}`` over the RFC 8785
canonical form of ``{advisories, timestamp}`` — the *same* envelope WARDEN already verifies. ``jcs()``
and ``spki_hex()`` are imported from warden_feed.py, never re-implemented: that canonicalizer is
cross-verified against ARGUS's TypeScript JCS and the AWR reference implementation, and a second
implementation is simply a second thing that can disagree with the first.

## §5 What is never in the bulletin

* **A third-party accusation.** Those go to the WARDEN threat feed, which has its own first-party
  guard and its own operator gating — and they are somebody else's reputation, not our record.
  The guard here is literally the same function read in the opposite direction: the feed publishes
  only what is NOT ours, the bulletin only what IS. One list, so the two can never drift apart.
* **An unverified `warden_reports` lead.** Leads are not findings. A lead carries the markers that
  make this refusal possible (``is_momus_finding``/``verified``/``disclaimer``), by design.
* **A private host, a bare IP, an operator token, or a full signature blob** — unconditionally, in
  every status, including a fully-disclosed `fixed` advisory. Our own reproducers point at in-cluster
  hostnames (``http://hub:9085/...``), so publishing one verbatim would publish our topology.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import time
from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from typing import Any, Iterable
from urllib.parse import urlsplit

from momus.findings import Finding, verify_document_signature
from momus.store import FindingStore

# Reuse, never re-implement. The two underscored helpers are warden_feed's signer-shape adapters
# (MOMUS's runtime holds a FindingSigner, tests hold a raw Signer); duplicating them here would mean
# two places that must agree about how a signature is produced.
from momus.warden_feed import (
    _FIRST_PARTY,
    _pubkey_b64,
    _sign_canonical,
    PatternRefused,
    check_pattern,
    jcs,
    spki_hex,
)

ID_PREFIX = "MOMUS"
SCHEMA_VERSION = "1.6.0"          # OSV schema version we emit
OSV_ECOSYSTEM = "AIMarket"
MAX_SNIPPET = 600                 # a snippet, not a corpus (same cap as warden_reports evidence)


def _now_z() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class AdvisoryRefused(ValueError):
    """This finding must not become an advisory. The reason is the message, and it is surfaced to the
    operator rather than swallowed — a silent drop is indistinguishable from "MOMUS found nothing"."""


class AdvisoryStatus(str, Enum):
    OPEN = "open"              # confirmed, not yet fixed → disclosure is withheld
    FIXED = "fixed"            # a MOMUS-signed `fixed` gate verdict exists → full disclosure
    WITHDRAWN = "withdrawn"    # retracted, but still on the record, with a reason


# ── §1 the stable id ─────────────────────────────────────────────────────────
_ID_RE = re.compile(r"^([A-Z][A-Z0-9]{2,15})-(\d{4})-(\d{4,})$")


@dataclass(frozen=True)
class AdvisoryId:
    """``MOMUS-YYYY-NNNN``. Immutable because an advisory number is a promise, not a variable."""

    year: int
    seq: int
    prefix: str = ID_PREFIX

    def __str__(self) -> str:
        # Zero-padded to four, and WIDENS past four rather than wrapping. The 10 000th advisory of a
        # year must not collide with the first — a duplicate id is worse than an ugly one.
        return f"{self.prefix}-{self.year:04d}-{self.seq:04d}"

    @classmethod
    def parse(cls, text: str) -> "AdvisoryId":
        m = _ID_RE.match((text or "").strip())
        if not m:
            raise ValueError(f"{text!r} is not an advisory id (expected e.g. MOMUS-2026-0001)")
        return cls(year=int(m.group(2)), seq=int(m.group(3)), prefix=m.group(1))


# ── §5 the unconditional scrub ───────────────────────────────────────────────
# Hosts a published document may name. Derived from warden_feed's first-party list rather than
# retyped, so there is exactly one place where "which of our hosts are public" is written down.
_PUBLIC_HOSTS = frozenset(h for h in _FIRST_PARTY if "." in h) | frozenset({
    # The public advisory ecosystem a reference legitimately points at.
    "github.com", "www.github.com", "osv.dev", "api.osv.dev", "nvd.nist.gov", "www.cisa.gov",
    "cve.org", "www.cve.org", "ossf.github.io",
})
_HOST_PLACEHOLDER = "<target-host>"

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+", re.I)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# `key: value` / `key=value` credentials, and a bare `Bearer <token>`. The value is consumed as part
# of the match — an earlier form replaced only the key and left the secret sitting next to the word
# `[redacted]`, which is the most embarrassing possible way to leak a token.
_SECRET_RE = re.compile(
    r"(?i)\b(authorization|token|api[_-]?key|apikey|secret|password|passwd|"
    r"x-momus-operator-token|momus[_-]?operator[_-]?token)\b\s*[:=]\s*(?:bearer\s+)?\S+")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{8,}")
# An Ed25519 signature is 88 base64 characters; a sha-256 hex digest is 64 and digests ARE
# publishable evidence for a fixed advisory. The threshold sits between them on purpose.
_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/=]{80,}\b")


def _rewrite_url(match: "re.Match[str]") -> str:
    """Keep the PATH (that is the lesson), drop the authority unless the host is public.

    Our probes build reproducers from ``target.base_url``, which in production is an in-cluster
    service name or an IP. The path and method are what a reader learns from; the host is only our
    topology, and a reproducer that names it is a starting point for someone else's scan."""
    url = match.group(0)
    try:
        parts = urlsplit(url)
    except ValueError:                                   # malformed → publish nothing of it
        return f"https://{_HOST_PLACEHOLDER}"
    if (parts.hostname or "").lower() in _PUBLIC_HOSTS:
        return url
    rest = parts.path or ""
    if parts.query:
        rest += "?" + parts.query
    return f"https://{_HOST_PLACEHOLDER}{rest}"


# A bare ``host:port`` with no scheme — how an in-cluster address most often appears in prose, and
# invisible to the URL pass above. The lookahead requires a letter in the host, so a clock ("12:30")
# or an offset is not mistaken for an address.
_HOSTPORT_RE = re.compile(r"\b((?=[a-z0-9.\-]*[a-z])[a-z0-9][a-z0-9.\-]{1,60}):\d{2,5}\b", re.I)


# An ISO-8601 instant is not an address, and the pattern above cannot tell: in
# ``2026-08-08T19:36:19Z`` the candidate host is ``2026-08-08T19`` — which satisfies "must contain a
# letter" because of the `T` — and the candidate port is ``:36``, so the stamp was published as
# ``<target-host>:19Z``. Found by reading a real `fixed` advisory's details, where the module's own
# "Re-tested by MOMUS on <date>" line was the thing being corrupted. The clock-only case ("12:30")
# was already safe and tested; it is the date-and-time form that has a letter in it.
_DATE_TIME_HOST_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{1,2}$", re.I)


def _rewrite_hostport(match: "re.Match[str]") -> str:
    host = match.group(1)
    if _DATE_TIME_HOST_RE.match(host):
        return match.group(0)
    return match.group(0) if host.lower() in _PUBLIC_HOSTS else _HOST_PLACEHOLDER


def scrub_sensitive(text: str, *, limit: int = MAX_SNIPPET) -> str:
    """Strip what may never appear in the bulletin, in ANY status. Applied to every published string.

    Order matters: URLs first (so an IP-hosted URL loses its host before the bare-IP pass sees it),
    then bare addresses, then credentials, then oversized blobs."""
    if not text:
        return ""
    out = _URL_RE.sub(_rewrite_url, str(text))
    out = _HOSTPORT_RE.sub(_rewrite_hostport, out)
    out = _IPV4_RE.sub("[ip-redacted]", out)
    out = _BEARER_RE.sub("bearer [redacted]", out)
    out = _SECRET_RE.sub(lambda m: f"{m.group(1)}=[redacted]", out)
    out = _BLOB_RE.sub("[blob-redacted]", out)
    return out.strip()[:limit]


# ── the advisory ─────────────────────────────────────────────────────────────
@dataclass
class Advisory:
    """One bulletin entry. Built unredacted; SERVED redacted (see :meth:`to_dict`)."""

    id: str
    status: str
    published: str
    modified: str
    component: str                    # OUR service, by its target name — never a URL, never a host
    category: str
    severity: str
    summary: str
    details: str = ""
    reproducer: str = ""
    references: list[dict[str, str]] = field(default_factory=list)
    # A list because several findings can share one dedup identity: the same bug rediscovered on a
    # later scan is a new finding_id and the same advisory.
    finding_ids: list[str] = field(default_factory=list)
    gate_verdict: dict[str, Any] = field(default_factory=dict)
    withdrawn_reason: str = ""
    # Set when a bug that was verified fixed has reappeared without a new verdict. The advisory
    # keeps its number (the id is per BUG, and this is the same bug) but reverts to `open`, so the
    # new occurrence's reproducer is withheld. Publishing it because an EARLIER one was already
    # public is the mistake this flag exists to make impossible to repeat quietly.
    regressed: bool = False
    regression_note: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    # Internal identity. Never serialized publicly: it tells a reader nothing the advisory id does not
    # already tell them, and the id is the handle we want cited.
    dedup_key: str = ""

    @property
    def advisory_id(self) -> AdvisoryId:
        return AdvisoryId.parse(self.id)

    def to_dict(self) -> dict[str, Any]:
        """The PUBLIC form — redacted per §2. This is the default path on purpose: a caller who
        forgets to think about disclosure gets the safe answer, not the exploit."""
        return _serialize(redact_for_disclosure(self))

    def raw_dict(self) -> dict[str, Any]:
        """The UNREDACTED form: operator-only, and never the body of a public response. Named
        awkwardly so that serving it is a visible decision in the calling code."""
        return asdict(self)

    def to_osv(self) -> dict[str, Any]:
        return to_osv(self)


# The one-liner an `open` advisory carries instead of the scanner's title. GENERATED from
# (severity, category, component) rather than derived from the finding, because a human- or
# LLM-written title ("free tier serves 1000 calls unpaid when n>100") is itself a recipe, and no
# review process can promise that a sentence written to be informative is not also actionable.
_OPEN_SUMMARY = "{severity} {category} issue in {component} — under coordinated disclosure"

_OPEN_DETAILS = (
    "MOMUS has confirmed this issue against a first-party service it audits. Under coordinated "
    "disclosure the reproducer, evidence digests, probe parameters and target are withheld until a "
    "MOMUS-signed `fixed` verdict exists for it. This entry exists so that the record is complete "
    "and countable while the hole is open — not so that it can be reproduced."
)

_WITHDRAWN_DETAILS = (
    "This advisory has been WITHDRAWN. It remains on the record with its reason, because an advisory "
    "that disappears makes every other entry unverifiable. Technical detail is withheld: a record "
    "MOMUS no longer stands behind must not carry a working reproducer under MOMUS's signature."
)

DISCLOSURE_FULL = "full"
DISCLOSURE_WITHHELD = (
    "withheld-pending-fix — coordinated disclosure: this entry deliberately omits the reproducer, "
    "evidence and target while the issue is unfixed"
)
DISCLOSURE_WITHDRAWN = "withheld-withdrawn — this advisory was retracted; see withdrawn_reason"

# Fields that can weaponize an entry. Empty for anything that is not `fixed`, and re-checked by
# _ensure_public() immediately before signing.
_ACTIONABLE = ("reproducer", "evidence", "gate_verdict", "references")


def redact_for_disclosure(advisory: Advisory) -> Advisory:
    """Apply §2. Pure: returns a NEW Advisory, mutates nothing, and is idempotent.

    This is the function the whole feature rests on, so it is deliberately boring: no configuration,
    no caller-supplied policy, no "verbose" mode. The status decides, and only the status.
    """
    status = (advisory.status or "").strip().lower()
    if status == AdvisoryStatus.FIXED.value:
        # Full disclosure — but §5 still applies: no private host, no bare IP, no token, no blob.
        return replace(
            advisory,
            status=status,
            summary=scrub_sensitive(advisory.summary, limit=300),
            details=scrub_sensitive(advisory.details, limit=4000),
            reproducer=scrub_sensitive(advisory.reproducer, limit=1000),
            evidence=_public_evidence(advisory.evidence),
            references=_public_references(advisory.references),
            gate_verdict=_public_gate(advisory.gate_verdict),
            finding_ids=list(advisory.finding_ids),
            withdrawn_reason=scrub_sensitive(advisory.withdrawn_reason, limit=500),
        )

    withdrawn = status == AdvisoryStatus.WITHDRAWN.value
    return replace(
        advisory,
        # An unknown/garbage status falls here too: fail closed. Anything we cannot positively
        # identify as `fixed` is treated as an open hole.
        status=status if withdrawn else AdvisoryStatus.OPEN.value,
        summary=_non_actionable_summary(advisory),
        details=_WITHDRAWN_DETAILS if withdrawn else _OPEN_DETAILS,
        reproducer="",
        evidence={},
        # No references at all. Every link we hold points either at the affected service or at
        # internal tooling, so "which links are safe" has no honest answer while the hole is open.
        references=[],
        gate_verdict={},
        finding_ids=list(advisory.finding_ids),
        withdrawn_reason=scrub_sensitive(advisory.withdrawn_reason, limit=500) if withdrawn else "",
    )


def _non_actionable_summary(advisory: Advisory) -> str:
    return _OPEN_SUMMARY.format(
        severity=(advisory.severity or "unrated").lower(),
        category=(advisory.category or "security").lower(),
        component=advisory.component or "an internal component")


def _public_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Digests and a redacted snippet — the same shape findings.Evidence already stores, because it
    was designed for exactly this: proving what happened without shipping raw payloads."""
    if not evidence:
        return {}
    out: dict[str, Any] = {}
    for key in ("request_digest", "response_digest"):
        if evidence.get(key):
            out[key] = str(evidence[key])[:120]
    for key in ("request_snippet", "response_snippet"):
        if evidence.get(key):
            out[key] = scrub_sensitive(str(evidence[key]))
    code = evidence.get("status_code")
    if isinstance(code, int):
        out["status_code"] = code
    return out


# OSV's reference-type enum. A type outside it makes the whole record fail OSV validation, and a
# consumer that rejects our document learns nothing from it — so an unknown type becomes WEB rather
# than being passed through as-is.
_OSV_REFERENCE_TYPES = frozenset({
    "ADVISORY", "ARTICLE", "DETECTION", "DISCUSSION", "REPORT", "FIX", "INTRODUCED", "GIT",
    "PACKAGE", "EVIDENCE", "WEB",
})


def _public_references(references: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    """OSV-shaped ``{type, url}`` references, scrubbed and deduped, in a stable order."""
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for ref in references or []:
        url = scrub_sensitive(str((ref or {}).get("url") or ""), limit=400)
        if not url or url in seen:
            continue
        seen.add(url)
        kind = str((ref or {}).get("type") or "WEB").upper()[:24]
        out.append({"type": kind if kind in _OSV_REFERENCE_TYPES else "WEB", "url": url})
    return sorted(out, key=lambda r: (r["type"], r["url"]))


def _public_gate(gate: dict[str, Any]) -> dict[str, Any]:
    """The fix verdict, reduced to what a reader can check without receiving the signature itself.

    A digest proves the verdict exists and is unchanged; the blob adds nothing a reader can do with
    it here and §5 keeps full signatures out of the bulletin. An operator who needs to verify offline
    asks for the verdict document itself."""
    if not gate:
        return {}
    sig = gate.get("signature") or {}
    out: dict[str, Any] = {
        "fixed": bool(gate.get("fixed")),
        "outcome": str(gate.get("outcome") or "")[:40],
        "checked_at": str(gate.get("checked_at") or "")[:32],
        "probe": str(gate.get("probe") or "")[:80],
    }
    key = str(gate.get("verifier_pubkey") or "")
    if key:
        out["verifier_pubkey_prefix"] = key[:12]
    value = str(sig.get("value") or "")
    if value:
        out["signature_digest"] = "sha256-" + hashlib.sha256(value.encode()).hexdigest()
    return out


def _serialize(advisory: Advisory) -> dict[str, Any]:
    """Wire form of an ALREADY-REDACTED advisory. ``disclosure`` travels with the record — the same
    habit as warden_reports' disclaimer: a document must state its own limits, because it will be
    read through routes, screenshots and copies that carry no other context."""
    status = advisory.status
    if status == AdvisoryStatus.FIXED.value:
        disclosure = DISCLOSURE_FULL
    elif status == AdvisoryStatus.WITHDRAWN.value:
        disclosure = DISCLOSURE_WITHDRAWN
    else:
        disclosure = DISCLOSURE_WITHHELD
    return {
        "id": advisory.id,
        "status": status,
        "disclosure": disclosure,
        "published": advisory.published,
        "modified": advisory.modified,
        "component": advisory.component,
        "category": advisory.category,
        "severity": advisory.severity,
        "summary": advisory.summary,
        "details": advisory.details,
        "reproducer": advisory.reproducer,
        "evidence": advisory.evidence,
        "references": advisory.references,
        "finding_ids": list(advisory.finding_ids),
        "gate_verdict": advisory.gate_verdict,
        "withdrawn_reason": advisory.withdrawn_reason,
    }


def _ensure_public(entry: dict[str, Any]) -> dict[str, Any]:
    """Last gate before bytes are signed: refuse an entry that leaks despite everything above.

    Redundant by construction, and kept anyway. The failure this guards against is not a bug in
    redact_for_disclosure — it is a future caller who hands signed_index() raw dicts from somewhere
    else. A signed exploit cannot be recalled once it is fetched."""
    if entry.get("status") == AdvisoryStatus.FIXED.value:
        # `fixed` is what unlocks the reproducer, so the word alone is not enough even here: a fixed
        # entry that carries no fix verdict never came out of BulletinStore.publish(), which sets the
        # status only from a signature it checked.
        if not entry.get("gate_verdict"):
            raise AdvisoryRefused(
                f"advisory {entry.get('id')} claims `fixed` but carries no fix verdict — full "
                "disclosure is unlocked by a MOMUS-signed re-test verdict, never by a status string")
        return entry
    leaking = [k for k in _ACTIONABLE if entry.get(k)]
    if leaking:
        raise AdvisoryRefused(
            f"advisory {entry.get('id')} is {entry.get('status')!r} but still carries "
            f"{', '.join(leaking)} — an unfixed hole must never be published with the means to "
            "exploit it; pass Advisory objects (or redact_for_disclosure output), not raw dicts")
    return entry


# ── §2 applied to the LIVE findings ledger ───────────────────────────────────
# The gap the module docstring warns about, closed here rather than in the route: withholding a
# reproducer in the bulletin while `GET /findings` serves the same reproducer one route over is not
# coordinated disclosure, it is paperwork. Same rule, same code, both surfaces.
_FINDING_ACTIONABLE = ("reproducer", "request_snippet", "response_snippet")

FINDING_DISCLOSURE_FULL = (
    "full — a MOMUS-signed `fixed` verdict is published for this bug, so its reproducer is a lesson "
    "rather than a weapon (see /bulletin)")
FINDING_DISCLOSURE_WITHHELD = (
    "withheld-pending-fix — coordinated disclosure: the reproducer, the probe payloads and the "
    "target host are omitted while no MOMUS-signed `fixed` verdict exists for this bug. MOMUS audits "
    "services we operate, so a working reproducer for an unfixed finding is an attack script")

_SIGNATURE_REDACTED_NOTE = (
    "this document was REDACTED for public disclosure, so the scanner signature over it would no "
    "longer verify and is withheld rather than served broken — a signature that fails looks like "
    "tampering. The verifiable original is in MOMUS's corpus; a fixed finding is republished whole "
    "as an advisory in /bulletin"
)


def signed_body(doc: dict[str, Any]) -> dict[str, Any]:
    """The fields the scanner signature actually covers — what a verifier must hash, and nothing else.

    ``Finding.canonical()`` is ``asdict(finding)`` minus the signature, so the signed body is exactly
    the dataclass's own fields. Everything a later layer bolts on is BOOKKEEPING and was never signed:
    the corpus adds ``seen_count`` / ``first_seen_at`` / ``last_seen_at`` when it reads a row back,
    scans add ``known_before``, and these routes add ``disclosure``.

    That mattered before this function existed, and not theoretically: a caller who took a finding
    from ``GET /findings``, dropped ``signature`` and verified the rest got False every time, because
    three bookkeeping keys were in the body. The signature was fine; the instructions were missing.
    Deriving the field list from the dataclass rather than denylisting known extras means a new
    bookkeeping field cannot quietly break verification again.
    """
    return {k: doc[k] for k in Finding.__dataclass_fields__
            if k != "signature" and k in doc}


def public_finding(finding: dict[str, Any], *, disclosed: Iterable[str] = ()) -> dict[str, Any]:
    """One signed finding as an ANONYMOUS caller may see it. Pure; returns a new dict.

    *disclosed* is the set of **dedup identities** (not finding ids) whose advisory is published as
    ``fixed``. Keyed on the dedup identity for the same reason the advisory number is: the bug is what
    got fixed, so a rediscovery of an already-published bug is disclosed too, while a fresh finding of
    a different bug is not — even if it shares a target.

    Two things happen, and the order matters:

    1. The actionable fields are emptied unless the bug is disclosed. §5's unconditional scrub is
       applied to *everything* that survives, in every case: our reproducers are built from
       in-cluster base URLs, so even a fully disclosed finding must not publish our topology.
    2. If a SIGNED field changed, the ``signature`` is withheld. It is computed over the whole
       document, so a redacted copy can never verify under it — and serving a signature that fails is
       worse than serving none: it reads as tampering, or as MOMUS signing badly. The comparison runs
       over :func:`signed_body` rather than the raw dicts, so a bookkeeping field the corpus added
       cannot strip a signature that would still have verified. The invariant this buys is worth
       stating: **a signature present in a public finding verifies.**

    Note what this deliberately does NOT do: it keeps the scanner's ``title`` and ``detail``, where
    §2 would replace them with a generated one-liner. The two surfaces are not the same object — the
    bulletin is a permanent, citable record, while this is the live ledger, and a ledger whose entries
    cannot be told apart is not a ledger. The consequence is real and worth naming rather than
    glossing: an unfixed finding's prose can still describe the shape of the bug ("returned 200 on the
    n+1th unpaid call"), which is more than the bulletin would publish for the same hole. What it can
    never carry is the copy-pasteable part — the reproducer, the payloads, and the host to aim them at.
    """
    doc = dict(finding or {})
    withheld = str(doc.get("dedup_key") or "") not in {str(k) for k in disclosed}

    evidence = dict(doc.get("evidence") or {})
    if withheld:
        for key in _FINDING_ACTIONABLE:
            if evidence.get(key):
                evidence[key] = ""
    out = dict(doc)
    out["evidence"] = {k: (scrub_sensitive(v) if isinstance(v, str) else v)
                       for k, v in evidence.items()}
    # The title and the detail stay — this is the live ledger, and a finding a reader cannot even
    # name is not a ledger entry. They are scrubbed, so a probe that quoted an in-cluster URL in its
    # prose does not publish it.
    out["title"] = scrub_sensitive(str(doc.get("title") or ""), limit=400)
    out["detail"] = scrub_sensitive(str(doc.get("detail") or ""), limit=2000)
    out["disclosure"] = FINDING_DISCLOSURE_WITHHELD if withheld else FINDING_DISCLOSURE_FULL

    if signed_body(out) != signed_body(doc):
        algorithm = str((doc.get("signature") or {}).get("algorithm") or "ed25519")
        out["signature"] = {"algorithm": algorithm, "redacted": True,
                            "note": _SIGNATURE_REDACTED_NOTE}
    return out


# ── building an advisory from a finding ──────────────────────────────────────
def _is_first_party(target: str) -> bool:
    """Is this one of OUR components? Answered by warden_feed's guard, read backwards.

    That guard refuses a deny pattern *because* it matches one of our identities. So "it refused for
    first-party" is precisely "this is ours". Deriving both answers from one function is the point:
    the threat feed publishes only third-party targets, the bulletin only first-party ones, and they
    cannot drift into overlapping or into both being wrong.
    """
    try:
        check_pattern(target)
    except PatternRefused as exc:
        return "first-party" in str(exc)
    return False           # accepted as a deny pattern ⇒ a stranger's surface ⇒ not ours


def _as_doc(finding: Finding | dict[str, Any]) -> dict[str, Any]:
    return asdict(finding) if isinstance(finding, Finding) else dict(finding or {})


def _refuse_leads_and_strangers(doc: dict[str, Any]) -> None:
    """§5. Ordered so the reader gets the most important reason first."""
    # A warden_reports lead. It carries these markers by construction (Suspicion.to_dict attaches
    # them to the data itself precisely so a check like this one is possible), and every one of them
    # is a refusal on its own — a lead is an anonymous stranger's claim, not something we found.
    if doc.get("is_momus_finding") is False or doc.get("verified") is False or doc.get("disclaimer"):
        raise AdvisoryRefused(
            "this is an UNVERIFIED third-party report from the warden_reports queue, not a MOMUS "
            "finding — leads are not findings, and publishing one under our advisory numbering would "
            "put our name on a stranger's accusation")
    if doc.get("identity") and not doc.get("finding_id"):
        raise AdvisoryRefused(
            "this looks like a reported LEAD (it has an `identity` and no `finding_id`) — only a "
            "signed MOMUS finding can become an advisory")

    target = str(doc.get("target") or "").strip()
    if not target:
        raise AdvisoryRefused("a finding with no target cannot be attributed to a component")
    if not _is_first_party(target):
        raise AdvisoryRefused(
            f"target {target!r} is NOT one of our components — the bulletin is MOMUS's record of "
            "holes in services WE operate. A third-party accusation belongs in the WARDEN threat "
            "feed, which has its own first-party guard and its own operator gating; it is somebody "
            "else's reputation, and it is not ours to publish under an advisory number")
    try:
        looks_addressed = urlsplit(f"//{target}").port is not None
    except ValueError:
        looks_addressed = True      # an authority we cannot even parse is never publishable
    if _IPV4_RE.search(target) or looks_addressed or "/" in target:
        raise AdvisoryRefused(
            f"component {target!r} looks like a host or an address — a bulletin never names a "
            "private host or a bare IP (§5); register the target under a service name")

    # Signed by the scanner, or it is not a MOMUS finding whatever it says it is. Fail closed: a
    # missing key, a missing signature or a signature that does not verify are all refusals.
    pubkey = str(doc.get("scanner_pubkey") or "")
    sig = doc.get("signature") or {}
    if not pubkey or not sig.get("value"):
        raise AdvisoryRefused(
            "the finding is unsigned — MOMUS publishes advisories only for findings it signed, "
            "so that an advisory can be traced back to a document a reader can verify offline")
    body = {k: v for k, v in doc.items() if k != "signature"}
    if not verify_document_signature(body, sig, pubkey):
        raise AdvisoryRefused(
            "the finding's scanner signature does not verify — refusing to publish an advisory for "
            "a document that has been altered since it was signed")

    if str(doc.get("outcome") or "") == "no_finding":
        raise AdvisoryRefused(
            "this is an honest NEGATIVE (the contract held) — valuable in the corpus, but an "
            "advisory about a hole that does not exist is noise in a security feed")
    status = str(doc.get("status") or "").lower()
    if status == "refuted":
        raise AdvisoryRefused(
            "an independent verifier REFUTED this finding — publishing it would put our signature "
            "on a claim we know to be wrong")


def gate_says_fixed(gate: dict[str, Any] | None, finding_ids: Iterable[str],
                    verifier_pubkey: str, current_finding_id: str = "") -> tuple[bool, str]:
    """Is there a MOMUS-signed ``fixed`` verdict for THIS bug? Fail-closed at every step.

    This is the switch that unlocks the reproducer, which makes it the most attractive thing in the
    module to forge: a bare ``{"fixed": true}`` must not turn an open hole into a published exploit.
    So an unsigned verdict, a verdict for another finding, a missing pin and a signature that does
    not verify all leave the advisory OPEN — the same fail-closed shape (and the same lesson) as
    economics._fix_verdict_ok, which once released real money on an unsigned dict.
    """
    if not gate:
        return False, "no fix verdict on record — advisory stays open"
    if not gate.get("fixed"):
        return False, "fix verdict says the finding still reproduces — advisory stays open"
    ids = {str(i) for i in finding_ids}
    if str(gate.get("finding_id") or "") not in ids:
        return False, "fix verdict is for a different finding — advisory stays open"
    # …and it must cover THE finding whose body is being served, not merely one of the
    # findings this advisory has ever collected.
    #
    # This was the hole. `finding_ids` accumulates every rediscovery of the same bug, so a
    # verdict for finding A satisfied the membership test above while the advisory body was
    # rebuilt from a LATER finding B. Result: status `fixed`, disclosure `full`, and the
    # reproducer served was B's — fresh and working — through every surface at once (the
    # signed index, the single advisory, OSV, Atom, and /findings). The comment justifying
    # the fallback argued that re-hiding protects nobody "because the reproducer is already
    # out". That is true of A's reproducer and false of B's, and B's is the one being served.
    if current_finding_id and str(gate.get("finding_id") or "") != str(current_finding_id):
        return False, ("fix verdict covers an earlier finding for this bug, not the one being "
                       "published — the bug regressed and this reproducer was never disclosed")
    if not verifier_pubkey:
        return False, "no MOMUS verifier key pinned to check the fix verdict — advisory stays open"
    sig = gate.get("signature") or {}
    if not sig.get("value"):
        return False, "fix verdict is unsigned — advisory stays open"
    body = {k: v for k, v in gate.items() if k != "signature"}
    if not verify_document_signature(body, sig, verifier_pubkey):
        return False, "fix verdict signature does not verify — advisory stays open"
    return True, "MOMUS-signed `fixed` verdict on record"


def advisory_from_finding(finding: Finding | dict[str, Any], *, advisory_id: str, published: str,
                          modified: str = "", status: str = AdvisoryStatus.OPEN.value,
                          gate_verdict: dict[str, Any] | None = None,
                          references: Iterable[dict[str, str]] = (),
                          finding_ids: Iterable[str] = ()) -> Advisory:
    """Build the UNREDACTED advisory for a finding, refusing anything §5 forbids.

    Unredacted because the corpus keeps the whole record; nothing serves this object directly —
    :meth:`Advisory.to_dict` is what a reader gets."""
    doc = _as_doc(finding)
    _refuse_leads_and_strangers(doc)
    evidence = dict(doc.get("evidence") or {})
    ids = list(dict.fromkeys([*(str(i) for i in finding_ids), str(doc.get("finding_id") or "")]))
    detail_lines = [str(doc.get("detail") or "")]
    if doc.get("probe"):
        detail_lines.append(f"Probe: {doc['probe']}")
    gate = dict(gate_verdict or {})
    if gate.get("checked_at"):
        detail_lines.append(
            f"Re-tested by MOMUS on {gate['checked_at']}: the finding's own probe is the fix gate, "
            "and it no longer reproduces.")
    return Advisory(
        id=advisory_id,
        status=status,
        published=published,
        modified=modified or published,
        component=str(doc.get("target") or ""),
        category=str(doc.get("category") or "security"),
        severity=str(doc.get("severity") or "medium"),
        summary=str(doc.get("title") or ""),
        details="\n".join(line for line in detail_lines if line),
        reproducer=str(evidence.get("reproducer") or ""),
        references=list(references),
        finding_ids=[i for i in ids if i],
        gate_verdict=gate,
        evidence=evidence,
        dedup_key=str(doc.get("dedup_key") or ""),
    )


# ── §3 OSV export ────────────────────────────────────────────────────────────
_OSV_NOTE = (
    "OSV describes vulnerable PACKAGE VERSIONS. A MOMUS advisory describes a DEPLOYED first-party "
    "SERVICE, which has no version axis: `affected[].package.name` is the service id, ecosystem "
    "`AIMarket` is ours and not an OSV-registered ecosystem, and NO version range was checked — do "
    "not read the absent `ranges` as 'all versions affected'. `severity` is empty because MOMUS "
    "holds a qualitative severity, not a CVSS vector; the qualitative value is in "
    "`database_specific.severity`. Inventing a vector to fill the field would be worse than leaving "
    "it empty."
)


def to_osv(advisory: Advisory) -> dict[str, Any]:
    """OSV record for one advisory, built from the REDACTED form (§2 applies to every export)."""
    pub = advisory.to_dict()
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "id": pub["id"],
        "modified": pub["modified"],
        "published": pub["published"],
        "summary": pub["summary"],
        "details": pub["details"],
        "severity": [],
        "affected": [{
            "package": {"ecosystem": OSV_ECOSYSTEM, "name": pub["component"]},
            "database_specific": {"deployed_service": True, "version_range_checked": False},
        }],
        "references": pub["references"],
        "credits": _osv_credits(pub),
        "database_specific": {
            "advisory_status": pub["status"],
            "disclosure": pub["disclosure"],
            "category": pub["category"],
            "severity": pub["severity"],
            "finding_ids": pub["finding_ids"],
            "gate_verdict": pub["gate_verdict"],
            "reproducer": pub["reproducer"],
            "evidence": pub["evidence"],
            "note": _OSV_NOTE,
        },
    }
    if pub["status"] == AdvisoryStatus.WITHDRAWN.value:
        # OSV's own field for this. A consumer that honours `withdrawn` stops acting on the record
        # without us having to delete it — exactly the behaviour §2 wants.
        record["withdrawn"] = pub["modified"]
        record["database_specific"]["withdrawn_reason"] = pub["withdrawn_reason"]
    return record


def _osv_credits(pub: dict[str, Any]) -> list[dict[str, Any]]:
    credits: list[dict[str, Any]] = [{"name": "MOMUS", "type": "FINDER",
                                      "contact": ["https://momus.modelmarket.dev"]}]
    if pub["status"] == AdvisoryStatus.FIXED.value:
        credits.append({"name": "MOMUS (re-test gate)", "type": "REMEDIATION_VERIFIER",
                        "contact": ["https://momus.modelmarket.dev"]})
    return credits


# ── §4 the signed index ──────────────────────────────────────────────────────
def signed_index(advisories: Iterable[Advisory | dict[str, Any]], signer: Any, *,
                 now_ms: int | None = None) -> dict[str, Any]:
    """``{advisories, timestamp, signature}`` — the envelope WARDEN already verifies.

    Signed over ``jcs({advisories, timestamp})`` with warden_feed's canonicalizer, hex-encoded
    signature, epoch-millisecond integer timestamp. Entries are sorted by id so the same set of
    advisories always produces identical bytes: an index whose signature churns on iteration order
    cannot be cached, diffed, or checked for replay.
    """
    entries = [_ensure_public(a.to_dict() if isinstance(a, Advisory) else dict(a))
               for a in advisories]
    entries.sort(key=lambda e: str(e.get("id") or ""))
    timestamp = int(now_ms if now_ms is not None else time.time() * 1000)
    canonical = jcs({"advisories": entries, "timestamp": timestamp})
    # oracle_core signs to base64; this envelope is hex, like WARDEN's feed.
    signature = base64.b64decode(_sign_canonical(signer, canonical)).hex()
    return {"advisories": entries, "timestamp": timestamp, "signature": signature}


def index_public_key_spki_hex(signer: Any) -> str:
    """The key to pin, in the same encoding the WARDEN feed publishes — one fewer format for an
    operator to get wrong."""
    return spki_hex(base64.b64decode(_pubkey_b64(signer)))


def bulletin_enabled() -> bool:
    """Publishing is opt-in and off by default. Becoming a public advisory publisher is a decision an
    operator makes, not a side effect of running the container."""
    return os.environ.get("MOMUS_BULLETIN", "").strip().lower() in ("1", "true", "yes", "on")


# ── the store ────────────────────────────────────────────────────────────────
class BulletinStore:
    """Mint / publish / withdraw / list, over MOMUS's own corpus.

    Holds no key of its own: signing an index is a call with a signer, so a BulletinStore that is
    only ever read cannot produce a signed document. Same containment as everywhere else in MOMUS —
    the thing that publishes and the thing that can sign are separable.
    """

    def __init__(self, corpus: FindingStore, *, verifier_pubkey: str = "",
                 public_url: str = "https://momus.modelmarket.dev"):
        self._corpus = corpus
        # The MOMUS re-test key that a `fixed` verdict must be signed by. Empty ⇒ nothing can ever
        # be published as fixed, which is the correct default: no pin, no full disclosure.
        self._verifier_pubkey = verifier_pubkey
        self._public_url = public_url.rstrip("/")

    # ── §1 minting ──────────────────────────────────────────────────────────
    def mint(self, dedup_key: str, *, year: int | None = None) -> str:
        """The advisory id for this BUG identity, minting one if it has none. Idempotent."""
        if not dedup_key:
            raise AdvisoryRefused(
                "an advisory number is minted per dedup identity, and this finding has none — "
                "without it a rediscovery of the same bug would get a second number")
        reserved = self._corpus.reserve_advisory_number(
            dedup_key, int(year if year is not None else time.gmtime().tm_year))
        if reserved["advisory_id"]:
            return str(reserved["advisory_id"])
        return str(AdvisoryId(year=int(reserved["year"]), seq=int(reserved["seq"])))

    # ── publish ─────────────────────────────────────────────────────────────
    def publish(self, finding: Finding | dict[str, Any], *,
                gate_verdict: dict[str, Any] | None = None,
                references: Iterable[dict[str, str]] = (), now: str | None = None) -> Advisory:
        """Publish (or re-publish) the advisory for a finding. Returns the unredacted Advisory.

        Re-publishing the same bug keeps the number, keeps the original ``published`` date, adds the
        new finding_id, and bumps ``modified``. Status is decided ONLY by a verifiable signed fix
        verdict — never by an argument a caller passes in.

        A WITHDRAWN advisory stays withdrawn here, whatever a rescan brings: withdrawal is an
        operator's judgement about the record, and an automated publish path that could quietly
        resurrect a retracted entry would make the withdrawal unreliable in exactly the way §2 says a
        deletion is. Re-listing it is a deliberate operator act, not a scan side effect.
        """
        doc = _as_doc(finding)
        _refuse_leads_and_strangers(doc)
        dedup = str(doc.get("dedup_key") or "") or (
            finding.compute_dedup_key() if isinstance(finding, Finding) else "")
        advisory_id = self.mint(dedup)
        stamp = now or _now_z()

        prior = self._corpus.advisory_for_dedup(dedup)
        prior_doc = (prior or {}).get("doc") or {}
        published = str(prior_doc.get("published") or stamp)
        known_ids = [str(i) for i in (prior_doc.get("finding_ids") or [])]
        # A fix verdict already on record stays on record. A published `fixed` advisory is not
        # silently walked back to `open` by a later re-publication: the reproducer is already out, so
        # re-hiding it protects nobody, and a status that oscillates is a record nobody can cite. A
        # regression shows up as a new finding_id and a bumped `modified`; an operator who wants the
        # record to say more than that withdraws it with a reason.
        # A verdict already on record is still USED, but only as evidence about the finding it
        # actually checked — gate_says_fixed now compares it against the finding being served.
        gate = dict(gate_verdict or prior_doc.get("gate_verdict") or {})
        current_id = str(doc.get("finding_id") or "")
        was_withdrawn = str(prior_doc.get("status") or "") == AdvisoryStatus.WITHDRAWN.value

        advisory = advisory_from_finding(
            doc, advisory_id=advisory_id, published=published, modified=stamp,
            gate_verdict=gate, references=references, finding_ids=known_ids)
        fixed, gate_reason = gate_says_fixed(gate, advisory.finding_ids, self._verifier_pubkey,
                                             current_finding_id=current_id)
        # A previously-fixed advisory whose new finding has no verdict is a REGRESSION, not a
        # fresh hole and not a still-fixed one. It stays listed under the same id — the number
        # is stable per bug — reverts to `open` so the new reproducer is withheld, and says
        # plainly that it was fixed once. Silently keeping `fixed` published a live exploit;
        # silently dropping the history would lose the fact that a fix had been verified.
        was_fixed = str(prior_doc.get("status") or "") == AdvisoryStatus.FIXED.value
        regressed = was_fixed and not fixed
        if was_withdrawn:
            advisory.status = AdvisoryStatus.WITHDRAWN.value
            advisory.withdrawn_reason = str(prior_doc.get("withdrawn_reason") or "withdrawn")
        else:
            advisory.status = (AdvisoryStatus.FIXED.value if fixed
                               else AdvisoryStatus.OPEN.value)
        if regressed:
            advisory.regressed = True
            advisory.regression_note = (
                "This advisory was verified fixed and the bug has reappeared. The new occurrence "
                "has no fix verdict, so its reproducer is withheld: an earlier disclosure licenses "
                f"republishing that reproducer, not this one. ({gate_reason})")
        self._save(advisory, dedup_key=dedup)
        return advisory

    def withdraw(self, advisory_id: str, reason: str) -> Advisory:
        """Retract an advisory WITHOUT removing it. A reason is mandatory."""
        reason = (reason or "").strip()
        if not reason:
            raise AdvisoryRefused(
                "a withdrawal needs a reason — an entry that changes to `withdrawn` with no "
                "explanation is the same information loss as deleting it")
        advisory = self.load(advisory_id)
        if advisory is None:
            raise AdvisoryRefused(f"no advisory {advisory_id!r} on record")
        advisory.status = AdvisoryStatus.WITHDRAWN.value
        advisory.withdrawn_reason = reason
        advisory.modified = _now_z()
        self._save(advisory, dedup_key=advisory.dedup_key)
        return advisory

    # ── read ────────────────────────────────────────────────────────────────
    def load(self, advisory_id: str) -> Advisory | None:
        """The stored UNREDACTED advisory (operator path). Use :meth:`get` to serve one."""
        doc = self._corpus.get_advisory(advisory_id)
        if doc is None:
            return None
        fields = {k: v for k, v in doc.items() if k in Advisory.__dataclass_fields__}
        return Advisory(**fields)

    def get(self, advisory_id: str) -> dict[str, Any] | None:
        """One advisory, redacted per §2 — the form a reader may see."""
        advisory = self.load(advisory_id)
        return advisory.to_dict() if advisory is not None else None

    def advisories(self, limit: int = 200, *, status: str | None = None) -> list[Advisory]:
        out: list[Advisory] = []
        for doc in self._corpus.list_advisories(limit, status=status):
            fields = {k: v for k, v in doc.items() if k in Advisory.__dataclass_fields__}
            out.append(Advisory(**fields))
        return out

    def list(self, limit: int = 200, *, status: str | None = None) -> list[dict[str, Any]]:
        """The public bulletin, newest number first, every entry redacted per §2. Withdrawn entries
        are included: the record is the point."""
        return [a.to_dict() for a in self.advisories(limit, status=status)]

    def osv(self, limit: int = 200) -> list[dict[str, Any]]:
        return [to_osv(a) for a in self.advisories(limit)]

    def index(self, signer: Any, *, limit: int = 200, now_ms: int | None = None) -> dict[str, Any]:
        return signed_index(self.advisories(limit), signer, now_ms=now_ms)

    def disclosed_dedup_keys(self) -> set[str]:
        """The BUG identities whose advisory is published as ``fixed``.

        The one input :func:`public_finding` needs, so the live findings ledger and the bulletin
        answer "may a reader see the reproducer for this bug?" from the same record instead of from
        two rules that can drift. An advisory that is `open` or `withdrawn` contributes nothing, so an
        empty bulletin discloses nothing — fail-closed by construction, not by a flag.
        """
        return {a.dedup_key for a in self.advisories(2000)
                if a.status == AdvisoryStatus.FIXED.value and a.dedup_key}

    def summary(self) -> dict[str, Any]:
        """Counts an operator (and the monitor panel) can read at a glance."""
        by_status: dict[str, int] = {}
        for advisory in self.advisories(2000):
            key = advisory.status or "open"
            by_status[key] = by_status.get(key, 0) + 1
        return {"advisories": sum(by_status.values()), "by_status": by_status,
                "bulletin_url": f"{self._public_url}/bulletin",
                "note": "an `open` advisory carries no reproducer, no evidence and no target: "
                        "coordinated disclosure, because MOMUS audits services we operate"}

    # ── internals ───────────────────────────────────────────────────────────
    def _save(self, advisory: Advisory, *, dedup_key: str) -> None:
        ident = AdvisoryId.parse(advisory.id)
        advisory.dedup_key = dedup_key
        self._corpus.save_advisory(
            advisory_id=advisory.id, year=ident.year, seq=ident.seq, dedup_key=dedup_key,
            status=advisory.status, component=advisory.component, severity=advisory.severity,
            published=advisory.published, modified=advisory.modified, doc=advisory.raw_dict())
