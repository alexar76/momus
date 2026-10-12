"""MOMUS as a signed threat-intel publisher for ARGUS's WARDEN firewall.

The red team feeds the blue team. MOMUS confirms a hostile pattern on a third-party MCP surface;
WARDEN — the firewall inside every ARGUS install — refuses that surface before its owner's agent ever
touches it. Without this channel the red team keeps finding things the blue team never hears about.

**We did not invent a protocol for this.** WARDEN already defines a signed-feed contract and already
enforces it fail-closed (`warden/src/threat-feed.ts`):

    { "records": ThreatRecord[], "timestamp": <epoch ms int>, "signature": "<hex ed25519>" }

signed over the **RFC 8785 (JCS)** canonical form of ``{records, timestamp}``, verified against a
hex-encoded **SPKI DER** public key the operator configures. WARDEN checks three things and keeps its
built-in floor if any fails: authenticity (signature), freshness (timestamp within a window, so a
stale snapshot cannot be replayed forever), determinism (canonical bytes). Conforming to a contract
somebody already hardened beats a bespoke bridge we would have to harden ourselves.

**ARGUS ships with no feed URL on purpose** — "a feed URL baked into the binary is a single point
every install would have to trust". So this is strictly opt-in: an operator who chooses to trust
MOMUS points `warden.threatFeedUrl` at it and pins `warden.feedPublicKey` to MOMUS's key. Nothing
here can push into anybody's agent.

## The rule that matters most: never publish a pattern that hits our own house

A WARDEN record is a **deny pattern**. Publishing `pattern: "hub"` would make every ARGUS install
that trusts us refuse *our own* Hub — the red team would have DoS'd the ecosystem with a signed
document. So:

* only findings whose target is a **third-party** surface are publishable at all;
* every candidate pattern is checked against a first-party denylist and dropped if it would match a
  component of ours;
* patterns must be specific enough to be meaningful (a 3-character pattern matches half the web).

Each rule is enforced here and tested, because the failure mode is not "a bad record" — it is a
signed, replayable, fleet-wide outage.
"""

from __future__ import annotations

import base64
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

# ── RFC 8785 (JCS) canonical form ────────────────────────────────────────────
# Narrow on purpose: the feed carries objects, arrays, strings and integers, and nothing else. A
# float would be a bug (WARDEN rejects a non-integer timestamp, and a fractional severity is
# meaningless), so this raises instead of guessing an encoding. tests/test_warden_feed.py asserts
# byte-for-byte agreement with the AWR reference implementation.

_ESCAPES = {
    '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
    "\n": "\\n", "\r": "\\r", "\t": "\\t",
}


def _jcs_string(text: str) -> str:
    out = ['"']
    for ch in text:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)      # JCS emits raw UTF-8 above U+001F, including non-ASCII
    out.append('"')
    return "".join(out)


def jcs(value: Any) -> str:
    """The RFC 8785 canonical serialization of *value*."""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, int):        # bool is handled above
        return str(value)
    if isinstance(value, float):
        raise TypeError("the threat feed carries no fractional numbers; a float here is a bug "
                        "(WARDEN rejects a non-integer timestamp outright)")
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        # JCS sorts by UTF-16 code units. For the ASCII keys this feed uses that is plain
        # code-point order; sorting the UTF-16 encoding keeps it correct for any key.
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(f"{_jcs_string(k)}:{jcs(v)}" for k, v in items) + "}"
    raise TypeError(f"{type(value).__name__} has no JCS form")


# ── the first-party guard ────────────────────────────────────────────────────
# OUR identities, as WARDEN would see them: server names, hostnames, package names.
#
# The check below is DIRECTIONAL, and getting the direction right is the whole point. WARDEN matches
# with `identity.includes(pattern)`, so a pattern is dangerous exactly when it is a SUBSTRING of one
# of our identities — "hub" is a substring of "aimarket-hub", so publishing it denies our Hub. The
# reverse containment is not dangerous and must not be refused: "evil-hub.example.com" contains "hub"
# but matches nothing of ours, and refusing it would silently drop legitimate third-party findings —
# a red team that cannot report on a hostile server because its name shares three letters with ours.
_FIRST_PARTY = (
    "aimarket", "aimarket-hub", "aimarket-agent", "aimarket-mcp", "aimarket-bridges",
    "aimarket-protocol", "aimarket-plugins", "aimarket-sdks", "aimarket-widget",
    "modelmarket.dev", "momus.modelmarket.dev", "metis.modelmarket.dev", "iot.modelmarket.dev",
    "oracles.modelmarket.dev", "skopos.modelmarket.dev", "service-mesh.modelmarket.dev",
    "atlas.modelmarket.dev", "magic-ai-factory.com", "alexar76.github.io", "alexar76",
    "momus", "treasury", "argus", "warden", "skopos", "metis", "gaia", "atlas", "helios",
    "dioscuri", "theoros", "acex", "lumen", "oracle-family", "aicom", "alien-monitor",
    "platon", "chronos", "ai-service-mesh", "aimarket-oracle-gateway",
)
# Below this length a pattern stops describing a threat and starts describing the internet.
MIN_PATTERN_LEN = 6

# A pattern must NAME something, not describe a category. WARDEN matches substrings, so a signed
# record of `pattern: "server"` makes every install that trusts us refuse essentially every MCP
# server on earth — a fleet-wide denial of service against third parties, published under our
# signature. Found by adversarially probing this guard: "server", "localhost", "python",
# "filesystem" and "mcp-server" all passed the length and first-party checks.
#
# So specificity is required structurally: the pattern must look like a HOST (contains a dot) or a
# NAMESPACED package (contains ':' or '/'). A bare word can never be published, however long it is.
# A reporter who means one package qualifies it — "npm:evil-pkg", not "evil-pkg" — and that
# qualification is information the record needs anyway.
_SPECIFIC = re.compile(r"^(?=.*[./:])[a-z0-9][a-z0-9._:/\-]*$")

# Belt to the structural braces: even WITH a dot or scope, these are categories rather than targets.
_GENERIC = frozenset({
    "mcp", "server", "servers", "mcp-server", "mcp-servers", "localhost", "127.0.0.1", "0.0.0.0",
    "python", "node", "nodejs", "npm", "pypi", "docker", "github", "gitlab", "filesystem", "http",
    "https", "api", "tool", "tools", "agent", "agents", "client", "proxy", "gateway", "sse",
    "stdio", "example.com", "localhost:3000", "test", "demo", "internal", ".com", ".io", ".dev",
    ".net", ".org", ".ai", "com", "io", "dev", "net", "org",
})

# MOMUS probe categories that can honestly be expressed as a WARDEN deny pattern. A billing-ceiling
# bug is real but is not something WARDEN can act on, so it is not published — a feed padded with
# records that cannot fire is a feed operators learn to ignore.
_PUBLISHABLE_CATEGORIES = {"injection", "prompt-injection", "authz", "replay", "exfiltration"}

_SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


class PatternRefused(ValueError):
    """A candidate record was refused. The reason is the message; it is logged, never swallowed."""


def check_pattern(pattern: str) -> str:
    """Return the pattern if it is safe to publish, else raise PatternRefused.

    Two failure modes, both worse than publishing nothing: a pattern that matches one of our own
    components turns a signed feed into a fleet-wide outage of our own ecosystem, and a pattern short
    enough to match everything turns WARDEN into a service that refuses all MCP servers.
    """
    p = (pattern or "").strip().lower()
    # First-party FIRST: short names like "hub" and "atlas" trip both rules, and "this is one of
    # ours" is the reason an operator needs to read. Reporting "too short" for `hub` would hide the
    # only fact that matters about it.
    #
    # Directional: refuse when the pattern is a SUBSTRING of one of our identities, because that is
    # exactly when WARDEN's `identity.includes(pattern)` would match us. Not the reverse.
    for own in _FIRST_PARTY:
        if p in own:
            raise PatternRefused(
                f"pattern {p!r} matches first-party identity {own!r} — publishing it would make "
                "every ARGUS install that trusts MOMUS refuse our own ecosystem")
    if len(p) < MIN_PATTERN_LEN:
        raise PatternRefused(
            f"pattern {p!r} is shorter than {MIN_PATTERN_LEN} characters — too broad to publish; "
            "it would match unrelated servers and WARDEN would deny half the world")
    # ASCII only. A homoglyph ("аimarket" with a Cyrillic а) matches nothing real, so it cannot deny
    # anything — but a non-ASCII pattern in a deny-list is always either a mistake or an attempt to
    # smuggle something past a reviewer's eyes, and neither belongs in a signed document.
    if not p.isascii():
        raise PatternRefused(
            f"pattern {p!r} contains non-ASCII characters — a deny pattern must be an exact "
            "identifier a reviewer can read unambiguously (homoglyphs are refused)")
    if p in _GENERIC:
        raise PatternRefused(
            f"pattern {p!r} names a CATEGORY, not a target — a signed record of it would make every "
            "install that trusts MOMUS refuse a whole class of unrelated third-party servers")
    if not _SPECIFIC.match(p):
        raise PatternRefused(
            f"pattern {p!r} is a bare word — it must name a host (contain a dot) or a namespaced "
            "package (contain ':' or '/'), e.g. 'evil.example.com' or 'npm:evil-pkg'. WARDEN matches "
            "substrings, so an unqualified word denies everything that happens to contain it")
    return p


@dataclass
class ThreatCandidate:
    """A confirmed MOMUS finding, in the shape WARDEN consumes."""

    pattern: str
    severity: str
    code: str
    reason: str
    source: str
    scope: str = "any"          # "server" | "tool" | "any"

    def to_record(self) -> dict[str, Any]:
        return {"pattern": check_pattern(self.pattern),
                "severity": _SEVERITY_MAP.get(self.severity.lower(), "medium"),
                "code": self.code, "reason": self.reason,
                "source": self.source, "scope": self.scope}


def candidate_from_finding(finding: dict[str, Any], *, first_party_targets: Iterable[str] = ()) -> ThreatCandidate:
    """Turn a MOMUS finding into a WARDEN candidate, or refuse it with a reason.

    Refuses, in order: a target of ours (we do not publish deny patterns about our own services), an
    unconfirmed finding (a signed feed must carry verified claims only), and a category WARDEN cannot
    act on.
    """
    target = str(finding.get("target") or "").strip().lower()
    if target in {t.strip().lower() for t in first_party_targets} or any(o in target for o in _FIRST_PARTY):
        raise PatternRefused(
            f"target {target!r} is first-party — MOMUS publishes deny patterns about THIRD-PARTY "
            "surfaces only; a finding about our own component goes to SKOPOS for remediation")
    status = str(finding.get("status") or "").lower()
    if status not in ("confirmed", "verified"):
        raise PatternRefused(
            f"finding {finding.get('finding_id')} is {status or 'unverified'} — the feed is signed, "
            "so it carries independently confirmed findings only")
    category = str(finding.get("category") or "").lower()
    if category not in _PUBLISHABLE_CATEGORIES:
        raise PatternRefused(
            f"category {category!r} is real but not actionable by a firewall — WARDEN matches "
            "patterns against server identity and tool definitions; publishing it would pad the "
            "feed with records that can never fire")
    pattern = str(finding.get("pattern") or finding.get("target") or "")
    return ThreatCandidate(
        pattern=pattern,
        severity=str(finding.get("severity") or "medium"),
        code=f"MOMUS-{str(finding.get('probe') or 'probe').upper().replace('_', '-')}",
        reason=str(finding.get("title") or "confirmed by MOMUS adversarial audit")[:200],
        source=f"momus:{finding.get('finding_id') or 'unknown'}",
        scope="tool" if "injection" in category else "any")


# ── the signed document ──────────────────────────────────────────────────────
def spki_hex(public_key_raw: bytes) -> str:
    """Ed25519 raw public key → hex SPKI DER, which is what `warden.feedPublicKey` expects.

    The 12-byte prefix is the fixed SPKI AlgorithmIdentifier for Ed25519 (RFC 8410): SEQUENCE, the
    1.3.101.112 OID, then the BIT STRING header. For Ed25519 it is constant, so the DER is a splice
    rather than a general encoder — and the test asserts `cryptography` produces the same bytes.
    """
    if len(public_key_raw) != 32:
        raise ValueError(f"an Ed25519 public key is 32 bytes, got {len(public_key_raw)}")
    prefix = bytes.fromhex("302a300506032b6570032100")
    return (prefix + public_key_raw).hex()


def _pubkey_b64(signer: Any) -> str:
    """MOMUS's runtime holds a FindingSigner (`.pubkey`); tests and tooling hold a raw Signer
    (`.public_key_b64`). Accept either rather than making callers unwrap."""
    key = getattr(signer, "public_key_b64", None) or getattr(signer, "pubkey", None)
    if not key:
        raise TypeError(f"{type(signer).__name__} exposes no Ed25519 public key")
    return key


def _sign_canonical(signer: Any, canonical: str) -> str:
    """Ed25519 signature, base64, from either signer shape."""
    if hasattr(signer, "sign_canonical"):
        return signer.sign_canonical(canonical)
    inner = getattr(signer, "_signer", None)      # FindingSigner wraps a Signer
    if inner is not None and hasattr(inner, "sign_canonical"):
        return inner.sign_canonical(canonical)
    raise TypeError(f"{type(signer).__name__} cannot sign a canonical string")


@dataclass
class WardenFeed:
    """Builds and signs the document WARDEN fetches."""

    signer: Any                                   # Signer or FindingSigner
    records: list[dict[str, Any]] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)

    def add(self, candidate: ThreatCandidate) -> bool:
        try:
            record = candidate.to_record()
        except PatternRefused as exc:
            self.refused.append(str(exc))
            return False
        if any(r["pattern"] == record["pattern"] for r in self.records):
            return False                          # one record per pattern; WARDEN matches, not counts
        self.records.append(record)
        return True

    def add_finding(self, finding: dict[str, Any], **kw) -> bool:
        try:
            return self.add(candidate_from_finding(finding, **kw))
        except PatternRefused as exc:
            self.refused.append(str(exc))
            return False

    @property
    def public_key_spki_hex(self) -> str:
        return spki_hex(base64.b64decode(_pubkey_b64(self.signer)))

    def document(self, *, now_ms: int | None = None) -> dict[str, Any]:
        """The signed feed. `timestamp` is epoch **milliseconds**, as WARDEN requires.

        Records are sorted by pattern so the same set of findings always produces identical bytes —
        a feed whose signature churns on key order is a feed operators cannot cache or diff.
        """
        records = sorted(self.records, key=lambda r: r["pattern"])
        timestamp = int(now_ms if now_ms is not None else time.time() * 1000)
        canonical = jcs({"records": records, "timestamp": timestamp})
        # WARDEN wants the signature hex-encoded; oracle_core signs to base64.
        sig_hex = base64.b64decode(_sign_canonical(self.signer, canonical)).hex()
        return {"records": records, "timestamp": timestamp, "signature": sig_hex}

    def summary(self, *, public_url: str = "") -> dict[str, Any]:
        """What is in the feed, what was refused, and the exact two lines an ARGUS operator needs.

        ARGUS needs NO code change to consume this — it reads the feed URL and the pinned key from
        the environment. Handing over a ready block matters because the alternative is transcribing
        88 hex characters by hand, and a mistyped pin fails as "signature INVALID", which reads like
        MOMUS published a bad feed rather than like a typo.
        """
        base = (public_url or "https://momus.modelmarket.dev").rstrip("/")
        return {"records": len(self.records), "refused": len(self.refused),
                "refusals": self.refused[:10],
                "feed_public_key_spki_hex": self.public_key_spki_hex,
                "note": "point warden.threatFeedUrl at /warden/threat-feed and pin "
                        "warden.feedPublicKey to feed_public_key_spki_hex",
                "argus_env": {
                    "ARGUS_THREAT_FEED_URL": f"{base}/warden/threat-feed",
                    "ARGUS_THREAT_FEED_PUBKEY": self.public_key_spki_hex,
                },
                "argus_env_block": (
                    f"export ARGUS_THREAT_FEED_URL={base}/warden/threat-feed\n"
                    f"export ARGUS_THREAT_FEED_PUBKEY={self.public_key_spki_hex}"),
                "trust_note": "Pinning this key is a decision to trust MOMUS's judgement about "
                              "third-party servers. WARDEN keeps its built-in floor if the feed is "
                              "unreachable, stale or unsigned — trusting MOMUS can only ADD "
                              "denials, never remove one."}


def build_feed(signer: Any, findings: Iterable[dict[str, Any]], *,
               first_party_targets: Iterable[str] = ()) -> WardenFeed:
    feed = WardenFeed(signer=signer)
    for f in findings:
        feed.add_finding(f, first_party_targets=first_party_targets)
    return feed


def feed_enabled() -> bool:
    """Publishing is opt-in. Off by default: an operator decides to become an intel publisher."""
    return os.environ.get("MOMUS_WARDEN_FEED", "").strip().lower() in ("1", "true", "yes", "on")


_MAX_RECORDS = 500      # WARDEN caps the body it will read; stay far under it


def cap(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the feed small enough that WARDEN's size limit never silently rejects the whole thing."""
    return records[:_MAX_RECORDS]


_PATTERN_SAFE = re.compile(r"^[a-z0-9._:\-/ ]+$")


def pattern_is_plain(pattern: str) -> bool:
    """WARNING guard: a pattern is matched as a substring, not a regex, by WARDEN — but a pattern
    carrying regex metacharacters is a sign the publisher meant something it is not getting."""
    return bool(_PATTERN_SAFE.match(pattern))
