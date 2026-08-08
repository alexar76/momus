"""MOMUS → WARDEN signed threat feed.

Two kinds of test here, and the second kind is the point:

* unit tests for the refusal rules, because the dangerous failure is not a malformed record — it is a
  **valid, signed, replayable** record whose pattern matches our own ecosystem and takes it offline
  across every ARGUS install that trusts us;
* cross-implementation tests that check our canonical bytes against the AWR reference JCS and, when
  Node is available, verify the signature with ARGUS's ACTUAL verifier. A feed that only our own code
  agrees with is not interoperable, it is a private format with extra steps.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from oracle_core.signing import Signer

from momus.warden_feed import (
    MIN_PATTERN_LEN,
    PatternRefused,
    ThreatCandidate,
    WardenFeed,
    build_feed,
    candidate_from_finding,
    check_pattern,
    jcs,
    spki_hex,
)

ROOT = Path(__file__).resolve().parents[2]


def _finding(**kw):
    base = {"finding_id": "mom-abc123", "target": "evil-mcp.example.com", "probe": "tool_poisoning",
            "category": "injection", "severity": "high", "status": "confirmed",
            "title": "tool description carries hidden exfiltration instructions"}
    base.update(kw)
    return base


# ── the guard that protects our own house ────────────────────────────────────
@pytest.mark.parametrize("pattern", [
    "hub", "momus", "aimarket-hub", "modelmarket.dev", "argus", "warden", "skopos",
    "metis.modelmarket.dev", "alexar76", "atlas",
])
def test_a_pattern_matching_our_own_ecosystem_is_refused(pattern):
    """A WARDEN record is a DENY pattern. Publishing one of ours, signed, is a self-inflicted
    fleet-wide outage of our own services — the worst thing this channel could ever do."""
    with pytest.raises(PatternRefused, match="first-party"):
        check_pattern(pattern)


@pytest.mark.parametrize("pattern", [
    "evil-hub.example.com",          # contains "hub" but matches nothing of ours
    "metis-clone.attacker.net",      # contains "metis"
    "fake-argus-updates.io",         # contains "argus"
])
def test_a_third_party_pattern_is_not_refused_for_merely_sharing_letters(pattern):
    """The guard is DIRECTIONAL. Refusing every pattern that happens to contain one of our names
    would silence the red team about hostile servers that typosquat us — which is precisely the
    class of server this feed exists to report. Caught by the 'hub' case failing its own test."""
    assert check_pattern(pattern) == pattern


def test_a_too_short_pattern_is_refused():
    """WARDEN matches substrings. A 3-character pattern denies half the internet."""
    with pytest.raises(PatternRefused, match="too broad"):
        check_pattern("ftp")
    assert len(check_pattern("evil-mcp.example.com")) >= MIN_PATTERN_LEN


def test_a_finding_about_our_own_target_never_becomes_a_record():
    """A finding about our own component belongs in the SKOPOS remediation loop, not in a public
    deny-list. Two different jobs; conflating them publishes our bugs to strangers."""
    with pytest.raises(PatternRefused, match="first-party"):
        candidate_from_finding(_finding(target="aimarket-hub", pattern="aimarket-hub"))


def test_an_unconfirmed_finding_is_never_published():
    """The document is signed. A signature turns a guess into an accusation with our name on it."""
    with pytest.raises(PatternRefused, match="raw|unverified"):
        candidate_from_finding(_finding(status="raw"))


def test_a_category_a_firewall_cannot_act_on_is_not_published():
    """A billing-ceiling bug is real and gets a bounty — but WARDEN matches server/tool identity, so
    the record could never fire. A feed padded with dead records is a feed operators stop reading."""
    with pytest.raises(PatternRefused, match="not actionable"):
        candidate_from_finding(_finding(category="billing"))


def test_a_valid_third_party_finding_becomes_a_usable_record():
    rec = candidate_from_finding(_finding()).to_record()
    assert rec["pattern"] == "evil-mcp.example.com"
    assert rec["severity"] == "high"
    assert rec["code"] == "MOMUS-TOOL-POISONING"
    assert rec["source"] == "momus:mom-abc123"
    assert rec["scope"] == "tool"          # injection findings match tool definitions
    assert set(rec) == {"pattern", "severity", "code", "reason", "source", "scope"}


def test_refusals_are_reported_not_swallowed(tmp_path):
    """An operator must be able to see WHY a finding did not reach the feed. A silent drop is
    indistinguishable from 'MOMUS found nothing'."""
    feed = build_feed(Signer(str(tmp_path / "k")),
                      [_finding(), _finding(finding_id="m2", target="aimarket-hub"),
                       _finding(finding_id="m3", category="billing")])
    assert len(feed.records) == 1 and len(feed.refused) == 2
    assert any("first-party" in r for r in feed.refused)
    assert any("not actionable" in r for r in feed.refused)


def test_duplicate_patterns_collapse(tmp_path):
    feed = WardenFeed(signer=Signer(str(tmp_path / "k")))
    c = ThreatCandidate(pattern="evil-mcp.example.com", severity="high", code="C",
                        reason="r", source="s")
    assert feed.add(c) is True and feed.add(c) is False and len(feed.records) == 1


# ── the wire format ──────────────────────────────────────────────────────────
def test_document_shape_is_exactly_what_warden_reads(tmp_path):
    doc = build_feed(Signer(str(tmp_path / "k")), [_finding()]).document(now_ms=1786200000000)
    assert set(doc) == {"records", "timestamp", "signature"}
    assert isinstance(doc["timestamp"], int)                    # WARDEN rejects non-integers
    assert len(doc["signature"]) == 128                          # 64 raw bytes, hex
    int(doc["signature"], 16)                                    # hex, not base64


def test_the_same_findings_always_produce_the_same_bytes(tmp_path):
    """A feed whose signature churns on iteration order cannot be cached, diffed or replayed-checked."""
    s = Signer(str(tmp_path / "k"))
    a = build_feed(s, [_finding(), _finding(finding_id="m2", target="bad2.example.org",
                                            pattern="bad2.example.org")])
    b = build_feed(s, [_finding(finding_id="m2", target="bad2.example.org",
                                pattern="bad2.example.org"), _finding()])
    assert a.document(now_ms=1)["signature"] == b.document(now_ms=1)["signature"]


def test_spki_hex_matches_the_cryptography_library(tmp_path):
    """The SPKI prefix is spliced rather than DER-encoded; prove it against a real encoder."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes_raw()
    expected = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()
    assert spki_hex(raw) == expected


def test_a_float_is_refused_rather_than_guessed():
    """JCS number encoding for non-integers is subtle; WARDEN rejects a fractional timestamp anyway.
    Raising beats emitting bytes the verifier will not reproduce."""
    with pytest.raises(TypeError, match="fractional"):
        jcs({"x": 1.5})


# ── cross-implementation agreement ───────────────────────────────────────────
def test_our_jcs_matches_the_awr_reference_implementation():
    """If our canonical bytes differ from the reference by one character, every signature we publish
    is invalid — and the only symptom WARDEN shows is 'signature INVALID'."""
    sys.path.insert(0, str(ROOT / "awr" / "reference" / "python"))
    awr_jcs = pytest.importorskip("awr.jcs", reason="AWR reference implementation not present")

    samples = [
        {"records": [], "timestamp": 1786200000000},
        {"records": [{"pattern": "evil.example.com", "severity": "high", "code": "MOMUS-X",
                      "reason": "hidden instructions", "source": "momus:m1", "scope": "tool"}],
         "timestamp": 1786200000000},
        # ordering, unicode, escapes, control characters, nesting
        {"z": 1, "a": {"b": [1, 2, {"d": "quote\" back\\slash"}], "A": "Ä unicode ✓"},
         "tab": "a\tb", "nl": "a\nb", "ctrl": "ab", "t": True, "f": False, "n": None},
    ]
    for sample in samples:
        assert jcs(sample).encode("utf-8") == awr_jcs.canonicalize(sample), sample


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_argus_verifier_accepts_our_signature(tmp_path):
    """The end-to-end proof: verify OUR document with ARGUS's actual verification code path —
    node:crypto, hex SPKI DER key, Ed25519 over the canonical bytes. This is the assertion that
    makes the integration real rather than plausible."""
    signer = Signer(str(tmp_path / "k"))
    feed = build_feed(signer, [_finding()])
    doc = feed.document(now_ms=1786200000000)

    script = tmp_path / "verify.mjs"
    script.write_text(
        "import { verify, createPublicKey } from 'node:crypto';\n"
        "const doc = JSON.parse(process.argv[2]);\n"
        "const keyHex = process.argv[3];\n"
        "const payload = process.argv[4];\n"          # canonical bytes, produced by OUR jcs
        "const pub = createPublicKey({ key: Buffer.from(keyHex, 'hex'),"
        " format: 'der', type: 'spki' });\n"
        "const ok = verify(null, Buffer.from(payload, 'utf8'), pub,"
        " Buffer.from(doc.signature, 'hex'));\n"
        "console.log(ok ? 'VALID' : 'INVALID');\n",
        encoding="utf-8")
    canonical = jcs({"records": doc["records"], "timestamp": doc["timestamp"]})
    out = subprocess.run(
        ["node", str(script), json.dumps(doc), feed.public_key_spki_hex, canonical],
        capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "VALID", (out.stdout, out.stderr)

    # And a tampered record must fail, or the check above proves nothing.
    doc["records"][0]["severity"] = "low"
    canonical_tampered = jcs({"records": doc["records"], "timestamp": doc["timestamp"]})
    out2 = subprocess.run(
        ["node", str(script), json.dumps(doc), feed.public_key_spki_hex, canonical_tampered],
        capture_output=True, text=True, timeout=60)
    assert out2.stdout.strip() == "INVALID", (out2.stdout, out2.stderr)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_argus_own_jcs_agrees_with_ours(tmp_path):
    """ARGUS canonicalizes with its own TypeScript JCS. Both sides must produce identical bytes from
    the wire JSON, or the signature verifies against bytes nobody else can reproduce."""
    argus_jcs = ROOT / "argus" / "src" / "warden" / "jcs.ts"
    if not argus_jcs.is_file():
        pytest.skip("argus/src/warden/jcs.ts not present")
    signer = Signer(str(tmp_path / "k"))
    doc = build_feed(signer, [_finding()]).document(now_ms=1786200000000)
    payload = {"records": doc["records"], "timestamp": doc["timestamp"]}

    # Run the TS canonicalizer through the compiled dist if present; otherwise transpile-free check
    # of the shipped JS build.
    dist = ROOT / "argus" / "dist" / "warden" / "jcs.js"
    if not dist.is_file():
        pytest.skip("argus dist not built (npm run build) — TS canonicalizer not runnable")
    script = tmp_path / "canon.mjs"
    script.write_text(
        f"import {{ canonicalize }} from '{dist.as_posix()}';\n"
        "console.log(canonicalize(JSON.parse(process.argv[2])));\n", encoding="utf-8")
    out = subprocess.run(["node", str(script), json.dumps(payload)],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.rstrip("\n") == jcs(payload)


# ── the HTTP surface ─────────────────────────────────────────────────────────
def _app(monkeypatch, tmp_path, *, enabled=True):
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_WARDEN_FEED", "1" if enabled else "0")
    from fastapi.testclient import TestClient

    from momus.app import build_app
    from momus.capabilities import MomusRuntime
    from momus.config import MomusConfig
    return TestClient(build_app(MomusRuntime(MomusConfig.from_env())))


def test_feed_route_is_404_until_an_operator_enables_publishing(monkeypatch, tmp_path):
    """404 rather than 403: with publishing off there IS no feed, and 'forbidden' would imply one
    exists behind a permission — which would tell a stranger we hold intel we are withholding."""
    r = _app(monkeypatch, tmp_path, enabled=False).get("/warden/threat-feed")
    assert r.status_code == 404 and "disabled" in r.json()["detail"]


def test_feed_route_is_public_and_serves_the_warden_shape(monkeypatch, tmp_path):
    """Public on purpose: WARDEN verifies the DOCUMENT, so gating the transport adds nothing and
    only means fewer installs are protected."""
    r = _app(monkeypatch, tmp_path).get("/warden/threat-feed")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"records", "timestamp", "signature"}
    assert isinstance(body["timestamp"], int) and isinstance(body["records"], list)


def test_summary_exposes_the_key_to_pin(monkeypatch, tmp_path):
    body = _app(monkeypatch, tmp_path).get("/warden/threat-feed/summary").json()
    assert len(body["feed_public_key_spki_hex"]) == 2 * (12 + 32)   # SPKI prefix + raw key, hex
    assert "warden.feedPublicKey" in body["note"]


def test_the_agent_card_advertises_the_skill(monkeypatch, tmp_path):
    card = _app(monkeypatch, tmp_path).get("/.well-known/agent-card.json").json()
    skill = next((s for s in card["skills"] if s["id"] == "threat-intel"), None)
    assert skill is not None
    assert "first-party" in skill["description"]     # the safety rule is stated in the contract


# ── adversarial: can this feed be used to harm THIRD parties at scale? ────────
@pytest.mark.parametrize("pattern", [
    "server", "servers", "mcp-server", "localhost", "python", "node", "filesystem",
    "api", "gateway", "proxy", "stdio", "example.com", "docker",
])
def test_a_category_pattern_cannot_be_published(pattern):
    """The worst thing this feed could do to strangers, found by probing the guard rather than
    reading it: `pattern: "server"` is a valid, signed record that makes every install trusting
    MOMUS refuse essentially every MCP server on earth. `server`, `localhost`, `python`,
    `filesystem` and `mcp-server` all passed the length and first-party checks before this."""
    # Assert the REFUSAL, not which guard caught it: "api" is also too short and "gateway" also
    # overlaps a first-party identity. All three reasons are correct; requiring one of them made the
    # test brittle without making the guarantee stronger.
    with pytest.raises(PatternRefused):
        check_pattern(pattern)


@pytest.mark.parametrize("pattern", ["evil-pkg", "badactor", "hostileserver", "someserver"])
def test_a_bare_word_cannot_be_published_however_long(pattern):
    """Length is not specificity. A pattern must NAME a host or a namespaced package."""
    with pytest.raises(PatternRefused, match="bare word"):
        check_pattern(pattern)


@pytest.mark.parametrize("pattern", [
    "evil.example.com", "npm:evil-pkg", "registry.evil.io/mcp", "bad-actor.example.org",
    "pkg:npm/evil-tools", "sub.domain.evil.example.net",
])
def test_a_specific_third_party_target_is_still_publishable(pattern):
    """The guard must not silence the red team: a concrete hostile target has to get through, or the
    feed is a safety theatre that reports nothing."""
    assert check_pattern(pattern) == pattern


def test_a_homoglyph_pattern_is_refused():
    """A Cyrillic 'а' in "аimarket" denies nothing real — but a non-ASCII deny pattern is either a
    mistake or an attempt to slip something past a reviewer, and a signed document carries neither."""
    with pytest.raises(PatternRefused, match="non-ASCII"):
        check_pattern("аimarket-hub")


def test_case_and_whitespace_cannot_smuggle_a_first_party_pattern():
    for sneaky in ("  AIMARKET-HUB  ", "MoMuS.ModelMarket.Dev", "\tskopos\n"):
        with pytest.raises(PatternRefused):
            check_pattern(sneaky)


def test_the_feed_is_capped_so_it_cannot_be_grown_until_warden_rejects_it(tmp_path):
    """WARDEN refuses a body over its size limit. An unbounded feed would eventually publish a
    document its own consumer throws away — the whole deny-list silently stops working."""
    from momus.warden_feed import cap

    assert len(cap([{"pattern": f"h{i}.example.com"} for i in range(5000)])) <= 500
