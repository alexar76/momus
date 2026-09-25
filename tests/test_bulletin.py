"""MOMUS's security bulletin.

The dangerous failure here is not a malformed advisory — it is a **well-formed, signed, published**
one that carries a working reproducer against a hole we have not fixed yet, on a host we operate. So
the disclosure tests assert on the SERIALIZED output field by field, and then on the whole blob:
a leak that survives the field assertions but appears in a details string is the same leak.

The second family of tests is about the record itself: a stable number per bug, numbers that are
never reused, and a withdrawn advisory that stays on the record with its reason. A public advisory
list that can be quietly renumbered or quietly emptied is not a record.
"""

from __future__ import annotations

import base64
import json
import re
import time

import pytest

from oracle_core.signing import Signer

from momus.bulletin import (
    Advisory,
    AdvisoryId,
    AdvisoryRefused,
    AdvisoryStatus,
    BulletinStore,
    bulletin_enabled,
    index_public_key_spki_hex,
    redact_for_disclosure,
    scrub_sensitive,
    signed_index,
    to_osv,
)
from momus.findings import Evidence, Finding, Outcome, Status
from momus.store import FindingStore
from momus.warden_feed import jcs

TARGET_URL = "http://hub:9085"                      # an in-cluster host: never publishable (§5)
TITLE = "free tier serves 1000 unpaid calls when n exceeds the declared ceiling"
DETAIL = "POST /ai-market/v2/invoke with n=1000 returned 200 and a result with no payment required"
YEAR = time.gmtime().tm_year


def _finding(scanner, *, target="hub", probe="free_tier_ceiling_bypass", category="authz",
             severity="high", status=Status.CONFIRMED.value, status_code=200, title=TITLE,
             reproducer: str | None = None) -> Finding:
    evidence = Evidence(
        request_digest="sha256-" + "a" * 64,
        response_digest="sha256-" + "b" * 64,
        request_snippet='{"capability_id": "c@v1", "input": {"n": 1000}}',
        response_snippet='{"output": {"served": true}, "price_usd": 0.0}',
        status_code=status_code,
        reproducer=reproducer if reproducer is not None else
        f"curl -X POST {TARGET_URL}/ai-market/v2/invoke -d '{{\"input\":{{\"n\":1000}}}}'",
    )
    return scanner.sign_finding(Finding(
        target=target, target_kind="hub", probe=probe, category=category, severity=severity,
        outcome=Outcome.FINDING.value, title=title, detail=DETAIL, evidence=evidence, status=status))


def _bulletin(tmp_path, *, verifier_pubkey: str = "") -> BulletinStore:
    return BulletinStore(FindingStore(str(tmp_path)), verifier_pubkey=verifier_pubkey)


def _fix_verdict(verifier, finding: Finding, *, fixed: bool = True) -> dict:
    """A real signed FixVerdict — the same document the remediation deploy gate emits."""
    from momus.engine.remediation import FixVerdict

    v = FixVerdict(finding_id=finding.finding_id, target=finding.target, probe=finding.probe,
                   fixed=fixed, outcome="no_finding" if fixed else "finding",
                   detail="the finding's own probe no longer reproduces")
    v.verifier_pubkey = verifier.pubkey
    canon = json.dumps(v.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    v.signature = verifier._signer.sign_payload(canon)
    return {**v.canonical(), "signature": v.signature}


# ── §1 the stable id ─────────────────────────────────────────────────────────
def test_the_same_bug_minted_twice_gets_the_same_number(tmp_path, scanner):
    """The whole point of a stable id: a rediscovery is the SAME bug, so it is the same advisory.
    Keyed on dedup_key, not finding_id — a number per report is just a report id in a costume."""
    bulletin = _bulletin(tmp_path)
    first = _finding(scanner)
    second = _finding(scanner)                      # same bug, new report
    assert first.dedup_key == second.dedup_key and first.finding_id != second.finding_id

    a = bulletin.publish(first)
    b = bulletin.publish(second)
    assert a.id == b.id
    assert len(bulletin.list()) == 1                # one advisory, not two
    # Both reports are recorded on the one advisory: several findings share one dedup identity.
    assert set(b.finding_ids) == {first.finding_id, second.finding_id}


def test_the_number_survives_a_restart(tmp_path, scanner):
    """Persisted in the corpus. A number that resets on restart is not stable, it is a session id."""
    f = _finding(scanner)
    minted = _bulletin(tmp_path).publish(f).id
    assert _bulletin(tmp_path).publish(_finding(scanner)).id == minted   # fresh process


def test_distinct_bugs_get_distinct_monotonic_zero_padded_numbers(tmp_path, scanner):
    bulletin = _bulletin(tmp_path)
    first = bulletin.publish(_finding(scanner, probe="free_tier_ceiling_bypass"))
    second = bulletin.publish(_finding(scanner, probe="manifest_signature_integrity",
                                       status_code=201))
    assert first.id == f"MOMUS-{YEAR}-0001"
    assert second.id == f"MOMUS-{YEAR}-0002"
    assert re.match(r"^MOMUS-\d{4}-\d{4}$", second.id)
    assert AdvisoryId.parse(second.id).seq == 2


def test_a_number_is_never_reused_after_a_withdrawal(tmp_path, scanner):
    """A withdrawn advisory keeps its number forever. Handing 0001 to a different bug later would
    make every citation of MOMUS-YYYY-0001 ambiguous — and citations are what a bulletin is for."""
    bulletin = _bulletin(tmp_path)
    first = bulletin.publish(_finding(scanner, probe="p1"))
    second = bulletin.publish(_finding(scanner, probe="p2", status_code=201))
    bulletin.withdraw(first.id, reason="duplicate of an upstream advisory")

    third = bulletin.publish(_finding(scanner, probe="p3", status_code=202))
    assert [first.id, second.id, third.id] == [f"MOMUS-{YEAR}-000{n}" for n in (1, 2, 3)]
    assert third.id != first.id
    # And the withdrawn one is still on the record.
    assert first.id in {a["id"] for a in bulletin.list()}


def test_advisory_id_widens_rather_than_wrapping_past_four_digits():
    """The 10 000th advisory of a year must not collide with the first."""
    assert str(AdvisoryId(2026, 7)) == "MOMUS-2026-0007"
    assert str(AdvisoryId(2026, 10000)) == "MOMUS-2026-10000"
    assert AdvisoryId.parse("MOMUS-2026-10000").seq == 10000
    with pytest.raises(ValueError):
        AdvisoryId.parse("MOMUS-2026-1")


# ── §2 coordinated disclosure: the test that stops us publishing an exploit ──
def test_an_open_advisory_exposes_no_reproducer_no_evidence_no_target(tmp_path, scanner):
    """Field by field on the SERIALIZED output, because this is the assertion that stands between
    MOMUS and publishing a working attack script against a service we run."""
    bulletin = _bulletin(tmp_path)
    advisory = bulletin.publish(_finding(scanner))
    assert advisory.status == AdvisoryStatus.OPEN.value

    pub = advisory.to_dict()
    assert pub["status"] == "open"
    assert pub["reproducer"] == ""
    assert pub["evidence"] == {}
    assert pub["references"] == []
    assert pub["gate_verdict"] == {}
    assert pub["withdrawn_reason"] == ""
    # What a reader DOES get: the id, the dates, the component, the category, the severity and one
    # non-actionable line. Enough to know a hole exists and to count it.
    assert pub["id"] == advisory.id
    assert pub["component"] == "hub" and pub["category"] == "authz" and pub["severity"] == "high"
    assert pub["published"] and pub["modified"]
    assert "withheld" in pub["disclosure"]

    # And nothing actionable anywhere in the blob: no target URL, no probe parameters, no digests,
    # no request/response snippets, no scanner title.
    blob = json.dumps(pub)
    for leak in ("hub:9085", "curl", "9085", "sha256-", "free_tier_ceiling_bypass",
                 '"n": 1000', "n=1000", TITLE, DETAIL, "served"):
        assert leak not in blob, leak


def test_an_open_advisory_summary_is_generated_not_the_scanners_title(tmp_path, scanner):
    """A scanner title is written to be informative, which is the same thing as actionable. The
    public one-liner is DERIVED from (severity, category, component) so it cannot be a recipe."""
    advisory = _bulletin(tmp_path).publish(_finding(scanner))
    pub = advisory.to_dict()
    assert pub["summary"] == "high authz issue in hub — under coordinated disclosure"
    assert advisory.summary == TITLE            # the real title is kept internally, just not served


def test_the_default_serialization_is_the_redacted_one(tmp_path, scanner):
    """Redaction is the DEFAULT path, not an opt-in. A caller who forgets to think about disclosure
    gets the safe answer; the unredacted form has a deliberately awkward name."""
    advisory = _bulletin(tmp_path).publish(_finding(scanner))
    assert advisory.to_dict()["reproducer"] == ""
    assert "curl" in advisory.raw_dict()["reproducer"]           # kept internally, on purpose
    assert _bulletin(tmp_path).get(advisory.id)["reproducer"] == ""
    assert all(a["reproducer"] == "" for a in _bulletin(tmp_path).list())


def test_a_fixed_advisory_does_expose_the_reproducer(tmp_path, scanner, verifier_a):
    """Once the hole is closed the reproducer is a lesson, not a weapon — and withholding it then
    is just hoarding. The switch is a MOMUS-signed `fixed` verdict, nothing else."""
    bulletin = _bulletin(tmp_path, verifier_pubkey=verifier_a.pubkey)
    finding = _finding(scanner)
    advisory = bulletin.publish(finding, gate_verdict=_fix_verdict(verifier_a, finding))
    assert advisory.status == AdvisoryStatus.FIXED.value

    pub = advisory.to_dict()
    assert pub["disclosure"] == "full"
    assert "/ai-market/v2/invoke" in pub["reproducer"]           # the path IS the lesson
    assert pub["evidence"]["response_digest"].startswith("sha256-")
    assert pub["evidence"]["status_code"] == 200
    assert pub["summary"] == TITLE
    assert "free_tier_ceiling_bypass" in pub["details"]
    assert pub["gate_verdict"]["fixed"] is True
    assert pub["gate_verdict"]["signature_digest"].startswith("sha256-")
    # §5 still applies to a fully disclosed advisory: the in-cluster host is gone, and the full
    # signature blob was never published — only a digest of it.
    assert "hub:9085" not in json.dumps(pub)
    assert "<target-host>" in pub["reproducer"]
    assert "signature" not in pub["gate_verdict"]


@pytest.mark.parametrize("mutate,why", [
    (lambda gate, f: {k: v for k, v in gate.items() if k != "signature"}, "unsigned"),
    (lambda gate, f: {**gate, "signature": {"algorithm": "ed25519", "value": ""}}, "empty signature"),
    (lambda gate, f: {**gate, "finding_id": "mom-somebody-elses-bug"}, "another finding"),
    (lambda gate, f: {**gate, "outcome": "finding", "fixed": False}, "not fixed"),
    (lambda gate, f: {**gate, "detail": "tampered after signing"}, "tampered body"),
    (lambda gate, f: {"finding_id": f.finding_id, "fixed": True}, "bare dict"),
])
def test_a_forged_fix_verdict_cannot_unlock_the_reproducer(tmp_path, scanner, verifier_a,
                                                           mutate, why):
    """The gate that unlocks full disclosure is the most attractive thing here to forge: it turns a
    withheld hole into a published exploit. Every failure mode leaves the advisory OPEN — the same
    fail-closed shape as economics._fix_verdict_ok, which once released real money on an unsigned
    dict because the check was skipped whenever an operand was falsy."""
    bulletin = _bulletin(tmp_path, verifier_pubkey=verifier_a.pubkey)
    finding = _finding(scanner)
    advisory = bulletin.publish(finding, gate_verdict=mutate(_fix_verdict(verifier_a, finding),
                                                             finding))
    assert advisory.status == AdvisoryStatus.OPEN.value, why
    assert advisory.to_dict()["reproducer"] == ""


def test_with_no_verifier_key_pinned_nothing_can_ever_be_published_as_fixed(tmp_path, scanner,
                                                                            verifier_a):
    """No pin, no full disclosure. Fail-closed default: an unconfigured bulletin publishes the
    minimum, it does not fall back to trusting whatever verdict it was handed."""
    bulletin = _bulletin(tmp_path)                  # verifier_pubkey=""
    finding = _finding(scanner)
    advisory = bulletin.publish(finding, gate_verdict=_fix_verdict(verifier_a, finding))
    assert advisory.status == AdvisoryStatus.OPEN.value
    assert advisory.to_dict()["reproducer"] == ""


def test_a_withdrawn_advisory_stays_on_the_record_with_its_reason(tmp_path, scanner, verifier_a):
    """An advisory that vanishes is worse than one that was wrong: silent deletion is how a public
    record stops being trustworthy. So a withdrawal is a state, never a delete."""
    bulletin = _bulletin(tmp_path, verifier_pubkey=verifier_a.pubkey)
    finding = _finding(scanner)
    advisory = bulletin.publish(finding, gate_verdict=_fix_verdict(verifier_a, finding))
    withdrawn = bulletin.withdraw(advisory.id, reason="the ceiling was enforced by a proxy; the "
                                                      "finding was an artefact of the test harness")

    listed = bulletin.list()
    assert [a["id"] for a in listed] == [advisory.id]
    entry = listed[0]
    assert entry["status"] == "withdrawn"
    assert "artefact of the test harness" in entry["withdrawn_reason"]
    assert "withdrawn" in entry["disclosure"]
    # Withheld again, deliberately: a record MOMUS no longer stands behind must not carry a working
    # reproducer under MOMUS's signature.
    assert entry["reproducer"] == "" and entry["evidence"] == {}
    assert withdrawn.modified >= advisory.published


def test_a_rescan_cannot_resurrect_a_withdrawn_advisory(tmp_path, scanner, verifier_a):
    """Withdrawal is an operator's judgement about the RECORD. If a rescan (or a fix verdict) could
    quietly re-list it, the withdrawal would be as unreliable as a deletion."""
    bulletin = _bulletin(tmp_path, verifier_pubkey=verifier_a.pubkey)
    finding = _finding(scanner)
    advisory = bulletin.publish(finding)
    bulletin.withdraw(advisory.id, reason="reported by mistake against a staging build")

    again = bulletin.publish(_finding(scanner), gate_verdict=_fix_verdict(verifier_a, finding))
    assert again.id == advisory.id
    assert again.status == AdvisoryStatus.WITHDRAWN.value
    assert "reported by mistake" in again.to_dict()["withdrawn_reason"]
    assert again.to_dict()["reproducer"] == ""


def test_a_reference_type_outside_osvs_enum_becomes_web(tmp_path, scanner, verifier_a):
    """An out-of-enum reference type makes the whole OSV record fail validation, and a consumer that
    rejects our document learns nothing from it."""
    bulletin = _bulletin(tmp_path, verifier_pubkey=verifier_a.pubkey)
    finding = _finding(scanner)
    advisory = bulletin.publish(finding, gate_verdict=_fix_verdict(verifier_a, finding),
                                references=[{"type": "blog-post", "url": "https://github.com/x/y"},
                                            {"type": "fix", "url": "https://github.com/x/y/pull/1"}])
    types = {r["type"] for r in advisory.to_dict()["references"]}
    assert types == {"WEB", "FIX"}


def test_a_withdrawal_without_a_reason_is_refused(tmp_path, scanner):
    bulletin = _bulletin(tmp_path)
    advisory = bulletin.publish(_finding(scanner))
    with pytest.raises(AdvisoryRefused, match="reason"):
        bulletin.withdraw(advisory.id, reason="   ")
    with pytest.raises(AdvisoryRefused, match="no advisory"):
        bulletin.withdraw("MOMUS-2026-9999", reason="nope")


def test_every_advisory_states_its_status_explicitly(tmp_path, scanner, verifier_a):
    """A reader must never have to infer whether a hole is still open."""
    bulletin = _bulletin(tmp_path, verifier_pubkey=verifier_a.pubkey)
    open_one = bulletin.publish(_finding(scanner, probe="p1"))
    fixed_finding = _finding(scanner, probe="p2", status_code=201)
    fixed_one = bulletin.publish(fixed_finding, gate_verdict=_fix_verdict(verifier_a, fixed_finding))
    bulletin.withdraw(bulletin.publish(_finding(scanner, probe="p3", status_code=202)).id,
                      reason="published in error")
    statuses = {a["id"]: a["status"] for a in bulletin.list()}
    assert set(statuses.values()) == {"open", "fixed", "withdrawn"}
    assert statuses[open_one.id] == "open" and statuses[fixed_one.id] == "fixed"
    assert all(a["status"] and a["disclosure"] for a in bulletin.list())


def test_redaction_is_pure_and_idempotent(tmp_path, scanner):
    """Pure so it is trivially testable, idempotent so a double-redaction (a list built from already
    public dicts, say) can never widen disclosure."""
    advisory = _bulletin(tmp_path).publish(_finding(scanner))
    before = advisory.raw_dict()
    once = redact_for_disclosure(advisory)
    assert advisory.raw_dict() == before                     # the input was not mutated
    assert redact_for_disclosure(once) == once


def test_an_unknown_status_is_treated_as_open(tmp_path):
    """Fail closed: anything we cannot positively identify as `fixed` is an open hole."""
    advisory = Advisory(id=f"MOMUS-{YEAR}-0001", status="probably-fine", published="x", modified="x",
                        component="hub", category="authz", severity="high", summary=TITLE,
                        reproducer=f"curl {TARGET_URL}/x", evidence={"status_code": 200})
    pub = advisory.to_dict()
    assert pub["status"] == "open" and pub["reproducer"] == "" and pub["evidence"] == {}


# ── §5 never in the bulletin ─────────────────────────────────────────────────
def test_a_warden_reports_lead_can_never_become_an_advisory(tmp_path):
    """Leads are not findings. A lead is an anonymous stranger's claim; numbering it as a MOMUS
    advisory would put our name on somebody else's accusation."""
    from momus.warden_reports import validate

    lead = validate({"identity": "evil-mcp.example.com",
                     "reason": "tool description asked my agent to exfiltrate the wallet"}).to_dict()
    with pytest.raises(AdvisoryRefused, match="UNVERIFIED third-party report"):
        _bulletin(tmp_path).publish(lead)

    # And laundering it — stripping the markers that say it is a lead — does not help: it still has
    # no signed finding behind it.
    laundered = {k: v for k, v in lead.items()
                 if k not in ("verified", "is_momus_finding", "disclaimer")}
    with pytest.raises(AdvisoryRefused):
        _bulletin(tmp_path).publish(laundered)


def test_a_third_party_target_can_never_become_an_advisory(tmp_path, scanner):
    """The bulletin is MOMUS's record of holes in services WE run. A third-party accusation belongs
    in the WARDEN threat feed, which has its own first-party guard and its own operator gating."""
    with pytest.raises(AdvisoryRefused, match="NOT one of our components"):
        _bulletin(tmp_path).publish(_finding(scanner, target="evil-mcp.example.com"))


@pytest.mark.parametrize("target", ["203.0.113.50", "10.0.0.4:9085", "hub/admin"])
def test_a_component_that_is_a_host_or_an_address_is_refused(tmp_path, scanner, target):
    """§5: never a private host, never a bare IP — not even as the component name."""
    with pytest.raises(AdvisoryRefused):
        _bulletin(tmp_path).publish(_finding(scanner, target=target))


def test_an_unsigned_or_tampered_finding_is_refused(tmp_path, scanner):
    """An advisory must trace back to a document a reader can verify offline."""
    doc = json.loads(json.dumps(_finding(scanner).__dict__, default=lambda o: o.__dict__))
    # The control: the same document, untouched, publishes fine — so the refusals below are about
    # the tampering and not about the shape of a dict that came off the wire.
    assert _bulletin(tmp_path).publish(doc).id

    with pytest.raises(AdvisoryRefused, match="unsigned"):
        _bulletin(tmp_path).publish({**doc, "signature": {}})
    with pytest.raises(AdvisoryRefused, match="does not verify"):
        _bulletin(tmp_path).publish({**doc, "severity": "critical"})


def test_an_honest_negative_or_a_refuted_finding_is_not_published(tmp_path, scanner):
    """An advisory about a hole that does not exist is noise in a security feed — and publishing a
    refuted claim puts our signature on something we know to be wrong."""
    negative = scanner.sign_finding(Finding(
        target="hub", target_kind="hub", probe="p", category="authz", severity="info",
        outcome=Outcome.NO_FINDING.value, title="the ceiling held", detail="d",
        evidence=Evidence("sha256-a", "sha256-b", status_code=402)))
    with pytest.raises(AdvisoryRefused, match="honest NEGATIVE"):
        _bulletin(tmp_path).publish(negative)
    with pytest.raises(AdvisoryRefused, match="REFUTED"):
        _bulletin(tmp_path).publish(_finding(scanner, status=Status.REFUTED.value))


def test_private_hosts_tokens_and_signature_blobs_are_scrubbed_from_any_text():
    """Unconditional, in every status. Our reproducers are built from in-cluster base URLs, so
    publishing one verbatim publishes our topology."""
    scrubbed = scrub_sensitive(
        "curl http://203.0.113.50:9085/ai-market/v2/invoke "
        "-H 'X-Momus-Operator-Token: s3cret-operator-token' "
        "-H 'Authorization: Bearer eyJhbGciOi.payload.signature' "
        f"# sig={'A' * 88}", limit=2000)
    assert "203.0.113.50" not in scrubbed
    assert "<target-host>/ai-market/v2/invoke" in scrubbed     # the path survives; the host does not
    assert "s3cret-operator-token" not in scrubbed
    assert "eyJhbGciOi.payload.signature" not in scrubbed
    assert "A" * 88 not in scrubbed and "[blob-redacted]" in scrubbed
    # A bare `host:port` in prose is an in-cluster address too, and the URL pass cannot see it.
    assert scrub_sensitive("reachable as hub:9085 on the ecosystem network") == \
        "reachable as <target-host> on the ecosystem network"
    assert "12:30" in scrub_sensitive("observed at 12:30 UTC")      # a clock is not an address
    # A public ecosystem host is left alone — an advisory reference must stay clickable.
    assert scrub_sensitive("see https://momus.modelmarket.dev/bulletin") \
        .endswith("https://momus.modelmarket.dev/bulletin")
    # An evidence digest is publishable for a fixed advisory, so the blob rule must not eat it.
    assert "sha256-" + "a" * 64 in scrub_sensitive("digest sha256-" + "a" * 64)


# ── §4 the signed index ──────────────────────────────────────────────────────
def test_the_signed_index_verifies_under_the_signers_key(tmp_path, scanner):
    bulletin = _bulletin(tmp_path)
    bulletin.publish(_finding(scanner, probe="p1"))
    bulletin.publish(_finding(scanner, probe="p2", status_code=201))
    signer = Signer(str(tmp_path / "index.key"))

    doc = signed_index(bulletin.advisories(), signer, now_ms=1786200000000)
    assert set(doc) == {"advisories", "timestamp", "signature"}
    assert isinstance(doc["timestamp"], int)          # an epoch-ms integer, like WARDEN's feed
    assert len(doc["signature"]) == 128 and int(doc["signature"], 16) >= 0
    assert [a["id"] for a in doc["advisories"]] == sorted(a["id"] for a in doc["advisories"])

    canonical = jcs({"advisories": doc["advisories"], "timestamp": doc["timestamp"]})
    value_b64 = base64.b64encode(bytes.fromhex(doc["signature"])).decode()
    assert Signer.verify(canonical, value_b64, signer.public_key_b64) is True


def test_a_tampered_advisory_breaks_the_index_signature(tmp_path, scanner):
    """Otherwise the check above proves nothing."""
    bulletin = _bulletin(tmp_path)
    bulletin.publish(_finding(scanner))
    signer = Signer(str(tmp_path / "index.key"))
    doc = signed_index(bulletin.advisories(), signer, now_ms=1786200000000)

    doc["advisories"][0]["severity"] = "low"
    tampered = jcs({"advisories": doc["advisories"], "timestamp": doc["timestamp"]})
    value_b64 = base64.b64encode(bytes.fromhex(doc["signature"])).decode()
    assert Signer.verify(tampered, value_b64, signer.public_key_b64) is False


def test_the_same_advisories_always_produce_the_same_bytes(tmp_path, scanner):
    """An index whose signature churns on iteration order cannot be cached, diffed or replay-checked."""
    bulletin = _bulletin(tmp_path)
    bulletin.publish(_finding(scanner, probe="p1"))
    bulletin.publish(_finding(scanner, probe="p2", status_code=201))
    signer = Signer(str(tmp_path / "index.key"))
    forward = bulletin.advisories()
    a = signed_index(forward, signer, now_ms=1)
    b = signed_index(list(reversed(forward)), signer, now_ms=1)
    assert a["signature"] == b["signature"]


def test_an_index_carrying_a_fixed_advisory_still_canonicalizes(tmp_path, scanner, verifier_a):
    """A fixed entry carries the pieces most likely to break canonical bytes — an integer status
    code, a boolean gate, nested objects. jcs() refuses a float outright, so a fixed advisory that
    ever grew a fractional field would fail here rather than at the verifier."""
    bulletin = _bulletin(tmp_path, verifier_pubkey=verifier_a.pubkey)
    finding = _finding(scanner)
    bulletin.publish(finding, gate_verdict=_fix_verdict(verifier_a, finding))
    signer = Signer(str(tmp_path / "index.key"))
    doc = signed_index(bulletin.advisories(), signer, now_ms=1786200000000)
    canonical = jcs({"advisories": doc["advisories"], "timestamp": doc["timestamp"]})
    value_b64 = base64.b64encode(bytes.fromhex(doc["signature"])).decode()
    assert Signer.verify(canonical, value_b64, signer.public_key_b64) is True
    assert doc["advisories"][0]["evidence"]["status_code"] == 200


def test_the_index_refuses_a_raw_dict_that_would_leak(tmp_path):
    """The last gate before bytes are signed. Redundant with redact_for_disclosure by construction,
    and kept because a signed exploit cannot be recalled once somebody has fetched it."""
    leaking = {"id": f"MOMUS-{YEAR}-0001", "status": "open", "reproducer": f"curl {TARGET_URL}/x"}
    with pytest.raises(AdvisoryRefused, match="never be published with the means to exploit"):
        signed_index([leaking], Signer(str(tmp_path / "k")))

    # And relabelling it `fixed` does not get it past the gate either: the word is not the verdict.
    with pytest.raises(AdvisoryRefused, match="carries no fix verdict"):
        signed_index([{**leaking, "status": "fixed"}], Signer(str(tmp_path / "k")))


def test_the_key_to_pin_is_published_in_wardens_encoding(tmp_path):
    """Same encoding as the threat feed: one fewer format for an operator to get wrong."""
    assert len(index_public_key_spki_hex(Signer(str(tmp_path / "k")))) == 2 * (12 + 32)


def test_publishing_is_opt_in(monkeypatch):
    monkeypatch.delenv("MOMUS_BULLETIN", raising=False)
    assert bulletin_enabled() is False
    monkeypatch.setenv("MOMUS_BULLETIN", "1")
    assert bulletin_enabled() is True


# ── §3 OSV export ────────────────────────────────────────────────────────────
def test_osv_export_states_the_version_mismatch_instead_of_pretending(tmp_path, scanner,
                                                                      verifier_a):
    bulletin = _bulletin(tmp_path, verifier_pubkey=verifier_a.pubkey)
    finding = _finding(scanner)
    record = to_osv(bulletin.publish(finding, gate_verdict=_fix_verdict(verifier_a, finding)))

    assert record["id"] == f"MOMUS-{YEAR}-0001"
    assert record["affected"][0]["package"] == {"ecosystem": "AIMarket", "name": "hub"}
    assert "ranges" not in record["affected"][0]           # nothing was checked, so nothing is claimed
    assert record["affected"][0]["database_specific"]["version_range_checked"] is False
    note = record["database_specific"]["note"]
    assert "no version axis" in note.lower() or "NO version range was checked" in note
    assert record["severity"] == []                        # no CVSS vector is held, so none is invented
    assert record["database_specific"]["severity"] == "high"
    assert set(record) >= {"schema_version", "id", "modified", "published", "summary", "details",
                           "severity", "affected", "references", "credits", "database_specific"}
    assert {c["type"] for c in record["credits"]} == {"FINDER", "REMEDIATION_VERIFIER"}


def test_the_osv_export_of_an_open_advisory_is_redacted_too(tmp_path, scanner):
    """Every export path goes through §2, not just the one a reviewer happened to read."""
    record = to_osv(_bulletin(tmp_path).publish(_finding(scanner)))
    blob = json.dumps(record)
    assert record["database_specific"]["reproducer"] == ""
    assert record["database_specific"]["evidence"] == {}
    assert "hub:9085" not in blob and "curl" not in blob and TITLE not in blob


def test_a_withdrawn_advisory_uses_osvs_own_withdrawn_field(tmp_path, scanner):
    """A consumer that honours `withdrawn` stops acting on the record without us deleting it."""
    bulletin = _bulletin(tmp_path)
    advisory = bulletin.publish(_finding(scanner))
    bulletin.withdraw(advisory.id, reason="duplicate of MOMUS-2026-0001")
    record = to_osv(bulletin.load(advisory.id))
    assert record["withdrawn"] == record["modified"]
    assert record["database_specific"]["withdrawn_reason"] == "duplicate of MOMUS-2026-0001"
    assert record["database_specific"]["advisory_status"] == "withdrawn"


def test_the_summary_counts_what_an_operator_needs(tmp_path, scanner):
    bulletin = _bulletin(tmp_path)
    bulletin.publish(_finding(scanner, probe="p1"))
    bulletin.withdraw(bulletin.publish(_finding(scanner, probe="p2", status_code=201)).id,
                      reason="not reproducible outside the harness")
    summary = bulletin.summary()
    assert summary["advisories"] == 2
    assert summary["by_status"] == {"open": 1, "withdrawn": 1}
    assert "coordinated disclosure" in summary["note"]


# ── the regression that republished a live exploit ───────────────────────────
def test_a_regression_does_not_keep_serving_the_new_reproducer_as_fixed(tmp_path, scanner, verifier_a):
    """A bug that was fixed and came back must NOT stay `fixed` with the NEW reproducer public.

    Reproduced by an adversarial review, end to end: publish an advisory as `fixed` with a valid
    signed verdict for finding A; the bug returns; publish finding B (same dedup identity, no new
    verdict). Status stayed `fixed`, disclosure stayed `full`, and the reproducer served — through the
    signed index, the single advisory, the OSV export, Atom and /findings at once — was B's, fresh and
    working.

    The fallback was justified in a comment: re-hiding "protects nobody, the reproducer is already
    out". That is true of A's reproducer and false of B's, and B's is what gets served. The verdict now
    has to cover the finding whose body is being published, not merely one the advisory has collected.
    """
    verifier = verifier_a
    store = _bulletin(tmp_path, verifier_pubkey=verifier.pubkey)

    first = _finding(scanner, reproducer="curl OLD-EXPLOIT")
    adv = store.publish(first, gate_verdict=_fix_verdict(verifier, first))
    assert adv.status == "fixed"
    assert "OLD-EXPLOIT" in json.dumps(adv.to_dict()), "a fixed advisory discloses its reproducer"

    # Same bug, later scan, no new verdict — a regression.
    second = _finding(scanner, reproducer="curl NEW-WORKING-EXPLOIT")
    again = store.publish(second)

    assert again.id == adv.id, "the id is per BUG and must survive a regression"
    assert again.status == "open", f"a regression must revert to open, got {again.status!r}"
    assert again.regressed is True and again.regression_note

    blob = json.dumps(again.to_dict())
    assert "NEW-WORKING-EXPLOIT" not in blob, "the NEW reproducer must never be served"


def test_a_fresh_verdict_for_the_new_finding_re_fixes_it(tmp_path, scanner, verifier_a):
    """The guard must not make a genuinely re-fixed bug unfixable — a permanently `open` advisory
    nobody can close would be the opposite failure."""
    verifier = verifier_a
    store = _bulletin(tmp_path, verifier_pubkey=verifier.pubkey)

    first = _finding(scanner, reproducer="curl OLD")
    store.publish(first, gate_verdict=_fix_verdict(verifier, first))

    second = _finding(scanner, reproducer="curl NEW")
    assert store.publish(second).status == "open"

    refixed = store.publish(second, gate_verdict=_fix_verdict(verifier, second))
    assert refixed.status == "fixed"
    assert "curl NEW" in json.dumps(refixed.to_dict()), "a verified fix discloses its reproducer"
