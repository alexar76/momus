"""Coordinated disclosure has to hold on EVERY public surface, not just the bulletin.

momus/bulletin.py §2 recorded the gap this file closes: the bulletin withholds an unfixed finding's
reproducer, while `GET /findings` and the `momus.findings@v1` capability served the same reproducer
(and the in-cluster target URL) straight from the corpus, publicly and unauthenticated. A rule that
holds on one route and not its neighbour is not a rule, so the tests here assert on the ROUTES and on
the whole response blob — a leak that survives a field assertion but shows up in a details string is
the same leak.

The other property under test is signature honesty. A redacted document cannot verify under the
signature that covered the original, and serving one that fails reads as tampering. So a public
finding either carries a signature that verifies, or carries none.
"""

from __future__ import annotations

import json

import httpx
import pytest

from momus.app import build_app
from momus.bulletin import public_finding, signed_body
from momus.capabilities import MomusRuntime
from momus.config import MomusConfig
from momus.findings import Evidence, Finding, Outcome, Status, verify_document_signature

TARGET_URL = "http://hub:9085"          # an in-cluster host: never publishable (bulletin.py §5)
REPRODUCER = f"curl -X POST {TARGET_URL}/ai-market/v2/invoke -d '{{\"input\":{{\"n\":1000}}}}'"
TITLE = "free tier serves 1000 unpaid calls when n exceeds the declared ceiling"


def _finding(scanner, *, probe="free_tier_ceiling_bypass", status_code=200) -> Finding:
    return scanner.sign_finding(Finding(
        target="hub", target_kind="hub", probe=probe, category="authz", severity="high",
        outcome=Outcome.FINDING.value, title=TITLE,
        detail=f"POST {TARGET_URL}/ai-market/v2/invoke with n=1000 returned 200 and no payment",
        status=Status.CONFIRMED.value,
        evidence=Evidence(
            request_digest="sha256-" + "a" * 64, response_digest="sha256-" + "b" * 64,
            request_snippet='{"capability_id": "c@v1", "input": {"n": 1000}}',
            response_snippet='{"output": {"served": true}, "price_usd": 0.0}',
            status_code=status_code, reproducer=REPRODUCER)))


def _as_doc(finding: Finding) -> dict:
    return json.loads(json.dumps(finding, default=lambda o: o.__dict__))


# ── the unit: one finding, one rule ──────────────────────────────────────────
def test_an_undisclosed_finding_loses_its_reproducer_and_its_payloads(scanner):
    """The exact leak bulletin.py §2 flagged: this document was public with a working attack script
    in it, against a host we operate."""
    public = public_finding(_as_doc(_finding(scanner)), disclosed=())

    assert public["evidence"]["reproducer"] == ""
    assert public["evidence"]["request_snippet"] == ""
    assert public["evidence"]["response_snippet"] == ""
    # The digests stay: they prove what happened without shipping the payload, which is what
    # findings.Evidence was shaped for.
    assert public["evidence"]["request_digest"].startswith("sha256-")
    assert public["evidence"]["status_code"] == 200
    # No copy-pasteable attack anywhere in the blob, and no topology: the reproducer, the captured
    # payloads and the in-cluster host the probe wrote into its own prose are all gone.
    blob = json.dumps(public)
    for leak in ("hub:9085", "curl", '"n": 1000', '"served": true'):
        assert leak not in blob, leak
    assert "<target-host>" in public["detail"]         # the path survives; the host does not
    assert "withheld-pending-fix" in public["disclosure"]


def test_the_ledger_still_names_its_entries(scanner):
    """The deliberate difference from the bulletin, asserted so it is a decision and not a drift.

    §2 replaces an open advisory's summary with a generated one-liner, because a permanent citable
    record has no need to describe an unfixed hole. The live ledger keeps the scanner's prose: a
    console whose rows cannot be told apart is not a ledger. So an unfixed finding here can still
    describe the SHAPE of the bug — what it can never carry is the copy-pasteable part.
    """
    public = public_finding(_as_doc(_finding(scanner)), disclosed=())
    assert public["title"] == TITLE
    assert "n=1000" in public["detail"]                # the shape of the bug survives …
    assert public["evidence"]["reproducer"] == ""      # … the weapon does not


def test_a_finding_whose_bug_is_published_as_fixed_comes_through(scanner):
    """Once the hole is closed the reproducer is a lesson, and withholding it is hoarding. Keyed on
    the DEDUP identity, so a rediscovery of an already-published bug is disclosed too."""
    finding = _finding(scanner)
    public = public_finding(_as_doc(finding), disclosed={finding.dedup_key})

    assert "/ai-market/v2/invoke" in public["evidence"]["reproducer"]
    assert public["disclosure"].startswith("full")
    # §5 is unconditional even here: the topology never ships, in any status.
    assert "hub:9085" not in json.dumps(public)
    assert "<target-host>" in public["evidence"]["reproducer"]


def test_disclosure_is_keyed_on_the_bug_not_the_report(scanner):
    """A different bug on the same target is NOT disclosed by its neighbour being fixed."""
    fixed = _finding(scanner, probe="p1")
    other = _finding(scanner, probe="p2", status_code=201)
    assert fixed.dedup_key != other.dedup_key

    disclosed = {fixed.dedup_key}
    assert public_finding(_as_doc(fixed), disclosed=disclosed)["evidence"]["reproducer"]
    assert public_finding(_as_doc(other), disclosed=disclosed)["evidence"]["reproducer"] == ""


def test_a_signature_present_in_a_public_finding_verifies(scanner):
    """The invariant that makes the redaction honest. A signature covers the whole document, so a
    redacted copy can never verify under it — and a signature that FAILS reads as tampering, or as
    MOMUS signing badly. So: verifiable, or withheld with a reason. Never broken."""
    finding = _finding(scanner)
    doc = _as_doc(finding)

    withheld = public_finding(doc, disclosed=())
    assert withheld["signature"].get("redacted") is True
    assert not withheld["signature"].get("value")
    assert "would no longer verify" in withheld["signature"]["note"]

    # The control: the ORIGINAL does verify, so the assertion above is about the redaction and not
    # about a signature that never worked.
    assert verify_document_signature(signed_body(doc), doc["signature"],
                                     doc["scanner_pubkey"]) is True


def test_redaction_is_pure_and_idempotent(scanner):
    doc = _as_doc(_finding(scanner))
    before = json.dumps(doc, sort_keys=True)
    once = public_finding(doc, disclosed=())
    assert json.dumps(doc, sort_keys=True) == before          # the input was not mutated
    assert public_finding(once, disclosed=()) == once


def test_the_scrubber_does_not_eat_an_iso_timestamp():
    """A regression: the `host:port` pass mistook an ISO instant for an in-cluster address.

    In ``2026-08-08T19:36:19Z`` the candidate host is ``2026-08-08T19`` — it satisfies "must contain
    a letter" because of the `T` — and the candidate port is ``:36``, so a published advisory read
    ``Re-tested by MOMUS on <target-host>:19Z``. Caught by reading a real `fixed` advisory, where the
    line being corrupted was the module's own. The clock-only form was already safe and tested; only
    the date-and-time form carries a letter.
    """
    from momus.bulletin import scrub_sensitive

    assert scrub_sensitive("Re-tested on 2026-08-08T19:36:19Z: gone") == \
        "Re-tested on 2026-08-08T19:36:19Z: gone"
    assert scrub_sensitive("at 2026-08-08 19:36:19 the probe ran") == \
        "at 2026-08-08 19:36:19 the probe ran"
    # …and the addresses it exists to catch are still caught.
    assert scrub_sensitive("reachable as hub:9085") == "reachable as <target-host>"
    assert scrub_sensitive("host 203.0.113.50:9085") == "host [ip-redacted]:9085"


# ── the routes: the surfaces a stranger can actually reach ───────────────────
@pytest.fixture
def wired(tmp_path, monkeypatch):
    """A real app over a real corpus, with one confirmed finding recorded."""
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_SIGNING_KEY_PATH", str(tmp_path / "scanner.key"))
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "offline")
    monkeypatch.setenv("AIFACTORY_PROD", "0")
    monkeypatch.delenv("MOMUS_BULLETIN", raising=False)
    monkeypatch.setenv("MOMUS_OPERATOR_TOKEN", "s3cret")
    runtime = MomusRuntime(MomusConfig.from_env())
    finding = _finding(runtime.signer)
    runtime.findings_db.record_finding(finding, scan_id="scan-test")
    app = build_app(runtime)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                               base_url="http://momus.local")
    return client, runtime, finding


@pytest.mark.asyncio
async def test_the_public_findings_route_serves_no_reproducer(wired):
    client, _runtime, _finding_obj = wired
    async with client as c:
        body = (await c.get("/findings")).json()

    assert body["count"] == 1
    assert body["findings"][0]["evidence"]["reproducer"] == ""
    assert "redacted" in body["disclosure"]
    blob = json.dumps(body)
    assert "hub:9085" not in blob and "curl" not in blob


@pytest.mark.asyncio
async def test_the_marketplace_invoke_path_serves_no_reproducer_either(wired):
    """The same document is reachable through /ai-market/v2/invoke, which is public by design (that
    is how the marketplace federates). A capability handler never sees the request, so it cannot be
    talked into the operator branch — this is where the ACT-capability gate was bypassed before."""
    client, _runtime, _finding_obj = wired
    async with client as c:
        r = await c.post("/ai-market/v2/invoke",
                         json={"capability_id": "momus.findings@v1", "input": {"limit": 10}})
        assert r.status_code == 200
        blob = json.dumps(r.json())

    assert "hub:9085" not in blob and "curl" not in blob and '"n": 1000' not in blob


@pytest.mark.asyncio
async def test_an_operator_still_gets_the_verifiable_original(wired):
    """The redaction protects readers, it does not blind the operator — otherwise triage and offline
    verification would have to move somewhere else."""
    client, _runtime, _finding_obj = wired
    async with client as c:
        body = (await c.get("/findings", headers={"x-momus-operator": "s3cret"})).json()

    doc = body["findings"][0]
    assert "/ai-market/v2/invoke" in doc["evidence"]["reproducer"]
    assert body["disclosure"].startswith("full")
    # Verified over signed_body(), and the response says so: the corpus adds seen_count /
    # first_seen_at / last_seen_at when it reads a row back, and hashing those too is why a naive
    # "everything minus signature" check failed on this route.
    assert set(body["unsigned_fields"]) >= {"seen_count", "first_seen_at", "last_seen_at"}
    assert any(k in doc for k in body["unsigned_fields"])
    assert verify_document_signature(signed_body(doc), doc["signature"],
                                     doc["scanner_pubkey"]) is True


@pytest.mark.asyncio
async def test_a_wrong_or_absent_token_gets_the_redacted_form(wired):
    client, _runtime, _finding_obj = wired
    async with client as c:
        for headers in ({}, {"x-momus-operator": "wrong"}, {"x-momus-operator": ""}):
            body = (await c.get("/findings", headers=headers)).json()
            assert body["findings"][0]["evidence"]["reproducer"] == "", headers


@pytest.mark.asyncio
async def test_publishing_a_fix_widens_the_findings_route_too(wired, verifier_a):
    """The end-to-end property: the bulletin is what DECIDES disclosure, so publishing an advisory as
    `fixed` is what releases the reproducer on the live ledger. One record, one rule, two surfaces."""
    import json as _json

    from momus.engine.remediation import FixVerdict

    client, runtime, finding = wired
    # A real signed fix verdict from MOMUS's own re-test gate, which signs with the scanner key —
    # the key the bulletin pins.
    verdict = FixVerdict(finding_id=finding.finding_id, target=finding.target, probe=finding.probe,
                         fixed=True, outcome="no_finding",
                         detail="the finding's own probe no longer reproduces")
    verdict.verifier_pubkey = runtime.signer.pubkey
    canon = _json.dumps(verdict.canonical(), sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False)
    verdict.signature = runtime.signer._signer.sign_payload(canon)
    gate = {**verdict.canonical(), "signature": verdict.signature}

    advisory = runtime.bulletin.publish(finding, gate_verdict=gate)
    assert advisory.status == "fixed"

    # Still withheld while publishing is OFF: no advisory is public, so nothing is disclosed.
    async with client as c:
        assert (await c.get("/findings")).json()["findings"][0]["evidence"]["reproducer"] == ""

    # And released once the operator turns the bulletin on.
    import os
    os.environ["MOMUS_BULLETIN"] = "1"
    try:
        app = build_app(runtime)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://momus.local") as c:
            doc = (await c.get("/findings")).json()["findings"][0]
            assert "/ai-market/v2/invoke" in doc["evidence"]["reproducer"]
            assert "hub:9085" not in _json.dumps(doc)      # §5 still unconditional
    finally:
        os.environ.pop("MOMUS_BULLETIN", None)


def test_the_scan_report_route_cannot_leak_what_the_bulletin_withheld(tmp_path, monkeypatch):
    """GET /scan/{id} served the FULL unredacted finding for a bug whose advisory was `open`.

    Reproduced by an adversarial review: the same bug published as an `open` advisory (reproducer
    withheld on all four bulletin surfaces) came back from the scan route with the reproducer — which
    carried the operator token — plus the in-cluster host, a bare IP and both raw snippets. No
    operator gate, no redaction, just a rate limiter.

    So the whole coordinated-disclosure design could be walked around by reading an advisory, taking
    the scan id it came from, and asking for the exploit directly. The lesson is the one the bulletin
    module had already written down and this route did not inherit: a disclosure rule enforced in ONE
    renderer is a habit, not a rule. Both now call the same public_finding().
    """
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_BULLETIN", "1")
    from fastapi.testclient import TestClient

    from momus.app import build_app
    from momus.capabilities import MomusRuntime
    from momus.config import MomusConfig

    runtime = MomusRuntime(MomusConfig.from_env())
    client = TestClient(build_app(runtime))

    SECRET = "curl -H 'x-momus-operator: s3cr3t' http://hub:9085/ai-market/v2/invoke"
    report = {
        "scan_id": "scan-leak-1",
        "findings": [{
            "finding_id": "mom-leak0001",
            "target": "hub", "probe": "free_tier_ceiling_bypass", "category": "authz",
            "severity": "high", "status": "confirmed", "title": "ceiling not enforced",
            "dedup_key": "never-disclosed",
            "evidence": {"reproducer": SECRET, "request_snippet": "raw request",
                         "response_snippet": "raw response",
                         "request_digest": "sha256-x", "response_digest": "sha256-y"},
        }],
    }
    runtime._scans["scan-leak-1"] = report

    body = client.get("/scan/scan-leak-1").text
    assert "s3cr3t" not in body, "the operator token reached a public route"
    assert SECRET not in body, "the reproducer for an undisclosed bug reached a public route"
    assert "hub:9085" not in body, "an in-cluster host reached a public route"
    assert "raw request" not in body and "raw response" not in body
