"""The bulletin over HTTP — the routes, not the redaction logic.

tests/test_bulletin.py proves that momus/bulletin.py redacts correctly. This file proves the thing a
reader actually gets: that the redacted form is what leaves the process. A disclosure rule that holds
in a unit test and leaks through a route is not a disclosure rule, so the load-bearing test here
fetches EVERY bulletin surface for an `open` advisory and asserts the reproducer is absent from all
four bodies — including the Atom feed, where it would have arrived as prose rather than as a field.

The other half is the boring-but-fatal wire details: publishing is off unless an operator turns it
on (and off means 404, not 403), the Atom feed has to PARSE as XML for a reader to see anything at
all, and the OSV export has to carry the fields an OSV consumer looks for.
"""

from __future__ import annotations

import base64
import json
import time
import xml.etree.ElementTree as ET

import httpx
import pytest

from oracle_core.signing import Signer

from momus.app import ATOM_NS, build_app
from momus.capabilities import MomusRuntime
from momus.config import MomusConfig
from momus.findings import Evidence, Finding, Outcome, Status
from momus.warden_feed import jcs

PUBLIC_URL = "https://momus.modelmarket.dev"
TARGET_URL = "http://hub:9085"                  # an in-cluster host: never publishable (§5)
TITLE = "free tier serves 1000 unpaid calls when n exceeds the declared ceiling"
DETAIL = "POST /ai-market/v2/invoke with n=1000 returned 200 and a result with no payment required"
PROBE = "free_tier_ceiling_bypass"
YEAR = time.gmtime().tm_year

BULLETIN_ROUTES = ["/bulletin", "/bulletin.atom", "/bulletin/osv", f"/bulletin/MOMUS-{YEAR}-0001"]

# Everything an `open` advisory must never carry, whatever the route or the format: the in-cluster
# target, the reproducer, the probe parameters, the evidence digests, and the scanner's own
# informative title (which is itself a recipe).
LEAKS = ("hub:9085", "9085", "curl", "sha256-", PROBE, "n=1000", '"n": 1000', TITLE, DETAIL,
         "served")


def _runtime(tmp_path, monkeypatch, **env) -> MomusRuntime:
    """A MOMUS runtime over a throwaway corpus and a throwaway key. Offline provider, no network."""
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_SIGNING_KEY_PATH", str(tmp_path / "scanner.key"))
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "offline")
    monkeypatch.setenv("MOMUS_PUBLIC_URL", PUBLIC_URL)
    monkeypatch.setenv("AIFACTORY_PROD", "0")
    monkeypatch.setenv("MOMUS_BULLETIN", "1")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return MomusRuntime(MomusConfig.from_env())


def _client(runtime: MomusRuntime) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=build_app(runtime)),
                             base_url="http://momus.local")


@pytest.fixture
def momus(tmp_path, monkeypatch):
    runtime = _runtime(tmp_path, monkeypatch)
    return _client(runtime), runtime


def _finding(runtime: MomusRuntime, *, probe: str = PROBE, status_code: int = 200) -> Finding:
    """A signed finding against a FIRST-PARTY component — the only kind that can become an advisory."""
    evidence = Evidence(
        request_digest="sha256-" + "a" * 64,
        response_digest="sha256-" + "b" * 64,
        request_snippet='{"capability_id": "c@v1", "input": {"n": 1000}}',
        response_snippet='{"output": {"served": true}, "price_usd": 0.0}',
        status_code=status_code,
        reproducer=f"curl -X POST {TARGET_URL}/ai-market/v2/invoke -d '{{\"input\":{{\"n\":1000}}}}'",
    )
    return runtime.signer.sign_finding(Finding(
        target="hub", target_kind="hub", probe=probe, category="authz", severity="high",
        outcome=Outcome.FINDING.value, title=TITLE, detail=DETAIL, evidence=evidence,
        status=Status.CONFIRMED.value))


def _fix_verdict(runtime: MomusRuntime, finding: Finding) -> dict:
    """A real signed FixVerdict from MOMUS's own re-test gate — the ONLY thing that unlocks full
    disclosure. Signed with the scanner key, which is the key runtime.bulletin pins."""
    from momus.engine.remediation import FixVerdict

    verdict = FixVerdict(finding_id=finding.finding_id, target=finding.target, probe=finding.probe,
                         fixed=True, outcome="no_finding",
                         detail="the finding's own probe no longer reproduces")
    verdict.verifier_pubkey = runtime.signer.pubkey
    canonical = json.dumps(verdict.canonical(), sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    verdict.signature = runtime.signer._signer.sign_payload(canonical)
    return {**verdict.canonical(), "signature": verdict.signature}


# ── publication is opt-in ─────────────────────────────────────────────────────
async def test_every_bulletin_route_is_absent_until_an_operator_publishes(momus, monkeypatch):
    """404 on all four, and 404 rather than 403 on purpose: an operator who did not enable
    publishing HAS no bulletin, and "forbidden" would tell a reader one exists behind a permission.

    The advisory below is published FIRST, so the 404 is the switch and not an empty corpus."""
    client, runtime = momus
    advisory = runtime.bulletin.publish(_finding(runtime))
    monkeypatch.delenv("MOMUS_BULLETIN", raising=False)
    async with client as c:
        for path in BULLETIN_ROUTES + [f"/bulletin/{advisory.id}"]:
            r = await c.get(path)
            assert r.status_code == 404, f"{path} → {r.status_code}"
            # The reason names the switch, so an operator can tell "not published here" apart from
            # "that advisory does not exist" — two very different answers about the same URL.
            assert "MOMUS_BULLETIN" in r.json()["detail"], path
        # And the advisory really is on the record: turning the switch back on serves it.
        monkeypatch.setenv("MOMUS_BULLETIN", "1")
        assert (await c.get(f"/bulletin/{advisory.id}")).status_code == 200


async def test_the_bulletin_stays_public_in_prod_without_an_operator_token(tmp_path, monkeypatch):
    """Read-only and public, like the threat feed: the index is signed, so authenticity does not
    depend on who fetched it, and gating a public record would only mean fewer people can check it."""
    runtime = _runtime(tmp_path, monkeypatch, AIFACTORY_PROD="1", MOMUS_OPERATOR_TOKEN="s3cret")
    runtime.bulletin.publish(_finding(runtime))
    async with _client(runtime) as c:
        assert (await c.get("/health")).json()["control_gated"] is True
        for path in ["/bulletin", "/bulletin.atom", "/bulletin/osv"]:
            assert (await c.get(path)).status_code == 200, path


# ── §4 the signed index ───────────────────────────────────────────────────────
async def test_the_index_is_the_signed_envelope_warden_already_verifies(momus):
    """Exactly {advisories, timestamp, signature}: the shape ARGUS's WARDEN already checks, so a
    consumer needs no MOMUS-specific verifier. The signature is re-derived here from the served
    bytes — a route that returned a well-formed envelope with somebody else's signature would pass a
    shape assertion and fail this one."""
    client, runtime = momus
    runtime.bulletin.publish(_finding(runtime, probe="p1"))
    runtime.bulletin.publish(_finding(runtime, probe="p2", status_code=201))
    async with client as c:
        doc = (await c.get("/bulletin")).json()

    assert set(doc) == {"advisories", "timestamp", "signature"}
    assert isinstance(doc["timestamp"], int) and doc["timestamp"] > 0   # epoch ms, never a float
    assert len(doc["signature"]) == 128 and int(doc["signature"], 16) >= 0
    assert len(doc["advisories"]) == 2
    # Sorted by id, so the same record always produces the same bytes to cache, diff and replay-check.
    assert [a["id"] for a in doc["advisories"]] == sorted(a["id"] for a in doc["advisories"])

    canonical = jcs({"advisories": doc["advisories"], "timestamp": doc["timestamp"]})
    value_b64 = base64.b64encode(bytes.fromhex(doc["signature"])).decode()
    assert Signer.verify(canonical, value_b64, runtime.signer.pubkey) is True
    # The key to pin is the one /health already publishes — one key, not a third format to get wrong.
    async with _client(runtime) as c:
        assert (await c.get("/health")).json()["scanner_pubkey"] == runtime.signer.pubkey


async def test_one_advisory_by_id_and_a_404_for_anything_not_on_the_record(momus):
    client, runtime = momus
    advisory = runtime.bulletin.publish(_finding(runtime))
    async with client as c:
        entry = (await c.get(f"/bulletin/{advisory.id}")).json()
        assert entry["id"] == advisory.id == f"MOMUS-{YEAR}-0001"
        assert entry["status"] == "open" and entry["component"] == "hub"

        for unknown in [f"MOMUS-{YEAR}-9999", "not-an-advisory-id", "MOMUS-2026-1"]:
            r = await c.get(f"/bulletin/{unknown}")
            # One answer for "never existed" and "malformed": both are "not on the record", and
            # distinguishing them would let a caller enumerate which numbers are taken.
            assert r.status_code == 404, unknown
            assert "on the record" in r.json()["detail"]


# ── the Atom feed ─────────────────────────────────────────────────────────────
async def test_the_atom_feed_parses_as_xml_with_stable_ids_and_the_modified_time(momus):
    """A feed that does not parse shows a reader nothing at all, so this asserts through an XML
    parser rather than on substrings."""
    client, runtime = momus
    first = runtime.bulletin.publish(_finding(runtime, probe="p1"))
    second = runtime.bulletin.publish(_finding(runtime, probe="p2", status_code=201))
    async with client as c:
        r = await c.get("/bulletin.atom")
        again = await c.get("/bulletin.atom")

    # The real Atom media type: a feed reader dispatches on it, and application/xml would leave it
    # guessing what the document is.
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/atom+xml")
    assert "charset=utf-8" in r.headers["content-type"]

    feed = ET.fromstring(r.content)
    assert feed.tag == f"{{{ATOM_NS}}}feed"

    def text(el: ET.Element, tag: str) -> str:
        node = el.find(f"{{{ATOM_NS}}}{tag}")
        return (node.text or "") if node is not None else ""

    assert text(feed, "id") == f"{PUBLIC_URL}/bulletin"
    entries = feed.findall(f"{{{ATOM_NS}}}entry")
    assert len(entries) == 2
    by_id = {text(e, "id"): e for e in entries}
    for advisory in (first, second):
        entry = by_id[f"{PUBLIC_URL}/bulletin/{advisory.id}"]      # a stable, dereferenceable id
        # <updated> is the advisory's MODIFIED time, so a fix or a withdrawal shows up as an update
        # in a reader instead of being invisible until the next new advisory.
        assert text(entry, "updated") == advisory.modified
        assert text(entry, "published") == advisory.published
        assert advisory.id in text(entry, "title")
        terms = {c.get("term") for c in entry.findall(f"{{{ATOM_NS}}}category")}
        assert terms == {"authz", "severity:high", "status:open"}
    # The feed's own <updated> is the newest modification in the record, and every date is RFC 3339
    # (a malformed one makes a strict reader reject the whole document).
    assert text(feed, "updated") == max(first.modified, second.modified)
    assert text(feed, "updated").endswith("Z")
    # Stable across polls: readers dedupe on the entry id, so a churning one republishes the whole
    # bulletin as unread on every fetch.
    assert [text(e, "id") for e in ET.fromstring(again.content).findall(f"{{{ATOM_NS}}}entry")] == \
        [text(e, "id") for e in entries]


async def test_the_atom_feed_escapes_advisory_text_instead_of_being_broken_by_it(momus):
    """An advisory summary and a withdrawal reason are TEXT. Un-escaped, `<` and `&` either break the
    XML for every reader or inject markup into whatever renders it — and a raw control byte cannot be
    escaped at all, it can only be dropped, or the whole feed stops parsing."""
    client, runtime = momus
    advisory = runtime.bulletin.publish(_finding(runtime))
    hostile = '<script>alert("x")</script> & a stray ]]> plus a \x00 control byte'
    runtime.bulletin.withdraw(advisory.id, reason=hostile)
    async with client as c:
        r = await c.get("/bulletin.atom")

    assert b"<script>" not in r.content and b"&lt;script&gt;" in r.content
    assert b"\x00" not in r.content
    feed = ET.fromstring(r.content)              # parses, which is the actual assertion
    entry = feed.find(f"{{{ATOM_NS}}}entry")
    content = (entry.find(f"{{{ATOM_NS}}}content").text or "")
    # Round-trips as the literal text it always was: escaped on the wire, intact after parsing.
    assert '<script>alert("x")</script>' in content and "]]>" in content
    assert "\x00" not in content
    assert "withdrawn:" in content and "status: withdrawn" in content


# ── §3 the OSV export ─────────────────────────────────────────────────────────
async def test_the_osv_export_carries_the_fields_and_states_the_mismatch(momus):
    """OSV, with the version-axis mismatch said out loud. A consumer reads a missing `ranges` as
    "all versions affected", so the note is the difference between an honest export and one that
    implies a version range was checked when none exists."""
    client, runtime = momus
    finding = _finding(runtime)
    runtime.bulletin.publish(finding, gate_verdict=_fix_verdict(runtime, finding))
    async with client as c:
        r = await c.get("/bulletin/osv")

    # A bare ARRAY, which is what an OSV consumer expects — and proof the route is not swallowed by
    # /bulletin/{advisory_id}, which would have answered "no advisory 'osv'".
    records = r.json()
    assert r.status_code == 200 and isinstance(records, list) and len(records) == 1
    record = records[0]
    assert set(record) >= {"id", "modified", "published", "summary", "details", "severity",
                           "affected", "references", "credits", "database_specific"}
    assert record["id"] == f"MOMUS-{YEAR}-0001"
    assert record["affected"][0]["package"] == {"ecosystem": "AIMarket", "name": "hub"}
    assert "ranges" not in record["affected"][0]          # nothing was checked, so nothing is claimed
    assert record["severity"] == []                       # no CVSS vector is held, so none is invented
    assert record["database_specific"]["severity"] == "high"
    note = record["database_specific"]["note"].lower()
    assert "no version axis" in note and "package" in note
    assert {c["type"] for c in record["credits"]} == {"FINDER", "REMEDIATION_VERIFIER"}


# ── the test this whole file exists for ───────────────────────────────────────
async def test_an_open_advisory_served_over_http_carries_no_reproducer(momus):
    """MOMUS audits services WE operate, so a published reproducer against an unfixed component is
    an attack script hosted under our own name and signature. Every surface is checked, because a
    leak through the Atom feed is the same leak as a leak through the JSON — and the Atom feed is
    the easy one to forget, since there the reproducer would arrive as prose, not as a field."""
    client, runtime = momus
    advisory = runtime.bulletin.publish(_finding(runtime))
    assert advisory.status == "open"
    assert "curl" in advisory.raw_dict()["reproducer"]        # it IS on the record, just not served

    async with client as c:
        index = await c.get("/bulletin")
        one = await c.get(f"/bulletin/{advisory.id}")
        osv = await c.get("/bulletin/osv")
        atom = await c.get("/bulletin.atom")

    entry = one.json()
    assert entry["reproducer"] == "" and entry["evidence"] == {}
    assert entry["references"] == [] and entry["gate_verdict"] == {}
    assert "withheld" in entry["disclosure"]                  # the record states its own limits
    assert index.json()["advisories"][0]["reproducer"] == ""
    assert osv.json()[0]["database_specific"]["reproducer"] == ""
    assert osv.json()[0]["database_specific"]["evidence"] == {}

    # Then the whole body of every route, because a leak that survives the field assertions by
    # riding along inside a details string is exactly as published as a leak in its own field.
    for response in (index, one, osv, atom):
        body = response.text
        for leak in LEAKS:
            assert leak not in body, f"{leak!r} leaked via {response.request.url.path}"


async def test_a_fixed_advisory_does_serve_its_reproducer(momus):
    """Otherwise the test above proves nothing: a bulletin that never serves a reproducer would pass
    it while being useless. Once the hole is closed the reproducer is a lesson, and the switch is a
    MOMUS-signed `fixed` verdict — never a status string."""
    client, runtime = momus
    finding = _finding(runtime)
    advisory = runtime.bulletin.publish(finding, gate_verdict=_fix_verdict(runtime, finding))
    assert advisory.status == "fixed"

    async with client as c:
        entry = (await c.get(f"/bulletin/{advisory.id}")).json()
        atom = (await c.get("/bulletin.atom")).text

    assert entry["disclosure"] == "full"
    assert "/ai-market/v2/invoke" in entry["reproducer"]        # the path IS the lesson
    assert "reproducer:" in atom and "/ai-market/v2/invoke" in atom
    # §5 is unconditional even here: the in-cluster host is replaced everywhere it appears, and the
    # fix verdict's full signature blob was never published — only a digest of it.
    assert "hub:9085" not in entry["reproducer"] and "<target-host>" in entry["reproducer"]
    assert "hub:9085" not in atom
    assert "signature" not in entry["gate_verdict"]
    assert entry["gate_verdict"]["signature_digest"].startswith("sha256-")
