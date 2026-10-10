"""The SKOPOS import must produce findings the fix loop can actually act on."""

from __future__ import annotations

import pytest

from momus.engine.remediation import escalation_for
from momus.findings import Outcome, Severity
from momus.intel.skopos_bridge import import_findings, to_finding


def _doc(*findings: dict, server: str = "oracle-host") -> dict:
    return {"server": server, "observed_at": "2026-09-13T21:00:00Z", "findings": list(findings)}


PORT = {
    "severity": "high",
    "category": "ports",
    "title": "PostgreSQL reachable from the internet",
    "detail": "tcp/5432 on 0.0.0.0 (postgres)",
    "recommendation": "Restrict bind to localhost or VPN; use firewall rules.",
}


def test_a_skopos_finding_becomes_an_actionable_momus_finding():
    [finding] = import_findings(_doc(PORT))
    assert finding.target == "oracle-host"
    assert finding.severity == Severity.HIGH.value
    assert finding.outcome == Outcome.FINDING.value
    assert finding.probe == "skopos:ports"
    # "ports" is SKOPOS's word; MOMUS files it under the risk it represents.
    assert finding.category == "exposure"
    assert finding.detail
    # A ticket is only useful if whoever picks it up can re-observe the defect.
    assert "skoposctl" in finding.evidence.reproducer
    assert finding.evidence.response_digest.startswith("sha256-")


def test_rescans_of_the_same_defect_are_one_finding():
    """An hourly scan must not open a ticket — or pay a bounty — every hour."""
    first = to_finding(PORT, server="oracle-host", observed_at="2026-09-13T21:00:00Z")
    later = to_finding(PORT, server="oracle-host", observed_at="2026-09-14T09:00:00Z")
    assert first is not None and later is not None
    assert first.dedup_key == later.dedup_key
    assert first.finding_id != later.finding_id  # distinct observations, same defect

    # Same defect on a different host is a different defect.
    elsewhere = to_finding(PORT, server="attested-host")
    assert elsewhere is not None
    assert elsewhere.dedup_key != first.dedup_key


def test_one_document_carrying_the_same_defect_twice_yields_one_finding():
    assert len(import_findings(_doc(PORT, dict(PORT)))) == 1


def test_info_is_dropped_unless_asked_for():
    noise = {"severity": "info", "category": "ports", "title": "sshd listening on 22", "detail": ""}
    assert import_findings(_doc(noise)) == []
    assert len(import_findings(_doc(noise), include_info=True)) == 1


@pytest.mark.parametrize(
    "raw",
    [
        {"severity": "high", "category": "ports", "title": "", "detail": "no title"},
        {"severity": "not-a-severity", "category": "ports", "title": "x"},
        {"category": "ports", "title": "no severity at all"},
    ],
)
def test_unusable_rows_are_skipped_not_guessed_at(raw):
    assert to_finding(raw, server="oracle-host") is None


def test_a_document_with_no_server_is_refused():
    """A host finding with no host cannot be routed, fixed or verified."""
    with pytest.raises(ValueError):
        import_findings({"findings": [PORT]})


def test_importing_does_not_bypass_human_escalation():
    """Being imported must not become a way to get an automated patch onto an infra box."""
    [finding] = import_findings(_doc(PORT, server="momus"))
    # Whatever escalation_for says for this component, the imported finding gets the
    # same answer as a natively-discovered one — the bridge sets no route of its own.
    assert escalation_for(finding.target, finding.target_kind) == escalation_for("momus", "host")


# ── the road, not just the door ─────────────────────────────────────────────────
# Converting an export and returning a count is what this route used to do, and it is
# indistinguishable from working: the caller gets 200 and a list of ids. These tests are
# about the half that was missing — that an imported finding is in the corpus, under an
# id the rest of the loop can resolve.
@pytest.fixture
def wired(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from momus.app import build_app
    from momus.capabilities import MomusRuntime
    from momus.config import MomusConfig

    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_SIGNING_KEY_PATH", str(tmp_path / "scanner.key"))
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "offline")
    monkeypatch.setenv("AIFACTORY_PROD", "0")
    monkeypatch.setenv("MOMUS_OPERATOR_TOKEN", "s3cret")
    runtime = MomusRuntime(MomusConfig.from_env())
    return runtime, TestClient(build_app(runtime))


def test_an_imported_finding_reaches_the_corpus(wired):
    runtime, client = wired
    r = client.post("/skopos/report", json=_doc(PORT), headers={"x-momus-operator": "s3cret"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["imported"] == 1 and body["new"] == 1
    fid = body["findings"][0]["finding_id"]
    # The corpus, not a local variable that goes out of scope when the handler returns.
    assert runtime.findings_db.get(fid)
    # And reachable by the deploy gate and the remediation door, which both go through _recall.
    assert runtime._recall(fid)


def test_an_imported_finding_is_visible_to_the_autopilot(wired):
    """The autopilot reads GET /findings. A finding it cannot see is one it cannot dispatch."""
    _, client = wired
    client.post("/skopos/report", json=_doc(PORT), headers={"x-momus-operator": "s3cret"})
    rows = client.get("/findings").json()["findings"]
    assert any(f.get("probe") == "skopos:ports" for f in rows)


def test_rescanning_the_same_defect_bumps_the_sighting_count(wired):
    """`seen_count` IS the dispatch evidence: a defect that survives N scans reproduced N times.

    It must come from N separate pushes, not from one push repeated — which is why the SKOPOS
    side sends one push per snapshot.
    """
    _, client = wired
    first = client.post("/skopos/report", json=_doc(PORT),
                        headers={"x-momus-operator": "s3cret"}).json()
    second = client.post("/skopos/report", json=_doc(PORT),
                         headers={"x-momus-operator": "s3cret"}).json()
    assert first["new"] == 1 and second["new"] == 0
    assert second["findings"][0]["seen_count"] == 2
    # A rediscovery keeps the FIRST id — handing back a fresh one gives SKOPOS an id
    # /remediate cannot resolve.
    assert second["findings"][0]["finding_id"] == first["findings"][0]["finding_id"]


def test_a_stranger_cannot_invent_findings(tmp_path, monkeypatch):
    """The route writes into the queue that opens remediation tickets.

    Gated like every other control route — `MOMUS_REQUIRE_OPERATOR`, which production sets by
    default. Without it an anonymous caller could file findings against any host MOMUS knows,
    and the loop would eventually try to fix them.
    """
    from fastapi.testclient import TestClient

    from momus.app import build_app
    from momus.capabilities import MomusRuntime
    from momus.config import MomusConfig

    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_SIGNING_KEY_PATH", str(tmp_path / "scanner.key"))
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "offline")
    monkeypatch.setenv("MOMUS_OPERATOR_TOKEN", "s3cret")
    monkeypatch.setenv("MOMUS_REQUIRE_OPERATOR", "1")
    client = TestClient(build_app(MomusRuntime(MomusConfig.from_env())))
    assert client.post("/skopos/report", json=_doc(PORT)).status_code in (401, 403)
    assert client.post("/skopos/report", json=_doc(PORT),
                       headers={"x-momus-operator": "s3cret"}).status_code == 200


# ── what the loop may and may not try to fix ────────────────────────────────────
PACKAGES = {
    "severity": "critical",
    "category": "packages",
    "title": "next 15.5.4 has a published RCE",
    "detail": "CVE-2025-XXXX affects <15.5.9",
    "recommendation": "Upgrade and redeploy.",
}


def test_a_machine_defect_escalates_to_a_person():
    """A patch cannot close it, so dispatching it buys a rejected patch and a spent agent run.

    "Postgres is bound to 0.0.0.0 on this host" is a property of the machine. The fixer edits a
    repository; nothing it can write changes that. The finding still becomes a signed, routed
    ticket — it just goes to someone with a shell.
    """
    [finding] = import_findings(_doc(PORT))
    assert escalation_for(finding.target, finding.target_kind, finding.category) == "human-governance"


def test_a_vulnerable_dependency_is_the_loop_s_own_work():
    """A CVE in a lockfile IS a line in a repo — fix, retest, redeploy is exactly this path."""
    [finding] = import_findings(_doc(PACKAGES))
    assert finding.category == "supply-chain"
    assert escalation_for(finding.target, finding.target_kind, finding.category) == "auto"


def test_the_ticket_carries_the_route_it_was_given(wired):
    """The rule has to bind where the ticket is minted, not only where it is asserted."""
    from momus.engine.remediation import open_ticket

    runtime, _ = wired
    [finding] = import_findings(_doc(PORT))
    assert open_ticket(finding, runtime.signer).route == "human-governance"
    [dep] = import_findings(_doc(PACKAGES))
    assert open_ticket(dep, runtime.signer).route == "auto"
