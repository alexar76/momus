"""MOMUS's persistent vulnerability corpus — findings must survive a restart, and a rediscovery
must bump a counter rather than duplicating the bug."""

from __future__ import annotations

from momus.findings import Evidence, Finding, Outcome, Status, Verdict, finding_digest
from momus.store import FindingStore


def _finding(scanner, *, target="oracles", probe="free_tier_ceiling_bypass", severity="high",
             resp="sha256-b"):
    f = Finding(target=target, target_kind="oracle", probe=probe, category="authz",
                severity=severity, outcome=Outcome.FINDING.value, title="t", detail="d",
                evidence=Evidence("sha256-a", resp), status=Status.RAW.value)
    return scanner.sign_finding(f)


def test_defaults_to_sqlite(tmp_path, monkeypatch):
    monkeypatch.delenv("MOMUS_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    db = FindingStore(str(tmp_path))
    assert db.backend == "sqlite"
    assert (tmp_path / "findings.db").exists()


def test_record_and_read_back(tmp_path, scanner):
    db = FindingStore(str(tmp_path))
    f = _finding(scanner)
    res = db.record_finding(f, scan_id="scan-1")
    assert res["new"] is True and res["seen_count"] == 1
    got = db.get(f.finding_id)
    assert got and got["title"] == "t" and got["signature"]["value"]


def test_survives_restart(tmp_path, scanner):
    f = _finding(scanner)
    FindingStore(str(tmp_path)).record_finding(f)
    # a brand-new store object = a fresh process
    again = FindingStore(str(tmp_path))
    assert again.get(f.finding_id) is not None
    assert again.stats()["total_findings"] == 1


def test_rediscovery_bumps_seen_count_not_duplicate(tmp_path, scanner):
    db = FindingStore(str(tmp_path))
    f1 = _finding(scanner)
    f2 = _finding(scanner)  # same bug (same target+probe+category+response digest), new report id
    assert f1.dedup_key == f2.dedup_key
    assert db.record_finding(f1)["new"] is True
    second = db.record_finding(f2)
    assert second["new"] is False and second["seen_count"] == 2
    assert db.stats()["total_findings"] == 1        # one BUG, not two rows
    assert db.stats()["recurring"] == 1
    assert db.seen_before(f1.dedup_key) == 2


def test_distinct_bugs_are_separate_rows(tmp_path, scanner):
    db = FindingStore(str(tmp_path))
    db.record_finding(_finding(scanner, probe="free_tier_ceiling_bypass"))
    db.record_finding(_finding(scanner, probe="manifest_signature_integrity", resp="sha256-zzz"))
    assert db.stats()["total_findings"] == 2


def test_query_filters(tmp_path, scanner):
    db = FindingStore(str(tmp_path))
    db.record_finding(_finding(scanner, severity="high"))
    db.record_finding(_finding(scanner, severity="low", probe="p2", resp="sha256-c"))
    db.record_finding(_finding(scanner, target="gaia", severity="medium", probe="p3", resp="sha256-d"))
    assert len(db.recent(50, severity="high")) == 1
    assert len(db.recent(50, severity="low")) == 1
    assert len(db.recent(50, target="gaia")) == 1
    assert len(db.recent(50)) == 3


def test_status_update(tmp_path, scanner):
    db = FindingStore(str(tmp_path))
    f = _finding(scanner)
    db.record_finding(f)
    db.set_status(f.finding_id, "confirmed")
    assert db.stats()["by_status"].get("confirmed") == 1


def test_verdicts_recorded_idempotently(tmp_path, scanner, verifier_a):
    db = FindingStore(str(tmp_path))
    f = _finding(scanner)
    db.record_finding(f)
    v = verifier_a.sign_verdict(Verdict(f.finding_id, finding_digest(f), "confirmed", "replay",
                                        0.95, "r", "va", subject_target=f.target, subject_probe=f.probe))
    db.record_verdict(v)
    db.record_verdict(v)  # same verdict twice → one row, no crash
    with db._conn() as con:
        n = con.cursor().execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
    assert n == 1


def test_stats_shape(tmp_path, scanner):
    db = FindingStore(str(tmp_path))
    db.record_finding(_finding(scanner))
    s = db.stats()
    assert s["backend"] == "sqlite" and s["total_findings"] == 1
    assert "by_severity" in s and "by_status" in s


def test_runtime_persists_findings_across_instances(tmp_path, monkeypatch, broken_oracle_transport):
    """End-to-end: a scan writes to the corpus, and a NEW runtime still sees the findings."""
    import asyncio
    from momus.capabilities import MomusRuntime
    from momus.config import MomusConfig
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("MOMUS_SIGNING_KEY_PATH", str(tmp_path / "k"))
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "offline")

    rt = MomusRuntime(MomusConfig.from_env())
    from momus.targets.oracle import OracleTarget
    tgt = OracleTarget("oracles", "http://broken.local", transport=broken_oracle_transport)
    report = asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        rt.scanner.scan([tgt]))
    rt._store(report)
    assert report.counts["findings"] >= 2

    rt2 = MomusRuntime(MomusConfig.from_env())          # fresh process
    assert rt2.corpus_stats()["total_findings"] >= 2
    assert len(rt2.recent_findings(50)) >= 2


class TestGetCarriesWhatTheCorpusKnows:
    """`doc` is the Finding as the scanner built it, so it cannot carry `seen_count` or
    `last_seen_at` — those are columns the table maintains across rediscoveries.

    Returning the document alone made both invisible to every caller that reads a finding by id.
    The remediation ticket then carried an empty `last_seen_at`, which silently disabled the
    conductor's regression rule: a real regression was answered with the old "already deployed"
    job and nothing ran at all.
    """

    def _finding(self, signer):
        from momus.findings import Evidence, Finding

        return Finding(target="canary", target_kind="oracle", probe="p", category="authz",
                       severity="high", outcome="finding", title="t", detail="d",
                       scanner_pubkey=signer.pubkey, evidence=Evidence(request_digest="a", response_digest="b"))

    def test_a_rediscovered_finding_reports_its_count_and_last_sighting(self, tmp_path):
        from momus.findings import FindingSigner
        from momus.store import FindingStore

        store = FindingStore(str(tmp_path / "corpus.db"))
        finding = self._finding(FindingSigner(str(tmp_path / "k")))
        store.record_finding(finding, scan_id="s1")
        store.record_finding(finding, scan_id="s2")

        got = store.get(finding.finding_id)
        assert got is not None
        assert got["seen_count"] == 2
        assert got["last_seen_at"] and got["last_seen_at"].endswith("Z")
        assert got["first_seen_at"] <= got["last_seen_at"]

    def test_it_agrees_with_the_listing(self, tmp_path):
        """`recent()` already merged them; the two shapes must not disagree about one finding."""
        from momus.findings import FindingSigner
        from momus.store import FindingStore

        store = FindingStore(str(tmp_path / "corpus.db"))
        finding = self._finding(FindingSigner(str(tmp_path / "k")))
        store.record_finding(finding, scan_id="s1")
        listed = store.recent(10)[0]
        got = store.get(finding.finding_id)
        for key in ("seen_count", "last_seen_at"):
            assert got[key] == listed[key], key
