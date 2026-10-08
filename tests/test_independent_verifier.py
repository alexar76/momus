"""The loop shipped patches with no independent judge, and nobody had decided that.

`momus.engine.verify.Verifier` was written, documented, and never instantiated. Nothing in
production wrote a confirmed verdict, so the dispatch policy's `finding["verdicts"]` branch
could not fire and "the same probe fired twice" became the whole gate — not a decision, just
what was left when the judge is missing. The projection did not carry verdicts either, so even
a written one would have been invisible.

These tests hold three things: the verifier is only built when it is genuinely independent,
it is shown the evidence it is asked to judge, and its absence leaves the loop exactly where
it was rather than somewhere worse.
"""

from __future__ import annotations

import pytest

from momus.engine.verify import _finding_to_verify_input
from momus.findings import Evidence, Finding


def _finding(**over) -> Finding:
    base = dict(
        finding_id="mom-test-0001",
        target="canary",
        target_kind="oracle",
        probe="manifest_signature_integrity",
        category="integrity",
        severity="high",
        outcome="finding",
        title="manifest signature does not verify",
        detail="The published manifest carries a signature that fails verification.",
        evidence=Evidence(
            request_digest="sha256-req",
            response_digest="sha256-resp",
            request_snippet="GET /manifest",
            response_snippet="Sign over manifest_canonical(manifest) — IMPORT it, do not reimplement",
            status_code=200,
            reproducer="curl -s http://canary:9450/manifest",
        ),
        scanner_pubkey="pk-scanner",
    )
    base.update(over)
    return Finding(**base)


# ── the verifier must be shown the evidence ───────────────────────────────────────

def test_the_response_snippet_reaches_the_verifier():
    # It is the acceptance criterion the rest of the loop treats as load-bearing, and it was
    # the one field the prompt dropped. A verifier asked about a response it was not shown
    # is not verifying; it is agreeing.
    text = _finding_to_verify_input(_finding())
    assert "IMPORT it, do not reimplement" in text
    assert "acceptance criterion" in text


def test_both_digests_reach_the_verifier():
    text = _finding_to_verify_input(_finding())
    assert "sha256-req" in text
    assert "sha256-resp" in text


def test_the_request_snippet_reaches_the_verifier():
    assert "GET /manifest" in _finding_to_verify_input(_finding())


def test_a_finding_with_no_response_says_there_is_nothing_to_judge():
    # Silence here is what produced confident verdicts about nothing.
    bare = _finding(evidence=Evidence(request_digest="d1", response_digest="d2"))
    text = _finding_to_verify_input(bare)
    assert "no response snippet" in text
    assert "inconclusive" in text


def test_the_verifier_is_told_to_judge_the_evidence_not_the_claim():
    text = _finding_to_verify_input(_finding())
    assert "not the claim" in text
    assert "false 'confirmed' costs more than a miss" in text


def test_a_pathological_snippet_is_bounded():
    huge = _finding(evidence=Evidence(
        request_digest="d1", response_digest="d2", response_snippet="x" * 50_000))
    text = _finding_to_verify_input(huge)
    assert len(text) < 10_000


# ── the verifier must actually be independent ─────────────────────────────────────

def test_no_metis_url_means_no_verifier_and_an_unchanged_loop(tmp_path, monkeypatch):
    from momus.capabilities import MomusRuntime
    from momus.config import MomusConfig

    cfg = MomusConfig(
        data_dir=str(tmp_path),
        signing_key_path=str(tmp_path / "scanner.key"),
        verifier_key_path=str(tmp_path / "verifier.key"),
        verifier_metis_url="",
    )
    runtime = MomusRuntime(cfg)
    assert runtime.verifier is None, "no endpoint configured means no verdicts, not a fake one"


def test_a_verifier_signing_with_the_scanner_key_is_refused(tmp_path, caplog):
    import logging

    from momus.capabilities import MomusRuntime
    from momus.config import MomusConfig

    shared = str(tmp_path / "one.key")
    cfg = MomusConfig(
        data_dir=str(tmp_path),
        signing_key_path=shared,
        verifier_key_path=shared,          # the misconfiguration this guard exists for
        verifier_metis_url="http://metis.invalid/v1",
    )
    with caplog.at_level(logging.ERROR):
        runtime = MomusRuntime(cfg)

    assert runtime.verifier is None, "a scanner signing its own verdicts is not evidence"
    assert "verifier key is the scanner key" in caplog.text


def test_a_distinct_key_yields_a_working_verifier(tmp_path):
    from momus.capabilities import MomusRuntime
    from momus.config import MomusConfig

    cfg = MomusConfig(
        data_dir=str(tmp_path),
        signing_key_path=str(tmp_path / "scanner.key"),
        verifier_key_path=str(tmp_path / "verifier.key"),
        verifier_metis_url="http://metis.invalid/v1",
    )
    runtime = MomusRuntime(cfg)

    assert runtime.verifier is not None
    assert runtime.verifier.pubkey != runtime.signer.pubkey


# ── verdicts must be visible once written ─────────────────────────────────────────

def test_verdicts_are_projected_so_the_dispatch_branch_can_fire(tmp_path):
    # The autopilot has always preferred `finding["verdicts"]` with a confirmed entry over a
    # sighting count. The projection never carried them, so the branch was unreachable.
    from momus.findings import FindingSigner, Verdict, finding_digest
    from momus.store import FindingStore

    store = FindingStore(str(tmp_path))
    finding = _finding()
    store.record_finding(finding, scan_id="scan-1")

    verifier = FindingSigner(str(tmp_path / "verifier.key"))
    store.record_verdict(verifier.sign_verdict(Verdict(
        finding_id=finding.finding_id,
        finding_digest=finding_digest(finding),
        verdict="confirmed", method="metis:/v1/verify", score=0.91,
        rationale="reproduced against the response snippet", verifier_id="v1", subject_target=finding.target, subject_probe=finding.probe)))

    page = store.recent(limit=10)
    row = next(f for f in page if f["finding_id"] == finding.finding_id)
    assert row["verdicts"], "recent() must carry the verdicts"
    assert row["verdicts"][0]["verdict"] == "confirmed"

    one = store.get(finding.finding_id)
    assert one["verdicts"], "get() must agree with recent()"


def test_a_finding_with_no_verdicts_reads_as_an_empty_list_not_a_missing_key(tmp_path):
    # The dispatch policy does `finding.get("verdicts") or []`; an absent key and an empty
    # list must mean the same thing, so that "not yet judged" never reads as an error.
    from momus.store import FindingStore

    store = FindingStore(str(tmp_path))
    finding = _finding()
    store.record_finding(finding, scan_id="scan-1")

    row = store.recent(limit=10)[0]
    assert row["verdicts"] == []


def test_verdicts_from_two_verifiers_are_both_kept(tmp_path):
    # HIGH severity needs two distinct verifiers in the payout gate; the store must not
    # collapse them.
    from momus.findings import FindingSigner, Verdict, finding_digest
    from momus.store import FindingStore

    store = FindingStore(str(tmp_path))
    finding = _finding()
    store.record_finding(finding, scan_id="scan-1")

    for name in ("a", "b"):
        signer = FindingSigner(str(tmp_path / f"{name}.key"))
        store.record_verdict(signer.sign_verdict(Verdict(
            finding_id=finding.finding_id, finding_digest=finding_digest(finding),
            verdict="confirmed", method="metis:/v1/verify", score=0.9,
            rationale="r", verifier_id=name, subject_target=finding.target, subject_probe=finding.probe)))

    assert len(store.get(finding.finding_id)["verdicts"]) == 2


# ── the judge must be read by what it SAYS ────────────────────────────────────────
#
# `data["verified"]` is Metis reporting that its own answer passed its own delivery critic.
# It is not a statement about the finding. Reading it as one made every well-formed reply a
# "confirmed" — including a reply whose text said the finding does not reproduce. A rubber
# stamp is worse than no judge, because the dispatch policy trusts it.

from momus.engine.verify import Verifier, _stated_verdict  # noqa: E402
from momus.findings import FindingSigner  # noqa: E402


def _verifier(tmp_path) -> Verifier:
    return Verifier(FindingSigner(str(tmp_path / "v.key")), verifier_id="test")


def _read(v: Verifier, data: dict):
    """Drive only the envelope-reading half, with no network."""
    import momus.engine.verify as mod

    score = mod._read_score(data)
    well_formed = bool(data.get("verified"))
    stated = _stated_verdict(data)
    if stated == "reproduces":
        conf = max(score, 0.6) if well_formed else min(max(score, 0.5), 0.6)
        return v._verdict(_finding(), "confirmed", "metis:/v1/verify", conf, "")
    if stated == "does_not_reproduce":
        return v._verdict(_finding(), "refuted", "metis:/v1/verify", max(score, 0.6), "")
    return v._verdict(_finding(), "inconclusive", "metis:/v1/verify", 0.0, "")


def test_a_wellformed_answer_saying_NO_is_not_a_confirmation(tmp_path):
    # The exact rubber stamp. Metis is happy with its own prose; its prose says no.
    data = {"verified": True, "verify_score": 0.95,
            "answer": "VERDICT: does_not_reproduce\nThe signature verifies against the manifest."}
    assert _read(_verifier(tmp_path), data).verdict == "refuted"


def test_a_wellformed_answer_with_no_verdict_line_is_inconclusive(tmp_path):
    # It answered something, but not the question it was asked.
    data = {"verified": True, "verify_score": 0.99,
            "answer": "The manifest looks plausible and the oracle appears healthy."}
    assert _read(_verifier(tmp_path), data).verdict == "inconclusive"


def test_an_explicit_yes_is_a_confirmation(tmp_path):
    data = {"verified": True, "verify_score": 0.9,
            "answer": "VERDICT: reproduces\nThe signature was computed over json.dumps."}
    v = _read(_verifier(tmp_path), data)
    assert v.verdict == "confirmed"
    assert v.score >= 0.6


def test_an_unclear_label_is_inconclusive_not_a_guess(tmp_path):
    data = {"verified": True, "answer": "VERDICT: unclear\nNo response body was supplied."}
    assert _read(_verifier(tmp_path), data).verdict == "inconclusive"


def test_a_confident_judgement_delivered_badly_carries_a_lower_score(tmp_path):
    # The critic's opinion of the ANSWER is a secondary gate, never the verdict itself.
    good = _read(_verifier(tmp_path), {"verified": True, "verify_score": 0.95,
                                       "answer": "VERDICT: reproduces\nx"})
    poor = _read(_verifier(tmp_path), {"verified": False, "verify_score": 0.95,
                                       "answer": "VERDICT: reproduces\nx"})
    assert good.score > poor.score
    assert poor.verdict == "confirmed", "a badly delivered judgement is still a judgement"


# ── parsing the label ─────────────────────────────────────────────────────────────

def test_the_label_is_found_at_the_start_of_a_line():
    assert _stated_verdict({"answer": "VERDICT: reproduces"}) == "reproduces"
    assert _stated_verdict({"answer": "intro\n  VERDICT: unclear  \nmore"}) == "unclear"
    assert _stated_verdict({"answer": "verdict: does_not_reproduce"}) == "does_not_reproduce"


def test_a_verdict_quoted_inside_prose_is_not_the_answer():
    # "the probe claims VERDICT: reproduces" is a description, not a judgement.
    assert _stated_verdict({"answer": "The probe claims VERDICT: reproduces here."}) == ""


def test_the_label_is_read_from_whichever_field_carries_the_text():
    for key in ("answer", "content", "output", "text"):
        assert _stated_verdict({key: "VERDICT: reproduces"}) == "reproduces"


def test_a_missing_or_odd_envelope_yields_no_label():
    assert _stated_verdict(None) == ""
    assert _stated_verdict({}) == ""
    assert _stated_verdict({"answer": ""}) == ""
    assert _stated_verdict({"answer": 42}) == ""


def test_the_prompt_asks_for_the_label_it_parses():
    # A parser and a prompt that disagree produce "inconclusive" for ever, silently.
    text = _finding_to_verify_input(_finding())
    for label in ("reproduces", "does_not_reproduce", "unclear"):
        assert f"VERDICT: {label}" in text


# ── a verdict must be filed against the BUG, not this sighting of it ──────────────

def test_a_rediscovery_files_its_verdict_under_the_canonical_id(tmp_path):
    """Three real verdicts once sat in the table under ids no reader ever looks up.

    A rediscovery mints a fresh `finding_id` for the observation; the corpus keeps the first
    one as the bug's identity. File the verdict under the fresh id and every projection
    honestly reports "no verdicts", which is exactly what a broken judge looks like.
    """
    from momus.store import FindingStore

    store = FindingStore(str(tmp_path))
    first = _finding(finding_id="mom-first")
    res1 = store.record_finding(first, scan_id="scan-1")
    assert res1["new"] is True

    # The same bug, seen again — same dedup key, new observation id.
    again = _finding(finding_id="mom-second-sighting")
    res2 = store.record_finding(again, scan_id="scan-2")

    assert res2["new"] is False
    assert res2["finding_id"] == "mom-first", "the corpus keeps the first id as the identity"


def test_the_verdict_carries_the_bug_id_and_the_sighting_digest(tmp_path):
    # Two fields, two different true statements: which bug, and which observation was judged.
    from momus.engine.verify import Verifier
    from momus.findings import FindingSigner, finding_digest

    v = Verifier(FindingSigner(str(tmp_path / "v.key")), verifier_id="test")
    sighting = _finding(finding_id="mom-fresh-sighting")

    verdict = v._verdict(sighting, "confirmed", "metis:/v1/verify", 0.9, "r",
                         finding_id="mom-canonical")

    assert verdict.finding_id == "mom-canonical"
    assert verdict.finding_digest == finding_digest(sighting)


def test_without_an_override_the_verdict_keeps_the_findings_own_id(tmp_path):
    from momus.engine.verify import Verifier
    from momus.findings import FindingSigner

    v = Verifier(FindingSigner(str(tmp_path / "v.key")), verifier_id="test")
    verdict = v._verdict(_finding(finding_id="mom-only"), "confirmed", "m", 0.9, "r")
    assert verdict.finding_id == "mom-only"


# ── the model must not judge what it cannot test ──────────────────────────────────
#
# Measured on the live canary: the manifest signature genuinely does NOT verify, and the
# judge returned "does_not_reproduce" at 0.92 confidence. Asking a language model whether a
# signature verifies, from a description of the response, is asking for an opinion about a
# fact. A false refutation is harmless while only CONFIRMED moves the bar; a false
# confirmation would not be.

import pytest as _pytest  # noqa: E402

from momus.engine.verify import _model_can_judge  # noqa: E402


@_pytest.mark.parametrize("category", ["integrity", "settlement", "replay", "authz"])
def test_a_deterministic_probe_is_out_of_the_models_scope(category):
    assert _model_can_judge(_finding(category=category)) is False


@_pytest.mark.parametrize("category", ["injection", "harmful-output", "plausibility", ""])
def test_a_judgement_probe_is_in_scope(category):
    assert _model_can_judge(_finding(category=category)) is True


def test_the_category_check_is_case_insensitive():
    assert _model_can_judge(_finding(category="INTEGRITY")) is False


@_pytest.mark.asyncio
async def test_a_deterministic_finding_is_never_confirmed_or_refuted_by_the_model(tmp_path):
    # No network call is made at all: the refusal happens before the request is built, so
    # this also proves we are not paying for a judgement we would then discard.
    from momus.engine.verify import Verifier
    from momus.findings import FindingSigner

    v = Verifier(FindingSigner(str(tmp_path / "v.key")), verifier_id="test")
    verdict = await v.verify_via_metis(
        _finding(category="integrity"), "http://metis.invalid", api_key="k")

    assert verdict.verdict == "inconclusive"
    assert verdict.score == 0.0
    assert "deterministic contract probe" in verdict.rationale
    assert "out of scope" in verdict.method


@_pytest.mark.asyncio
async def test_the_reason_names_the_right_instrument(tmp_path):
    from momus.engine.verify import Verifier
    from momus.findings import FindingSigner

    v = Verifier(FindingSigner(str(tmp_path / "v.key")), verifier_id="test")
    verdict = await v.verify_via_metis(_finding(category="integrity"), "http://metis.invalid")
    assert "replay" in verdict.rationale and "second principal" in verdict.rationale


# ── the replay verifier: run the probe, do not opine about it ─────────────────────

def test_a_replay_subject_carries_no_evidence(tmp_path):
    """A peer asked to re-run a probe is not handed the finding document.

    It does not need it — it produces its own observation — and shipping it would give a
    peer the evidence the coordinated-disclosure rule withholds from that tier.
    """
    from dataclasses import fields

    from momus.engine.verify import ReplaySubject

    names = {f.name for f in fields(ReplaySubject)}
    assert names == {"finding_id", "finding_digest", "target", "probe", "category", "severity"}
    assert "evidence" not in names and "detail" not in names


def test_a_reproducing_replay_confirms_with_the_digest_it_was_asked_about(tmp_path):
    from momus.engine.verify import ReplaySubject, Verifier
    from momus.findings import FindingSigner

    v = Verifier(FindingSigner(str(tmp_path / "v.key")), verifier_id="peer")
    subject = ReplaySubject(finding_id="mom-canonical", finding_digest="sha256-observed",
                            target="canary", probe="manifest_signature_integrity")

    verdict = v.verify_via_replay(subject, reproduced=True, finding_id="mom-canonical")

    assert verdict.verdict == "confirmed"
    assert verdict.method == "replay"
    assert verdict.finding_id == "mom-canonical"
    assert verdict.finding_digest == "sha256-observed", "the digest it was asked about, not a new one"
    assert verdict.score >= 0.9


def test_a_non_reproducing_replay_refutes(tmp_path):
    from momus.engine.verify import ReplaySubject, Verifier
    from momus.findings import FindingSigner

    v = Verifier(FindingSigner(str(tmp_path / "v.key")), verifier_id="peer")
    subject = ReplaySubject(finding_id="mom-1", finding_digest="d", target="canary", probe="p")
    assert v.verify_via_replay(subject, reproduced=False).verdict == "refuted"


def test_a_replay_verdict_is_signed_by_the_peer_not_the_scanner(tmp_path):
    from momus.engine.verify import ReplaySubject, Verifier
    from momus.findings import FindingSigner

    scanner = FindingSigner(str(tmp_path / "scanner.key"))
    peer = FindingSigner(str(tmp_path / "peer.key"))
    v = Verifier(peer, verifier_id="peer")

    verdict = v.verify_via_replay(
        ReplaySubject(finding_id="m", finding_digest="d", target="t", probe="p"),
        reproduced=True)

    assert verdict.verifier_pubkey == peer.pubkey
    assert verdict.verifier_pubkey != scanner.pubkey


@_pytest.mark.asyncio
async def test_no_replay_peer_means_no_verdict_rather_than_a_fabricated_one(tmp_path):
    # No verdict at all is the honest state for a finding nobody independent has looked at,
    # and it is the state the loop was already in.
    from momus.capabilities import MomusRuntime
    from momus.config import MomusConfig

    cfg = MomusConfig(
        data_dir=str(tmp_path),
        signing_key_path=str(tmp_path / "scanner.key"),
        verifier_key_path=str(tmp_path / "verifier.key"),
        verifier_metis_url="http://metis.invalid/v1",
        replay_verifier_url="",
    )
    runtime = MomusRuntime(cfg)
    assert await runtime._replay_verdict(_finding(), "mom-1") is None


@_pytest.mark.asyncio
async def test_a_peer_signing_with_our_own_key_is_discarded(tmp_path, monkeypatch, caplog):
    """The peer is this instance behind another URL, or a config that copied the key.

    Either way it is not a second opinion, and a verdict that only looks independent is
    exactly the thing the payout gate compares public keys to prevent.
    """
    import logging

    from momus.capabilities import MomusRuntime
    from momus.config import MomusConfig

    cfg = MomusConfig(
        data_dir=str(tmp_path),
        signing_key_path=str(tmp_path / "scanner.key"),
        verifier_key_path=str(tmp_path / "verifier.key"),
        verifier_metis_url="http://metis.invalid/v1",
        replay_verifier_url="http://peer.invalid",
    )
    runtime = MomusRuntime(cfg)

    class _Resp:
        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def json():
            return {"finding_id": "mom-1", "verdict": "confirmed", "method": "replay",
                    "score": 0.95, "verifier_id": "peer",
                    "verifier_pubkey": runtime.signer.pubkey}

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            return _Resp()

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    with caplog.at_level(logging.ERROR):
        assert await runtime._replay_verdict(_finding(), "mom-1") is None
    assert "not independent" in caplog.text
