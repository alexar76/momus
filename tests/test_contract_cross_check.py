"""A replay shares the probe's implementation, so it shares the probe's mistakes.

Two MOMUS instances re-running one probe prove the finding is not a flake and not a
fabrication by the reporting instance. They cannot prove the probe asks the right question:
the same code, run twice, is wrong the same way twice — confidently, and now with two
signatures on it.

`manifest_canonical` has eight independent implementations in this tree, and one of them has
already taken the whole federation down: the hub added a fifth field, the oracle copy did not
follow, and every oracle manifest failed verification. A probe holding the wrong copy would
reject every CORRECT signature, and a replay would confirm it.

So the verifier reads the contract a second way, from the protocol's own conformance
reference. These tests hold that second reading to its job: it must back a real finding, catch
a probe that is wrong about a healthy target, and refuse to decide when the two readings
disagree — which is itself the drift defect, not evidence for or against the target.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from momus.engine import cross_check as cc


# ── a stand-in for the two implementations ────────────────────────────────────────

def _reference_source() -> str:
    """A minimal module with the protocol's canonical form, loaded the way the real one is."""
    return (
        "import hashlib, json\n"
        "def digest(v):\n"
        "    return hashlib.sha256(json.dumps(v, sort_keys=True, ensure_ascii=False)"
        ".encode()).hexdigest()\n"
        "def manifest_canonical(m):\n"
        "    return (f\"capabilities_count:{m.get('capabilities_count', 0)}\"\n"
        "            f\"|generated_at:{m.get('generated_at', '')}\"\n"
        "            f\"|protocol_version:{m.get('protocol_version', 'v1')}\"\n"
        "            f\"|tools_hash:{digest(m.get('tools', []))}\"\n"
        "            f\"|by_hub_hash:{digest(m.get('by_hub', {}))}\")\n"
    )


@pytest.fixture
def reference(tmp_path, monkeypatch):
    path = tmp_path / "run.py"
    path.write_text(_reference_source())
    monkeypatch.setattr(cc, "REFERENCE_PATH", str(path))
    monkeypatch.setattr(cc, "_reference", None)
    monkeypatch.setattr(cc, "_reference_error", "")
    return path


MANIFEST = {
    "capabilities_count": 1,
    "generated_at": "2026-08-30T00:00:00Z",
    "protocol_version": "v2",
    "tools": [{"id": "t1", "price_per_call_usd": 0.01}],
    "signature": {"value": "sig", "public_key": "pk", "algorithm": "ed25519"},
}


def _same_canonical(m):
    import hashlib

    def d(v):
        return hashlib.sha256(json.dumps(v, sort_keys=True, ensure_ascii=False).encode()).hexdigest()

    return (f"capabilities_count:{m.get('capabilities_count', 0)}"
            f"|generated_at:{m.get('generated_at', '')}"
            f"|protocol_version:{m.get('protocol_version', 'v1')}"
            f"|tools_hash:{d(m.get('tools', []))}"
            f"|by_hub_hash:{d(m.get('by_hub', {}))}")


def _drifted_canonical(m):
    """The failure that actually happened: a copy that never grew the fifth field."""
    return _same_canonical(m).rsplit("|by_hub_hash:", 1)[0]


# ── both readings agree the signature is bad ──────────────────────────────────────

def test_two_implementations_rejecting_it_supports_the_finding(reference):
    check = cc.cross_check_manifest(MANIFEST, _same_canonical, lambda c, v, k: False)

    assert check.available
    assert check.canonical_agrees
    assert check.supports_the_finding
    assert not check.contradicts_the_finding
    assert "two independent implementations" in check.detail


# ── the reference says the target is fine ─────────────────────────────────────────

def test_a_probe_that_is_wrong_about_a_healthy_target_is_caught(reference):
    # The reference verifies the signature, so the defect is in the probe, not the oracle.
    check = cc.cross_check_manifest(MANIFEST, _same_canonical, lambda c, v, k: True)

    assert check.contradicts_the_finding
    assert not check.supports_the_finding
    assert "the probe is wrong, not the target" in check.detail


# ── the two readings disagree ─────────────────────────────────────────────────────

def test_drifted_implementations_make_the_verdict_untrustworthy(reference):
    # This is the real outage, reproduced: the hub gained by_hub_hash, a copy did not follow.
    check = cc.cross_check_manifest(MANIFEST, _drifted_canonical, lambda c, v, k: False)

    assert check.available
    assert check.canonical_agrees is False
    assert not check.supports_the_finding, "drift is not evidence about the target"
    assert "DISAGREE" in check.detail and "drifted" in check.detail


def test_drift_is_reported_even_when_both_happen_to_reject(reference):
    # Agreement on the ANSWER while disagreeing on the QUESTION is a coincidence, not proof.
    check = cc.cross_check_manifest(MANIFEST, _drifted_canonical, lambda c, v, k: False)
    assert check.probe_verifies is False and check.reference_verifies is False
    assert check.canonical_agrees is False
    assert not check.supports_the_finding


# ── degraded, and saying so ───────────────────────────────────────────────────────

def test_a_missing_reference_degrades_rather_than_lies(tmp_path, monkeypatch):
    monkeypatch.setattr(cc, "REFERENCE_PATH", str(tmp_path / "absent.py"))
    monkeypatch.setattr(cc, "_reference", None)
    monkeypatch.setattr(cc, "_reference_error", "")

    check = cc.cross_check_manifest(MANIFEST, _same_canonical, lambda c, v, k: False)

    assert check.available is False
    assert not check.supports_the_finding and not check.contradicts_the_finding
    assert "not found" in check.detail


def test_a_broken_reference_does_not_break_the_scan(tmp_path, monkeypatch):
    bad = tmp_path / "run.py"
    bad.write_text("this is not python(((\n")
    monkeypatch.setattr(cc, "REFERENCE_PATH", str(bad))
    monkeypatch.setattr(cc, "_reference", None)
    monkeypatch.setattr(cc, "_reference_error", "")

    check = cc.cross_check_manifest(MANIFEST, _same_canonical, lambda c, v, k: False)
    assert check.available is False
    assert "failed to load" in check.detail


def test_a_manifest_with_no_signature_is_not_cross_checkable(reference):
    check = cc.cross_check_manifest({"capabilities_count": 0}, _same_canonical,
                                    lambda c, v, k: False)
    assert check.available is False
    assert "no signature" in check.detail


def test_a_verifier_that_raises_is_reported_not_propagated(reference):
    def boom(c, v, k):
        raise ValueError("bad key")

    check = cc.cross_check_manifest(MANIFEST, _same_canonical, boom)
    assert check.available is True
    assert "verification raised" in check.detail
    assert not check.supports_the_finding


# ── the real reference must actually be the real reference ────────────────────────

def test_the_shipped_reference_is_the_protocols_own_and_not_a_copy_of_oracle_core():
    """If this ever becomes a copy of the implementation it checks, it stops being a check."""
    repo = pathlib.Path(__file__).resolve().parents[2]
    ref = repo / "aimarket-protocol" / "conformance" / "run.py"
    assert ref.is_file(), "the protocol conformance reference is what the image ships"

    text = ref.read_text()
    assert "def manifest_canonical" in text
    assert "oracle_core" not in text, "the reference must not import the thing it verifies"


def test_the_two_implementations_agree_today():
    """A parity check, so drift is caught here and not in production.

    Not a claim that they can never diverge — that is exactly what the cross-check exists to
    notice at runtime — but if they diverge, this test should say so first.
    """
    import importlib.util
    import pathlib as _p

    repo = _p.Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        "_ref", repo / "aimarket-protocol" / "conformance" / "run.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    from oracle_core.signing import Signer

    canon = Signer.__new__(Signer)
    manifest = {k: v for k, v in MANIFEST.items() if k != "signature"}
    assert Signer.manifest_canonical(canon, manifest) == module.manifest_canonical(manifest)
