"""The settlement ladder — UNI by default, and crypto-on alone must NEVER start paying bounties."""

from __future__ import annotations

import pytest

from momus.economics import BountyLedger, KeyRing, PayoutGate, PayoutState
from momus.findings import Evidence, Finding, Outcome, Status, Verdict, finding_digest
from momus.settlement import SettlementBackend, SettlementMode, resolve_mode


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("MOMUS_SETTLEMENT", "MOMUS_BOUNTY_ONCHAIN", "MOMUS_BOUNTY_CHAIN",
              "MOMUS_BOUNTY_SPLITTER", "AIFACTORY_CRYPTO_ENABLED"):
        monkeypatch.delenv(k, raising=False)


def test_default_is_uni_simulation():
    mode, reason = resolve_mode()
    assert mode is SettlementMode.UNI
    assert "no value moves" in reason


def test_crypto_alone_does_not_enable_onchain(monkeypatch):
    """The whole point of the second switch: crypto ON is NOT enough to pay a bounty on chain."""
    monkeypatch.setenv("AIFACTORY_CRYPTO_ENABLED", "1")
    monkeypatch.setenv("MOMUS_SETTLEMENT", "base")
    # MOMUS_BOUNTY_ONCHAIN deliberately absent
    mode, reason = resolve_mode()
    assert mode is SettlementMode.HELD
    assert "own opt-in" in reason


def test_onchain_needs_splitter_address(monkeypatch):
    monkeypatch.setenv("AIFACTORY_CRYPTO_ENABLED", "1")
    monkeypatch.setenv("MOMUS_BOUNTY_ONCHAIN", "1")
    monkeypatch.setenv("MOMUS_SETTLEMENT", "base")
    mode, reason = resolve_mode()
    assert mode is SettlementMode.HELD and "SPLITTER" in reason


def test_full_ladder_reaches_base(monkeypatch):
    monkeypatch.setenv("AIFACTORY_CRYPTO_ENABLED", "1")
    monkeypatch.setenv("MOMUS_BOUNTY_ONCHAIN", "1")
    monkeypatch.setenv("MOMUS_SETTLEMENT", "base")
    monkeypatch.setenv("MOMUS_BOUNTY_SPLITTER", "0x" + "ab" * 20)
    mode, _ = resolve_mode()
    assert mode is SettlementMode.BASE


def test_onchain_requested_without_crypto_fails_closed(monkeypatch):
    monkeypatch.setenv("MOMUS_SETTLEMENT", "base")
    monkeypatch.setenv("MOMUS_BOUNTY_ONCHAIN", "1")
    monkeypatch.setenv("MOMUS_BOUNTY_SPLITTER", "0x" + "ab" * 20)
    mode, reason = resolve_mode()  # crypto master switch off
    assert mode is SettlementMode.HELD and "CRYPTO_ENABLED is off" in reason


def test_uni_settles_and_records(tmp_path):
    b = SettlementBackend(SettlementMode.UNI, "uni", uni_ledger_path=str(tmp_path / "uni.jsonl"))
    d = b.settle_share(finding_id="mom-1", role="finder", recipient="k", amount_usd=25.0)
    assert d.settled and d.simulated and d.reference.startswith("uni-")
    assert (tmp_path / "uni.jsonl").read_text().count("uni_settlement") == 1
    assert b.settles_value is False  # UNI never moves real value


def test_base_prepares_unsigned_call_never_broadcasts():
    b = SettlementBackend(SettlementMode.BASE, "base", splitter="0x" + "cd" * 20)
    d = b.settle_share(finding_id="mom-1", role="fixer", recipient="0xrecipient", amount_usd=17.5)
    assert d.settled is False          # nothing settled until an operator signs
    assert d.prepared_call["function"].startswith("releaseShare")
    assert d.prepared_call["args"]["amount"] == 17_500_000   # 6-decimal USDC
    assert "UNSIGNED" in d.prepared_call["note"]


# ── integration with the payout gate ────────────────────────────────────────
def _finding(scanner, severity="high"):
    f = Finding(target="oracles", target_kind="oracle", probe="p", category="authz", severity=severity,
                outcome=Outcome.FINDING.value, title="t", detail="d",
                evidence=Evidence("sha256-a", "sha256-b"), status=Status.RAW.value)
    return scanner.sign_finding(f)


def _confirm(vs, f):
    return vs.sign_verdict(Verdict(f.finding_id, finding_digest(f), "confirmed", "replay", 0.95, "r", vs.pubkey[:6]))


def test_gate_in_uni_pays_but_simulated(tmp_path, scanner, verifier_a, verifier_b):
    kr = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    backend = SettlementBackend(SettlementMode.UNI, "uni", uni_ledger_path=str(tmp_path / "uni.jsonl"))
    gate = PayoutGate(kr, BountyLedger(str(tmp_path / "l.jsonl")), crypto_enabled=False, prod=False,
                      cooldown_s=0, external_verifiers={verifier_a.pubkey}, settlement=backend)
    f = _finding(scanner, "high")
    dec = gate.authorize(f, [_confirm(verifier_a, f), _confirm(verifier_b, f)], deposit_posted_usd=25)
    assert dec.state == PayoutState.PAID.value          # the loop completes in UNI…
    assert dec.settlement["simulated"] is True           # …but no value moved
    assert dec.settlement["mode"] == "uni"


def test_gate_in_base_holds_until_operator_signs(tmp_path, scanner, verifier_a, verifier_b):
    kr = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    backend = SettlementBackend(SettlementMode.BASE, "base", splitter="0x" + "cd" * 20)
    gate = PayoutGate(kr, BountyLedger(str(tmp_path / "l.jsonl")), crypto_enabled=True, prod=False,
                      cooldown_s=0, external_verifiers={verifier_a.pubkey}, settlement=backend)
    f = _finding(scanner, "high")
    dec = gate.authorize(f, [_confirm(verifier_a, f), _confirm(verifier_b, f)], deposit_posted_usd=25)
    assert dec.state == PayoutState.HELD.value           # MOMUS never broadcasts its own payout
    assert dec.settlement["prepared_call"]["contract"].startswith("0x")


def test_split_carries_settlement_per_share(tmp_path, scanner, verifier_a, verifier_b):
    import json
    kr = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    backend = SettlementBackend(SettlementMode.UNI, "uni", uni_ledger_path=str(tmp_path / "uni.jsonl"))
    gate = PayoutGate(kr, BountyLedger(str(tmp_path / "l.jsonl")), crypto_enabled=False, prod=False,
                      cooldown_s=0, external_verifiers={verifier_a.pubkey}, settlement=backend)
    f = _finding(scanner, "high")
    fixv = {"finding_id": f.finding_id, "fixed": True, "outcome": "no_finding"}
    fixv["signature"] = scanner._signer.sign_payload(
        json.dumps({k: v for k, v in fixv.items() if k != "signature"}, sort_keys=True,
                   separators=(",", ":"), ensure_ascii=False))
    out = gate.authorize_split(
        f, [_confirm(verifier_a, f), _confirm(verifier_b, f)],
        participants={"finder": scanner.pubkey, "fixer": "factory-1", "conductor": "skopos-1"},
        deposit_posted_usd=25, fix_verdict=fixv, deploy_ack={"accepted": True},
        momus_pubkey=scanner.pubkey)
    assert out["settlement"]["mode"] == "uni" and out["settlement"]["moves_real_value"] is False
    assert all(s["settlement"]["simulated"] for s in out["shares"] if s["state"] == "paid")
    assert out["total_released_usd"] == 50.0
