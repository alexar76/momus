"""The payout gate — the most important tests in the project. No single key both declares a
finding valid AND releases its payout, and every anti-abuse control actually bites."""

from __future__ import annotations

import pytest

from momus.economics import (
    BountyLedger,
    KeyRing,
    PayoutGate,
    PayoutState,
    is_valid_ed25519_pubkey,
    terms_for,
)
from momus.findings import (
    Evidence,
    Finding,
    FindingSigner,
    Outcome,
    Status,
    Verdict,
    finding_digest,
)


def _finding(scanner, severity="high", target="oracles", kind="oracle"):
    f = Finding(target=target, target_kind=kind, probe="p", category="authz", severity=severity,
                outcome=Outcome.FINDING.value, title="t", detail="d",
                evidence=Evidence("sha256-a", "sha256-b"), status=Status.RAW.value)
    return scanner.sign_finding(f)


def _confirm(vs, f):
    return vs.sign_verdict(Verdict(f.finding_id, finding_digest(f), "confirmed", "replay", 0.95, "r", vs.pubkey[:6]))


def _refute(vs, f):
    return vs.sign_verdict(Verdict(f.finding_id, finding_digest(f), "refuted", "replay", 0.9, "r", vs.pubkey[:6]))


@pytest.fixture
def gate(tmp_path, scanner, verifier_a):
    kr = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    led = BountyLedger(str(tmp_path / "ledger.jsonl"))
    return PayoutGate(kr, led, crypto_enabled=True, prod=False, cooldown_s=0,
                      external_verifiers={verifier_a.pubkey})


def test_keyring_refuses_scanner_equals_treasury(tmp_path):
    same = str(tmp_path / "one.key")
    with pytest.raises(ValueError, match="differ from the scanner"):
        KeyRing(same, same)


def test_no_treasury_key_fails_closed(tmp_path, scanner, verifier_a, verifier_b):
    kr = KeyRing(str(tmp_path / "scanner.key"))  # no treasury
    gate = PayoutGate(kr, BountyLedger(str(tmp_path / "l.jsonl")), crypto_enabled=True, prod=True, cooldown_s=0)
    f = _finding(scanner)
    dec = gate.authorize(f, [_confirm(verifier_a, f), _confirm(verifier_b, f)], deposit_posted_usd=25)
    assert dec.state == PayoutState.REFUSED.value
    assert dec.signature == {}  # nothing to sign with, no treasury


def test_scanner_cannot_self_verify(gate, scanner):
    f = _finding(scanner, "high")
    self_v = scanner.sign_verdict(Verdict(f.finding_id, finding_digest(f), "confirmed", "self", 1.0, "r", "sc"))
    dec = gate.authorize(f, [self_v], deposit_posted_usd=25)
    assert dec.state == PayoutState.REFUSED.value


def test_high_needs_external_verifier(gate, scanner, verifier_b):
    # two distinct verifiers but NEITHER is the registered external one -> refused
    f = _finding(scanner, "high")
    other = FindingSigner_of(gate)  # a second non-external key
    dec = gate.authorize(f, [_confirm(verifier_b, f), _confirm(other, f)], deposit_posted_usd=25)
    assert dec.state == PayoutState.REFUSED.value


def test_high_pays_with_external_plus_internal(gate, scanner, verifier_a, verifier_b):
    f = _finding(scanner, "high")
    dec = gate.authorize(f, [_confirm(verifier_a, f), _confirm(verifier_b, f)], deposit_posted_usd=25)
    assert dec.state == PayoutState.PAID.value
    assert dec.amount_usd == terms_for("high").bounty_usd
    assert dec.signature.get("value")  # signed by the treasury


def test_dedup_blocks_double_pay(gate, scanner, verifier_a, verifier_b):
    f = _finding(scanner, "high")
    vs = [_confirm(verifier_a, f), _confirm(verifier_b, f)]
    first = gate.authorize(f, vs, deposit_posted_usd=25)
    second = gate.authorize(f, vs, deposit_posted_usd=25)
    assert first.state == PayoutState.PAID.value
    assert second.state == PayoutState.REFUSED.value


def test_small_order_verifier_key_rejected(gate, scanner):
    import base64
    small = base64.b64encode(bytes.fromhex("01" + "00" * 31)).decode()
    f = _finding(scanner, "medium")
    fake = Verdict(f.finding_id, finding_digest(f), "confirmed", "x", 1.0, "r", "fake")
    fake.verifier_pubkey = small
    fake.signature = {"algorithm": "ed25519", "value": "AAAA"}
    dec = gate.authorize(f, [fake], deposit_posted_usd=2.5)
    assert dec.state == PayoutState.REFUSED.value


def test_infra_target_never_auto_pays(gate, scanner, verifier_a, verifier_b):
    f = _finding(scanner, "critical", target="treasury", kind="oracle")
    scanner.sign_finding(f)
    dec = gate.authorize(f, [_confirm(verifier_a, f), _confirm(verifier_b, f)], deposit_posted_usd=100)
    assert dec.state == PayoutState.REFUSED.value
    assert any("infra" in r for r in dec.reasons)


def test_deposit_below_required_refused(gate, scanner, verifier_a, verifier_b):
    f = _finding(scanner, "high")  # requires 50% of $50 = $25
    dec = gate.authorize(f, [_confirm(verifier_a, f), _confirm(verifier_b, f)], deposit_posted_usd=1.0)
    assert dec.state == PayoutState.REFUSED.value
    assert any("deposit" in r for r in dec.reasons)


def test_crypto_off_settles_in_uni_simulation(tmp_path, scanner, verifier_a, verifier_b):
    """Crypto off is NOT a dead end: the default tier is the UNI simulation, so the whole loop
    completes and is auditable — while `simulated` records that no value moved."""
    kr = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    gate = PayoutGate(kr, BountyLedger(str(tmp_path / "l.jsonl")), crypto_enabled=False, prod=False,
                      cooldown_s=0, external_verifiers={verifier_a.pubkey})
    f = _finding(scanner, "high")
    dec = gate.authorize(f, [_confirm(verifier_a, f), _confirm(verifier_b, f)], deposit_posted_usd=25)
    assert dec.state == PayoutState.PAID.value
    assert dec.settlement["mode"] == "uni" and dec.settlement["simulated"] is True


def test_explicit_held_tier_releases_nothing(tmp_path, scanner, verifier_a, verifier_b):
    from momus.settlement import SettlementBackend, SettlementMode
    kr = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    gate = PayoutGate(kr, BountyLedger(str(tmp_path / "l.jsonl")), crypto_enabled=False, prod=False,
                      cooldown_s=0, external_verifiers={verifier_a.pubkey},
                      settlement=SettlementBackend(SettlementMode.HELD, "settlement disabled"))
    f = _finding(scanner, "high")
    dec = gate.authorize(f, [_confirm(verifier_a, f), _confirm(verifier_b, f)], deposit_posted_usd=25)
    assert dec.state == PayoutState.HELD.value


def test_medium_pays_with_one_distinct_verifier(gate, scanner, verifier_b):
    f = _finding(scanner, "medium")
    dec = gate.authorize(f, [_confirm(verifier_b, f)], deposit_posted_usd=2.5)
    assert dec.state == PayoutState.PAID.value


def test_info_never_pays(gate, scanner, verifier_a, verifier_b):
    f = _finding(scanner, "info")
    dec = gate.authorize(f, [_confirm(verifier_a, f), _confirm(verifier_b, f)], deposit_posted_usd=100)
    assert dec.state == PayoutState.REFUSED.value


def test_deposit_forfeit_on_refute(gate, scanner, verifier_a, verifier_b):
    f = _finding(scanner, "high")
    rule = gate.adjudicate_deposit(f, [_refute(verifier_a, f), _refute(verifier_b, f)], deposit_posted_usd=25)
    assert rule["ruling"] == "forfeit"
    assert rule["forfeited_usd"] == 25


def test_deposit_refund_when_not_refuted(gate, scanner, verifier_a):
    f = _finding(scanner, "high")
    rule = gate.adjudicate_deposit(f, [_confirm(verifier_a, f)], deposit_posted_usd=25)
    assert rule["ruling"] == "refund"


def test_cooldown_blocks_rapid_claims(tmp_path, scanner, verifier_a, verifier_b):
    kr = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    led = BountyLedger(str(tmp_path / "l.jsonl"))
    gate = PayoutGate(kr, led, crypto_enabled=True, prod=False, cooldown_s=60,
                      external_verifiers={verifier_a.pubkey})
    f1 = _finding(scanner, "high")
    led.record_claim(scanner.pubkey, now=1000.0, payload={})
    dec = gate.authorize(f1, [_confirm(verifier_a, f1), _confirm(verifier_b, f1)],
                         deposit_posted_usd=25, now=1010.0)
    assert dec.state == PayoutState.REFUSED.value
    assert any("cooldown" in r for r in dec.reasons)


def test_valid_pubkey_helper():
    import base64
    good = base64.b64encode(bytes(range(32))).decode()  # 32 bytes, not small-order
    assert is_valid_ed25519_pubkey(good)
    assert not is_valid_ed25519_pubkey(base64.b64encode(b"tooshort").decode())
    assert not is_valid_ed25519_pubkey("")


def _fix_verdict(momus, finding, fixed=True):
    import json
    v = {"finding_id": finding.finding_id, "target": finding.target, "probe": finding.probe,
         "fixed": fixed, "outcome": "no_finding" if fixed else "finding", "detail": "x",
         "checked_at": "2026-01-01T00:00:00Z", "verifier_pubkey": momus.pubkey}
    v["signature"] = momus._signer.sign_payload(json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return v


def test_split_pays_all_verified_contributors(gate, scanner, verifier_a, verifier_b):
    f = _finding(scanner, "high")  # pool = $50
    momus = scanner  # the finder/retester in the single-box case
    fixv = _fix_verdict(momus, f, fixed=True)
    out = gate.authorize_split(
        f, [_confirm(verifier_a, f), _confirm(verifier_b, f)],
        participants={"finder": scanner.pubkey, "fixer": "factory-1", "conductor": "skopos-1"},
        deposit_posted_usd=25, fix_verdict=fixv, deploy_ack={"accepted": True}, momus_pubkey=momus.pubkey)
    assert out["base_state"] == "paid" and out["pool_usd"] == 50.0
    by_role = {s["role"]: s for s in out["shares"]}
    assert by_role["finder"]["amount_usd"] == 25.0 and by_role["finder"]["state"] == "paid"
    assert by_role["fixer"]["amount_usd"] == 17.5 and by_role["fixer"]["state"] == "paid"
    assert by_role["conductor"]["amount_usd"] == 7.5 and by_role["conductor"]["state"] == "paid"
    assert out["total_released_usd"] == 50.0  # finder + fixer + conductor = full pool


def test_split_withholds_fixer_without_fixed_verdict(gate, scanner, verifier_a, verifier_b):
    f = _finding(scanner, "high")
    out = gate.authorize_split(
        f, [_confirm(verifier_a, f), _confirm(verifier_b, f)],
        participants={"finder": scanner.pubkey, "fixer": "factory-1", "conductor": "skopos-1"},
        deposit_posted_usd=25, fix_verdict=None, deploy_ack=None, momus_pubkey=scanner.pubkey)
    by_role = {s["role"]: s for s in out["shares"]}
    assert by_role["finder"]["state"] == "paid"          # finder still paid for the confirmed find
    assert by_role["fixer"]["state"] == "refused"        # no fix → no fixer share
    assert by_role["conductor"]["state"] == "refused"    # no fix/deploy → no conductor share


def test_split_pays_nothing_when_finding_not_confirmed(gate, scanner):
    f = _finding(scanner, "high")
    fixv = _fix_verdict(scanner, f, fixed=True)
    out = gate.authorize_split(
        f, [],  # no independent confirmation → base refused → whole pool is zero
        participants={"finder": scanner.pubkey, "fixer": "factory-1"},
        deposit_posted_usd=25, fix_verdict=fixv, deploy_ack={"accepted": True}, momus_pubkey=scanner.pubkey)
    assert out["pool_usd"] == 0.0 and out["total_released_usd"] == 0.0
    assert all(s["state"] == "refused" for s in out["shares"])


def FindingSigner_of(gate):
    # helper: mint a fresh, distinct non-external verifier key in a temp dir
    import tempfile, os
    return FindingSigner(os.path.join(tempfile.mkdtemp(), "other.key"))
