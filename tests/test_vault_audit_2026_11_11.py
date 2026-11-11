"""Audit 2026-11-11, satellites-6 and satellites-7.

satellites-6: a UNI share was paid only out of a reservation, and nothing but the operator's manual
/vault/reserve made one, so every claim ended HELD; a refused claim's reservation stayed forever.
satellites-7: the per-scanner claim cooldown read a timestamp that nothing ever recorded.
"""
from __future__ import annotations

from momus.economics import BountyLedger, KeyRing, PayoutGate, PayoutState
from momus.findings import Evidence, Finding, Outcome, Status, Verdict, finding_digest
from momus.settlement import SettlementBackend, SettlementMode
from momus.vault import UniVault


def _finding(scanner, severity="high"):
    f = Finding(target="oracles", target_kind="oracle", probe="p", category="authz", severity=severity,
                outcome=Outcome.FINDING.value, title="t", detail="d",
                evidence=Evidence("sha256-a", "sha256-b"), status=Status.RAW.value)
    return scanner.sign_finding(f)


def _confirm(vs, f):
    return vs.sign_verdict(Verdict(f.finding_id, finding_digest(f), "confirmed", "replay", 0.95, "r",
                                   vs.pubkey[:6], subject_target=f.target, subject_probe=f.probe))


def _gate(tmp_path, verifier_a, vault, *, cooldown_s=0.0, ledger_name="l.jsonl"):
    kr = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    return PayoutGate(kr, BountyLedger(str(tmp_path / ledger_name)), crypto_enabled=False, prod=False,
                      cooldown_s=cooldown_s, external_verifiers={verifier_a.pubkey},
                      settlement=SettlementBackend(SettlementMode.UNI, "uni",
                                                   uni_ledger_path=str(tmp_path / "uni.jsonl"), vault=vault))


def test_a_gate_approved_share_is_paid_from_a_funded_vault_without_a_manual_reservation(
        tmp_path, scanner, verifier_a, verifier_b):
    vault = UniVault(str(tmp_path / "vault.jsonl"))
    vault.fund(100.0)
    f = _finding(scanner, "high")
    dec = _gate(tmp_path, verifier_a, vault).authorize(
        f, [_confirm(verifier_a, f), _confirm(verifier_b, f)], deposit_posted_usd=25)
    assert dec.state == PayoutState.PAID.value, dec.reasons
    assert vault.balance == 50.0 and vault.reserved == 0.0


def test_a_short_vault_still_refuses(tmp_path, scanner, verifier_a, verifier_b):
    vault = UniVault(str(tmp_path / "vault.jsonl"))
    vault.fund(10.0)
    f = _finding(scanner, "high")
    dec = _gate(tmp_path, verifier_a, vault).authorize(
        f, [_confirm(verifier_a, f), _confirm(verifier_b, f)], deposit_posted_usd=25)
    assert dec.state == PayoutState.HELD.value and "insufficient available funds" in dec.settlement["reason"]
    assert vault.balance == 10.0 and vault.reserved == 0.0


def test_a_refused_claim_hands_its_reservation_back(tmp_path, scanner, verifier_a):
    vault = UniVault(str(tmp_path / "vault.jsonl"))
    vault.fund(100.0)
    f = _finding(scanner, "high")
    vault.reserve(f.finding_id, 50.0)
    dec = _gate(tmp_path, verifier_a, vault).authorize(f, [_confirm(verifier_a, f)], deposit_posted_usd=25)
    assert dec.state == PayoutState.REFUSED.value          # one confirmation is not a quorum
    assert vault.reserved == 0.0 and vault.available == 100.0


def test_a_dry_run_settles_and_records_nothing(tmp_path, scanner, verifier_a, verifier_b):
    vault = UniVault(str(tmp_path / "vault.jsonl"))
    vault.fund(100.0)
    gate = _gate(tmp_path, verifier_a, vault)
    f = _finding(scanner, "high")
    verdicts = [_confirm(verifier_a, f), _confirm(verifier_b, f)]
    dry = gate.authorize(f, verdicts, deposit_posted_usd=25, settle=False, record=False)
    assert dry.state == PayoutState.HELD.value and vault.balance == 100.0
    assert not (tmp_path / "l.jsonl").exists() or "decision" not in (tmp_path / "l.jsonl").read_text()
    assert gate.authorize(f, verdicts, deposit_posted_usd=25).state == PayoutState.PAID.value


def test_the_claim_cooldown_bites_and_survives_a_restart(tmp_path, scanner, verifier_a, verifier_b):
    vault = UniVault(str(tmp_path / "vault.jsonl"))
    vault.fund(1_000.0)
    gate = _gate(tmp_path, verifier_a, vault, cooldown_s=60)
    f1 = _finding(scanner, "high")
    # A different bug (another probe), so the second claim is not refused as a duplicate.
    f2 = scanner.sign_finding(Finding(target="oracles", target_kind="oracle", probe="p2", category="authz",
                                      severity="high", outcome=Outcome.FINDING.value, title="t2", detail="d2",
                                      evidence=Evidence("sha256-c", "sha256-d"), status=Status.RAW.value))
    assert gate.authorize(f1, [_confirm(verifier_a, f1), _confirm(verifier_b, f1)],
                          deposit_posted_usd=25, now=1_000.0).state == PayoutState.PAID.value
    second = gate.authorize(f2, [_confirm(verifier_a, f2), _confirm(verifier_b, f2)],
                            deposit_posted_usd=25, now=1_010.0)
    assert second.state == PayoutState.REFUSED.value and any("cooldown" in r for r in second.reasons)
    restarted = _gate(tmp_path, verifier_a, vault, cooldown_s=60)       # same ledger file
    again = restarted.authorize(f2, [_confirm(verifier_a, f2), _confirm(verifier_b, f2)],
                                deposit_posted_usd=25, now=1_020.0)
    assert any("cooldown" in r for r in again.reasons)


# ── review of 2026-11-11 ─────────────────────────────────────────────────────
def test_a_junk_claim_naming_a_reserved_finding_does_not_release_it(tmp_path, scanner, verifier_a):
    vault = UniVault(str(tmp_path / "vault.jsonl"))
    vault.fund(500.0)
    vault.reserve("victim-F", 200.0)
    junk = _finding(scanner, "high")
    junk.finding_id = "victim-F"
    junk.signature = {"algorithm": "ed25519", "value": "AAAA"}         # not the scanner's signature
    dec = _gate(tmp_path, verifier_a, vault).authorize(junk, [], deposit_posted_usd=25)
    assert dec.state == PayoutState.REFUSED.value
    assert vault.reserved_for("victim-F") == 200.0 and vault.available == 300.0


def test_reusing_one_finding_id_does_not_switch_the_cooldown_off(tmp_path, scanner, verifier_a, verifier_b):
    vault = UniVault(str(tmp_path / "vault.jsonl"))
    vault.fund(1_000.0)
    gate = _gate(tmp_path, verifier_a, vault, cooldown_s=60)
    f1 = _finding(scanner, "high")
    assert gate.authorize(f1, [_confirm(verifier_a, f1), _confirm(verifier_b, f1)],
                          deposit_posted_usd=25, now=1_000.0).state == PayoutState.PAID.value
    other = Finding(target="oracles", target_kind="oracle", probe="p9", category="authz", severity="high",
                    outcome=Outcome.FINDING.value, title="t9", detail="d9",
                    evidence=Evidence("sha256-e", "sha256-f"), status=Status.RAW.value)
    other.finding_id = f1.finding_id                                     # same id, different bug
    other = scanner.sign_finding(other)
    second = gate.authorize(other, [_confirm(verifier_a, other), _confirm(verifier_b, other)],
                            deposit_posted_usd=25, now=1_010.0)
    assert second.state == PayoutState.REFUSED.value and any("cooldown" in r for r in second.reasons)


def test_the_self_audit_never_pays_out_of_the_operator_vault(tmp_path, scanner, monkeypatch):
    from momus.economics import KeyRing
    from momus.engine.selfaudit import run_self_audit

    vault_path = tmp_path / "env_vault.jsonl"
    UniVault(str(vault_path)).fund(200.0)
    monkeypatch.setenv("MOMUS_UNI_VAULT_PATH", str(vault_path))
    keyring = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    counter = {"n": 0}

    def ledger_path_factory():
        counter["n"] += 1
        return str(tmp_path / f"audit_{counter['n']}.jsonl")

    for _ in range(3):
        report = run_self_audit(scanner, keyring, ledger_path_factory)
        assert report.counts["findings"] == 0
    assert UniVault(str(vault_path)).balance == 200.0
