"""The UNI vault (a balance that can run out) and the security budget that refills it by rule.

The point of these tests is that the simulation is *economically real*: money enters only through a
funding event, a bounty draws it down, an exhausted vault REFUSES instead of paying, and the refill
is governed by a standing rule that escalates rather than letting a funder silently starve the
auditor.
"""

from __future__ import annotations

import pytest

from momus.budget import AllocationRule, SecurityBudget
from momus.economics import BountyLedger, KeyRing, PayoutGate, PayoutState
from momus.findings import Evidence, Finding, Outcome, Status, Verdict, finding_digest
from momus.settlement import SettlementBackend, SettlementMode
from momus.vault import TX_MEANING, UniVault


# ── the vault ────────────────────────────────────────────────────────────────
def test_starts_empty_and_funds(tmp_path):
    v = UniVault(str(tmp_path / "vault.jsonl"))
    assert v.balance == 0 and v.available == 0
    v.fund(100.0)
    assert v.balance == 100.0 and v.available == 100.0
    assert v.journal()[-1]["kind"] == "fund"
    assert "operator" in v.journal()[-1]["means"]


def test_reserve_then_release_moves_money_once(tmp_path):
    v = UniVault(str(tmp_path / "vault.jsonl"))
    v.fund(100.0)
    ok, _why, _tx = v.reserve("mom-1", 50.0)
    assert ok
    assert v.balance == 100.0 and v.reserved == 50.0 and v.available == 50.0  # set aside, not spent
    assert v.release("mom-1", "finder", 25.0)[0]
    assert v.balance == 75.0 and v.reserved == 25.0 and v.available == 50.0
    assert v.release("mom-1", "fixer", 17.5)[0]
    assert v.balance == 57.5


def test_reserve_refuses_when_insufficient(tmp_path):
    v = UniVault(str(tmp_path / "vault.jsonl"))
    v.fund(30.0)
    ok, why, _ = v.reserve("mom-1", 50.0)
    assert not ok and "insufficient available funds" in why


def test_reservation_blocks_a_second_claim_from_the_same_dollar(tmp_path):
    v = UniVault(str(tmp_path / "vault.jsonl"))
    v.fund(60.0)
    assert v.reserve("mom-1", 50.0)[0]
    ok, why, _ = v.reserve("mom-2", 50.0)          # only $10 left available
    assert not ok and "available $10.00" in why


def test_release_cannot_overdraw_its_reservation(tmp_path):
    v = UniVault(str(tmp_path / "vault.jsonl"))
    v.fund(100.0)
    v.reserve("mom-1", 20.0)
    ok, why, _ = v.release("mom-1", "finder", 50.0)
    assert not ok and "exceeds what is reserved" in why
    assert v.balance == 100.0                       # nothing left the vault


def test_unreserve_returns_funds(tmp_path):
    v = UniVault(str(tmp_path / "vault.jsonl"))
    v.fund(100.0)
    v.reserve("mom-1", 50.0)
    v.unreserve("mom-1", note="claim refused after reservation")
    assert v.available == 100.0 and v.reserved == 0.0


def test_forfeited_deposit_is_the_only_non_operator_inflow(tmp_path):
    v = UniVault(str(tmp_path / "vault.jsonl"))
    v.fund(10.0)
    v.forfeit_deposit("mom-bad", 25.0)
    assert v.balance == 35.0
    assert v.journal()[-1]["kind"] == "forfeit" and "spam funds the honest side" in v.journal()[-1]["means"]
    v.refund_deposit("mom-ok", 25.0)                # a refund does not change the vault's balance
    assert v.balance == 35.0


def test_every_transaction_kind_explains_itself(tmp_path):
    v = UniVault(str(tmp_path / "vault.jsonl"))
    v.fund(100.0); v.reserve("f", 50.0); v.release("f", "finder", 25.0)
    v.unreserve("f"); v.forfeit_deposit("g", 5.0); v.refund_deposit("h", 5.0)
    kinds = {t["kind"] for t in v.journal(50)}
    assert kinds == set(TX_MEANING)                  # all six kinds exercised
    for t in v.journal(50):
        assert t["means"] and t["means"] == TX_MEANING[t["kind"]]
        assert t["balance_after"] is not None and t["available_after"] is not None


def test_journal_replays_state_after_restart(tmp_path):
    p = str(tmp_path / "vault.jsonl")
    v = UniVault(p)
    v.fund(100.0); v.reserve("mom-1", 50.0); v.release("mom-1", "finder", 25.0)
    again = UniVault(p)                              # fresh process
    assert again.balance == 75.0 and again.reserved == 25.0 and again.available == 50.0


# ── the vault wired into settlement: the balance really runs out ──────────────
def _finding(scanner, severity="high"):
    f = Finding(target="oracles", target_kind="oracle", probe="p", category="authz", severity=severity,
                outcome=Outcome.FINDING.value, title="t", detail="d",
                evidence=Evidence("sha256-a", "sha256-b"), status=Status.RAW.value)
    return scanner.sign_finding(f)


def _confirm(vs, f):
    return vs.sign_verdict(Verdict(f.finding_id, finding_digest(f), "confirmed", "replay", 0.95, "r",
                                   vs.pubkey[:6]))


def test_exhausted_vault_holds_instead_of_paying(tmp_path, scanner, verifier_a, verifier_b):
    """An empty vault must HOLD the decision, not invent money. This is the honest failure."""
    vault = UniVault(str(tmp_path / "vault.jsonl"))   # never funded
    kr = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    gate = PayoutGate(kr, BountyLedger(str(tmp_path / "l.jsonl")), crypto_enabled=False, prod=False,
                      cooldown_s=0, external_verifiers={verifier_a.pubkey},
                      settlement=SettlementBackend(SettlementMode.UNI, "uni",
                                                   uni_ledger_path=str(tmp_path / "uni.jsonl"),
                                                   vault=vault))
    f = _finding(scanner, "high")
    dec = gate.authorize(f, [_confirm(verifier_a, f), _confirm(verifier_b, f)], deposit_posted_usd=25)
    assert dec.state == PayoutState.HELD.value
    assert "vault refused" in dec.settlement["reason"]
    assert vault.balance == 0.0


def test_funded_vault_pays_and_draws_down(tmp_path, scanner, verifier_a, verifier_b):
    vault = UniVault(str(tmp_path / "vault.jsonl"))
    vault.fund(100.0)
    vault.reserve("pool", 0)  # no-op; the gate reserves per finding below
    kr = KeyRing(str(tmp_path / "scanner.key"), str(tmp_path / "treasury.key"))
    gate = PayoutGate(kr, BountyLedger(str(tmp_path / "l.jsonl")), crypto_enabled=False, prod=False,
                      cooldown_s=0, external_verifiers={verifier_a.pubkey},
                      settlement=SettlementBackend(SettlementMode.UNI, "uni",
                                                   uni_ledger_path=str(tmp_path / "uni.jsonl"),
                                                   vault=vault))
    f = _finding(scanner, "high")
    vault.reserve(f.finding_id, 50.0)                 # the pool for this bounty
    dec = gate.authorize(f, [_confirm(verifier_a, f), _confirm(verifier_b, f)], deposit_posted_usd=25)
    assert dec.state == PayoutState.PAID.value
    assert vault.balance == 50.0                      # $50 left the vault
    assert dec.settlement["simulated"] is True        # still no real value


# ── the security budget: refill by rule, escalate above it ───────────────────
@pytest.mark.asyncio
async def test_top_up_grants_within_the_standing_rule(tmp_path):
    vault = UniVault(str(tmp_path / "vault.jsonl"))
    rule = AllocationRule(rate_bps=200, period_cap_usd=500.0, top_up_threshold_usd=50.0,
                          top_up_target_usd=250.0)
    # 2% of $20,000 settled volume = $400 allowance, so a $250 request is inside the rule.
    budget = SecurityBudget(vault, rule, fallback_volume_usd=20_000.0)
    assert budget.needs_top_up()
    res = await budget.request_top_up()
    assert res.approved and res.granted_usd == 250.0 and not res.escalated
    assert vault.balance == 250.0
    assert "standing rule" in res.reason and "operator-declared" in res.source


@pytest.mark.asyncio
async def test_request_above_the_allowance_escalates_not_starves(tmp_path):
    """The funder cannot silently defund the auditor: the shortfall is reported and escalated."""
    vault = UniVault(str(tmp_path / "vault.jsonl"))
    rule = AllocationRule(rate_bps=100, period_cap_usd=500.0, top_up_target_usd=250.0)
    # 1% of $5,000 = $50 allowance vs a $250 request.
    budget = SecurityBudget(vault, rule, fallback_volume_usd=5_000.0)
    res = await budget.request_top_up()
    assert res.approved and res.granted_usd == 50.0
    assert res.escalated and "escalated to human governance" in res.reason
    assert vault.balance == 50.0


@pytest.mark.asyncio
async def test_period_allowance_exhausts_then_escalates(tmp_path):
    vault = UniVault(str(tmp_path / "vault.jsonl"))
    rule = AllocationRule(rate_bps=200, period_cap_usd=100.0, top_up_target_usd=100.0)
    budget = SecurityBudget(vault, rule, fallback_volume_usd=1_000_000.0)  # rate is huge; cap binds
    first = await budget.request_top_up()
    assert first.granted_usd == 100.0
    vault.release  # (no-op reference)
    # drain it so a second request is needed
    vault.reserve("x", 100.0); vault.release("x", "finder", 100.0)
    second = await budget.request_top_up()
    assert not second.approved and second.escalated
    assert "allowance exhausted" in second.reason


@pytest.mark.asyncio
async def test_no_top_up_when_above_target(tmp_path):
    vault = UniVault(str(tmp_path / "vault.jsonl"))
    vault.fund(500.0)
    budget = SecurityBudget(vault, AllocationRule(top_up_target_usd=250.0), fallback_volume_usd=1e6)
    res = await budget.request_top_up()
    assert not res.approved and res.granted_usd == 0.0 and "no top-up needed" in res.reason


@pytest.mark.asyncio
async def test_unreachable_hub_is_reported_not_hidden(tmp_path):
    vault = UniVault(str(tmp_path / "vault.jsonl"))
    budget = SecurityBudget(vault, AllocationRule(rate_bps=200),
                            hub_url="http://127.0.0.1:1", fallback_volume_usd=10_000.0)
    res = await budget.request_top_up()
    assert "hub unreachable" in res.source          # honest about where the number came from
