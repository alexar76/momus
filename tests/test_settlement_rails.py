"""The reward-rail ladder, and the invariant it must never break.

The owner's rule, in their words: **"a system with crypto off must not become less secure."**

MOMUS is a security auditor that also happens to get paid. Those are two different concerns and
this file exists to keep them apart:

  - the LADDER tests pin which rail carries a share under each configuration;
  - the FALLBACK tests pin that a real rail which cannot settle never stalls the loop;
  - the INVARIANT tests pin that none of it reaches the scanner, the verifier or the deploy gate.

The invariant is asserted twice on purpose — once behaviourally (the same finding is judged
identically on every rail) and once structurally (the security modules cannot even import the money
modules). The behavioural test catches a regression; the structural test catches the *design* drift
that would make one possible.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from momus.economics import BountyLedger, KeyRing, PayoutGate, PayoutState
from momus.findings import Evidence, Finding, FindingSigner, Outcome, Status, Verdict, finding_digest
from momus.settlement import (
    FALLBACK_HELD,
    FALLBACK_SANDBOX,
    SettlementBackend,
    SettlementMode,
    looks_like_evm_address,
    resolve_fallback,
    resolve_mode,
)

SPLITTER = "0x" + "cd" * 20
MOMUS_PKG = Path(__file__).resolve().parents[1] / "momus"


# ─────────────────────────────────────────────────────────────────── fixtures


@pytest.fixture()
def scanner(tmp_path):
    return FindingSigner(str(tmp_path / "scanner.key"))


@pytest.fixture()
def verifier_a(tmp_path):
    return FindingSigner(str(tmp_path / "va.key"))


@pytest.fixture()
def verifier_b(tmp_path):
    return FindingSigner(str(tmp_path / "vb.key"))


def _finding(scanner, severity="high"):
    f = Finding(target="oracles", target_kind="oracle", probe="p", category="authz",
                severity=severity, outcome=Outcome.FINDING.value, title="t", detail="d",
                evidence=Evidence("sha256-a", "sha256-b"), status=Status.RAW.value)
    return scanner.sign_finding(f)


def _confirm(vs, f):
    return vs.sign_verdict(Verdict(f.finding_id, finding_digest(f), "confirmed", "replay", 0.95,
                                   "r", vs.pubkey[:6], subject_target=f.target,
                                   subject_probe=f.probe))


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """No ambient rail configuration leaks into these tests."""
    for var in ("AIFACTORY_CRYPTO_ENABLED", "MOMUS_BOUNTY_ONCHAIN", "MOMUS_SETTLEMENT",
                "MOMUS_BOUNTY_CHAIN", "MOMUS_BOUNTY_SPLITTER", "MOMUS_REWARD_FALLBACK",
                "MOMUS_UNI_VAULT_PATH", "MOMUS_UNI_LEDGER_PATH", "MOMUS_DATA_DIR"):
        monkeypatch.delenv(var, raising=False)


# ─────────────────────────────────────────────────────────────────── the ladder


def test_nothing_configured_is_the_sandbox_rail():
    mode, reason = resolve_mode()
    assert mode is SettlementMode.UNI and "no value moves" in reason


def test_crypto_off_cannot_reach_a_real_rail(monkeypatch):
    """The master switch is the first rung, and asking for BASE without it does not escalate."""
    monkeypatch.setenv("MOMUS_SETTLEMENT", "base")
    monkeypatch.setenv("MOMUS_BOUNTY_ONCHAIN", "1")
    monkeypatch.setenv("MOMUS_BOUNTY_SPLITTER", SPLITTER)
    mode, reason = resolve_mode(crypto_enabled=False)
    assert mode is SettlementMode.HELD and "AIFACTORY_CRYPTO_ENABLED is off" in reason


def test_crypto_alone_never_starts_paying_bounties(monkeypatch):
    """Turning crypto on for the ecosystem must not silently start paying red-team bounties."""
    monkeypatch.setenv("MOMUS_SETTLEMENT", "base")
    monkeypatch.setenv("MOMUS_BOUNTY_SPLITTER", SPLITTER)
    mode, reason = resolve_mode(crypto_enabled=True)
    assert mode is SettlementMode.HELD and "MOMUS_BOUNTY_ONCHAIN" in reason


def test_the_full_ladder_reaches_base(monkeypatch):
    monkeypatch.setenv("MOMUS_SETTLEMENT", "base")
    monkeypatch.setenv("MOMUS_BOUNTY_ONCHAIN", "1")
    monkeypatch.setenv("MOMUS_BOUNTY_SPLITTER", SPLITTER)
    mode, _ = resolve_mode(crypto_enabled=True)
    assert mode is SettlementMode.BASE


@pytest.mark.parametrize("bad", ["not-an-address", "0xdeadbeef", SPLITTER + "ff", "0x" + "zz" * 20])
def test_a_malformed_splitter_fails_closed(monkeypatch, bad):
    """Only EMPTINESS used to be checked, so a typo'd address resolved to BASE and surfaced as a
    failed transaction the first time a human signed one."""
    monkeypatch.setenv("MOMUS_SETTLEMENT", "base")
    monkeypatch.setenv("MOMUS_BOUNTY_ONCHAIN", "1")
    monkeypatch.setenv("MOMUS_BOUNTY_SPLITTER", bad)
    mode, reason = resolve_mode(crypto_enabled=True)
    assert mode is SettlementMode.HELD and "20-byte address" in reason


def test_address_shape_check():
    assert looks_like_evm_address(SPLITTER)
    assert not looks_like_evm_address("")
    assert not looks_like_evm_address("cd" * 20)          # no 0x
    assert not looks_like_evm_address("0x" + "cd" * 19)   # too short


# ─────────────────────────────────────────────────────────────────── the fallback


def test_the_default_fallback_is_the_resilient_one():
    fallback, reason = resolve_fallback()
    assert fallback == FALLBACK_SANDBOX and "keeps running" in reason


def test_an_unrecognised_fallback_defaults_to_sandbox(monkeypatch):
    monkeypatch.setenv("MOMUS_REWARD_FALLBACK", "typo")
    assert resolve_fallback()[0] == FALLBACK_SANDBOX


def test_an_unfunded_base_rail_pays_on_the_sandbox_rail_instead():
    """The headline behaviour: LIVE is on, the real rail cannot settle, and MOMUS keeps going."""
    b = SettlementBackend(SettlementMode.BASE, "base", splitter=SPLITTER)
    d = b.settle_share(finding_id="mom-1", role="finder", recipient="0xr", amount_usd=50.0)
    assert d.settled is True                    # the loop is not stalled
    assert d.simulated is True                  # and it does not pretend USDC moved
    assert d.rail == "sandbox"
    assert d.fallback_from == "base"
    assert d.mode == "base"                     # the CONFIGURED tier is still reported honestly


def test_the_fallback_still_never_broadcasts():
    """Falling back must not quietly become a licence to move real money."""
    b = SettlementBackend(SettlementMode.BASE, "base", splitter=SPLITTER)
    d = b.settle_share(finding_id="mom-1", role="finder", recipient="0xr", amount_usd=50.0)
    assert "UNSIGNED" in d.prepared_call["note"]
    assert d.prepared_call["contract"] == SPLITTER


def test_the_unsigned_call_survives_the_fallback():
    """An operator who DOES want to pay in USDC must still be handed the call to sign."""
    b = SettlementBackend(SettlementMode.BASE, "base", splitter=SPLITTER)
    d = b.settle_share(finding_id="mom-1", role="fixer", recipient="0xr", amount_usd=17.5)
    assert d.prepared_call["args"]["amount"] == 17_500_000       # 6-decimal USDC, unchanged
    assert d.prepared_call["function"].startswith("releaseShare")


def test_held_fallback_restores_the_stalling_stance():
    b = SettlementBackend(SettlementMode.BASE, "base", splitter=SPLITTER, fallback=FALLBACK_HELD)
    d = b.settle_share(finding_id="mom-1", role="finder", recipient="0xr", amount_usd=50.0)
    assert d.settled is False and d.rail == "base" and d.fallback_from == ""


def test_solana_falls_back_too():
    b = SettlementBackend(SettlementMode.SOLANA, "solana")
    d = b.settle_share(finding_id="mom-1", role="finder", recipient="0xr", amount_usd=50.0)
    assert d.settled is True and d.rail == "sandbox" and d.fallback_from == "solana"


def test_the_sandbox_journal_records_which_rail_paid(tmp_path):
    """An auditor reading the journal must be able to tell a fallback from a plain UNI settlement."""
    ledger = tmp_path / "uni.jsonl"
    b = SettlementBackend(SettlementMode.BASE, "base", splitter=SPLITTER,
                          uni_ledger_path=str(ledger))
    b.settle_share(finding_id="mom-1", role="finder", recipient="0xr", amount_usd=50.0)
    rec = json.loads(ledger.read_text(encoding="utf-8").splitlines()[0])
    assert rec["simulated"] is True and rec["rail"] == "sandbox" and rec["fallback_from"] == "base"


def test_a_plain_uni_settlement_is_not_marked_as_a_fallback(tmp_path):
    ledger = tmp_path / "uni.jsonl"
    b = SettlementBackend(SettlementMode.UNI, "uni", uni_ledger_path=str(ledger))
    d = b.settle_share(finding_id="mom-1", role="finder", recipient="0xr", amount_usd=50.0)
    rec = json.loads(ledger.read_text(encoding="utf-8").splitlines()[0])
    assert d.fallback_from == "" and rec["fallback_from"] is None


# ─────────────────────────────────────────────────────────────────── the vault


def test_the_vault_is_opt_in_so_a_fresh_deployment_still_pays():
    """Attaching a vault by default would be worse than not wiring it at all: a fresh vault holds
    $0.00 and refuses every release, turning 'the loop always runs' into 'nothing is ever paid'."""
    b = SettlementBackend.from_env()
    assert b.vault is None
    d = b.settle_share(finding_id="mom-1", role="finder", recipient="0xr", amount_usd=50.0)
    assert d.settled is True


def test_opting_into_the_vault_attaches_it(monkeypatch, tmp_path):
    monkeypatch.setenv("MOMUS_UNI_VAULT_PATH", str(tmp_path / "vault.jsonl"))
    b = SettlementBackend.from_env()
    assert b.vault is not None
    assert b.describe()["vault_attached"] is True


def test_an_unfunded_vault_refuses_rather_than_inventing_money(monkeypatch, tmp_path):
    monkeypatch.setenv("MOMUS_UNI_VAULT_PATH", str(tmp_path / "vault.jsonl"))
    b = SettlementBackend.from_env()
    d = b.settle_share(finding_id="mom-1", role="finder", recipient="0xr", amount_usd=50.0)
    assert d.settled is False and "refused" in d.reason


def test_a_funded_vault_pays_and_drains(monkeypatch, tmp_path):
    monkeypatch.setenv("MOMUS_UNI_VAULT_PATH", str(tmp_path / "vault.jsonl"))
    b = SettlementBackend.from_env()
    b.vault.fund(100.0)
    b.vault.reserve("mom-1", 50.0)
    d = b.settle_share(finding_id="mom-1", role="finder", recipient="0xr", amount_usd=50.0)
    assert d.settled is True and b.vault.balance == pytest.approx(50.0)


def test_from_env_wires_a_ledger_path(monkeypatch, tmp_path):
    """The shipped service used to pass neither a ledger nor a vault, so the UNI tier wrote nothing
    and checked nothing."""
    monkeypatch.setenv("MOMUS_DATA_DIR", str(tmp_path))
    b = SettlementBackend.from_env()
    assert b._uni_path is not None and str(tmp_path) in str(b._uni_path)


# ─────────────────────────────────────────────────────────────────── the status surface


def test_describe_tells_the_operator_which_rail_and_why():
    d = SettlementBackend.from_env().describe()
    assert d["reward_fallback"] == FALLBACK_SANDBOX
    assert d["reward_fallback_reason"]
    assert d["moves_real_value"] is False
    assert d["gates_security"] is False


# ═══════════════════════════════════════════════════ THE INVARIANT ═══════════════════
#
# "A system with crypto off must not become less secure."
#


#: Every module on the scan -> verify -> ticket -> gate path. Deliberately exhaustive: a guard test
#: that skips a file it cannot find is a hole, and the first version of this list said
#: "engine/scan.py" (the file is engine/scanner.py) and silently skipped it.
#:
#: engine/selfaudit.py is NOT here and must not be added: it imports the economics layer because it
#: AUDITS the payout gate. It is a test of the money path, not a consumer of it.
SECURITY_PATH = [
    "a2a.py",                  # the remediation ticket hand-off
    "security.py",             # prompt/response hardening
    "findings.py",             # the signed document
    "warden_feed.py",
    "engine/scanner.py",
    "engine/verify.py",
    "engine/cross_check.py",
    "engine/remediation.py",
    "targets/base.py",
    "targets/hub.py",
    "targets/oracle.py",
    "targets/injection.py",
]

#: `momus.economics` is intentionally absent: engine/remediation.py imports _INFRA_COMPONENTS from
#: it, which is a ROUTING constant (which components escalate to a human), not a balance. What must
#: never reach the security path is anything that knows how much money there is.
MONEY_MODULES = {"momus.settlement", "momus.vault", "momus.bounty", "momus.budget"}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


@pytest.mark.parametrize("rel", SECURITY_PATH)
def test_the_security_path_cannot_import_the_money_modules(rel):
    """The structural half of the invariant. A module that cannot import a balance cannot be gated
    by one — this is what makes 'crypto off is not less secure' a property rather than a promise."""
    path = MOMUS_PKG / rel
    assert path.is_file(), f"{rel} is missing — fix the list rather than letting the guard skip"
    leaked = _imports(path) & MONEY_MODULES
    assert not leaked, f"{rel} imports {leaked} — the security path must not depend on the money path"


RAILS = [
    ("crypto off", dict(crypto_enabled=False), {}),
    ("crypto on, no bounty opt-in", dict(crypto_enabled=True),
     {"MOMUS_SETTLEMENT": "base", "MOMUS_BOUNTY_SPLITTER": SPLITTER}),
    ("crypto on, unfunded base rail", dict(crypto_enabled=True),
     {"MOMUS_SETTLEMENT": "base", "MOMUS_BOUNTY_ONCHAIN": "1", "MOMUS_BOUNTY_SPLITTER": SPLITTER}),
    ("crypto on, fallback disabled", dict(crypto_enabled=True),
     {"MOMUS_SETTLEMENT": "base", "MOMUS_BOUNTY_ONCHAIN": "1", "MOMUS_BOUNTY_SPLITTER": SPLITTER,
      "MOMUS_REWARD_FALLBACK": "held"}),
]


def _judge(tmp_path, scanner, verifiers, monkeypatch, env, gate_kw, name):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    kr = KeyRing(str(tmp_path / f"s-{name}.key"), str(tmp_path / f"t-{name}.key"))
    gate = PayoutGate(kr, BountyLedger(str(tmp_path / f"l-{name}.jsonl")), prod=False, cooldown_s=0,
                      external_verifiers={verifiers[0].pubkey}, **gate_kw)
    f = _finding(scanner, "high")
    return gate.authorize(f, [_confirm(v, f) for v in verifiers], deposit_posted_usd=25)


@pytest.mark.parametrize("name,gate_kw,env", RAILS)
def test_a_well_verified_finding_is_never_refused_because_of_the_rail(
    tmp_path, scanner, verifier_a, verifier_b, monkeypatch, name, gate_kw, env
):
    """Behavioural half. The rail decides how a share is PAID, never whether the security gates
    passed. A finding with two independent confirmations clears the gates on every rail."""
    dec = _judge(tmp_path, scanner, [verifier_a, verifier_b], monkeypatch, env, gate_kw, name)
    assert dec.state != PayoutState.REFUSED.value, f"rail {name!r} refused a well-verified finding"


@pytest.mark.parametrize("name,gate_kw,env", RAILS)
def test_an_under_verified_finding_is_refused_identically_on_every_rail(
    tmp_path, scanner, verifier_a, monkeypatch, name, gate_kw, env
):
    """The other direction, which matters more: a rail must not let a WEAKER claim through. One
    verifier is not enough for HIGH, on any rail, with crypto on or off."""
    dec = _judge(tmp_path, scanner, [verifier_a], monkeypatch, env, gate_kw, name)
    assert dec.state == PayoutState.REFUSED.value, f"rail {name!r} paid an under-verified finding"
