"""The five locales of the self-healing runbook must document the SAME thing.

A runbook is load-bearing: every row in it is a variable that turns some refusal on or off. A
translation that silently loses one is worse than no translation, because a reader who finds the page
in their own language reasonably assumes it is complete. So the parity is a test, not a habit.

Deliberately checks the *keys* rather than the prose: the variable names, the section count and the
navigation links. Prose is expected to differ; the contract is not.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parent.parent / "docs"
LOCALES = ("ru", "es", "fr", "zh")
#: Both five-language documents in this set. The runbook says how to operate the loop; the case study
#: records the run that proved it. Losing a variable from one or a diagram from the other are the same
#: class of failure: a reader who finds the page in their language assumes it is complete.
DOC_STEMS = ("self-healing-operations", "first-self-heal")
CANON = DOCS / "self-healing-operations.md"


def _vars(text: str) -> set[str]:
    return set(re.findall(r"`(AIFACTORY_[A-Z_]+|SKOPOS_[A-Z_]+)`", text))


def _sections(text: str) -> int:
    return len(re.findall(r"^## ", text, re.M))


@pytest.fixture(scope="module")
def canon() -> str:
    assert CANON.is_file(), f"the canonical English runbook is missing: {CANON}"
    return CANON.read_text(encoding="utf-8")


@pytest.mark.parametrize("locale", LOCALES)
def test_the_translation_exists(locale):
    assert (DOCS / f"self-healing-operations.{locale}.md").is_file()


@pytest.mark.parametrize("locale", LOCALES)
def test_every_locale_documents_the_same_variables(locale, canon):
    """The one that matters. A missing variable is a refusal the reader will not know exists."""
    text = (DOCS / f"self-healing-operations.{locale}.md").read_text(encoding="utf-8")
    expected, got = _vars(canon), _vars(text)
    assert not (expected - got), f"{locale} is missing: {sorted(expected - got)}"
    assert not (got - expected), f"{locale} documents variables the English page does not: " \
                                 f"{sorted(got - expected)}"


@pytest.mark.parametrize("locale", LOCALES)
def test_every_locale_has_the_same_sections(locale, canon):
    text = (DOCS / f"self-healing-operations.{locale}.md").read_text(encoding="utf-8")
    assert _sections(text) == _sections(canon), \
        f"{locale} has {_sections(text)} sections, English has {_sections(canon)}"


@pytest.mark.parametrize("locale", LOCALES)
def test_every_locale_links_to_all_the_others(locale):
    """A reader who lands on the wrong language must be one click from theirs."""
    text = (DOCS / f"self-healing-operations.{locale}.md").read_text(encoding="utf-8")
    assert "self-healing-operations.md" in text, f"{locale} does not link back to English"
    for other in LOCALES:
        if other == locale:
            continue
        assert f"self-healing-operations.{other}.md" in text, \
            f"{locale} does not link to {other}"


def test_the_canonical_page_links_to_every_translation(canon):
    for locale in LOCALES:
        assert f"self-healing-operations.{locale}.md" in canon, \
            f"English does not link to {locale}"


@pytest.mark.parametrize("locale", ("md",) + LOCALES)
def test_the_redeploy_answer_is_present_everywhere(locale):
    """The question that prompted the page: changing remediation code redeploys ONE service, because
    the public factory does not mount the route at all. Every locale has to carry that answer."""
    name = "self-healing-operations.md" if locale == "md" else f"self-healing-operations.{locale}.md"
    text = (DOCS / name).read_text(encoding="utf-8")
    assert "AIFACTORY_REMEDIATION_FIX_ENABLED" in text
    assert "next.config.js" in text, \
        f"{locale} omits WHY a merely-disabled route would still be publicly reachable"


# ── the case study, and its diagrams ──────────────────────────────────────────
CASE = "first-self-heal"


def _path(stem: str, locale: str | None) -> Path:
    return DOCS / (f"{stem}.md" if locale is None else f"{stem}.{locale}.md")


def _mermaid_blocks(text: str) -> list[str]:
    out, inside, buf = [], False, []
    for line in text.splitlines():
        if line.strip() == "```mermaid":
            inside, buf = True, []
            continue
        if inside and line.strip() == "```":
            out.append("\n".join(buf))
            inside = False
            continue
        if inside:
            buf.append(line)
    return out


@pytest.mark.parametrize("locale", (None,) + LOCALES)
def test_the_case_study_exists_in_every_language(locale):
    assert _path(CASE, locale).is_file()


@pytest.mark.parametrize("locale", LOCALES)
def test_the_case_study_carries_the_same_diagrams(locale):
    """A translation that drops a diagram drops the explanation, not the decoration."""
    canon = _mermaid_blocks(_path(CASE, None).read_text(encoding="utf-8"))
    got = _mermaid_blocks(_path(CASE, locale).read_text(encoding="utf-8"))
    assert len(got) == len(canon) == 2, f"{locale}: {len(got)} mermaid blocks, English has {len(canon)}"
    # Same diagram KINDS in the same order — prose inside them is expected to differ.
    for i, (a, b) in enumerate(zip(canon, got)):
        assert a.strip().split()[0] == b.strip().split()[0], \
            f"{locale}: diagram {i} is a {b.strip().split()[0]}, English has {a.strip().split()[0]}"


@pytest.mark.parametrize("locale", (None,) + LOCALES)
def test_the_sequence_diagram_is_structurally_sound(locale):
    """A mermaid syntax error does not degrade — it renders nothing at all, in every locale that
    copied it. So: every arrow must reference a declared participant."""
    blocks = _mermaid_blocks(_path(CASE, locale).read_text(encoding="utf-8"))
    seq = next(b for b in blocks if b.strip().startswith("sequenceDiagram"))
    ids = set(re.findall(r"participant (\w+) as", seq))
    assert len(ids) == 6, f"{locale}: {len(ids)} participants declared"
    arrows = re.findall(r"^\s*(\w+)\s*-(?:->)?>>?\s*(\w+)\s*:", seq, re.M)
    assert arrows, f"{locale}: no messages in the sequence diagram"
    for src, dst in arrows:
        assert src in ids, f"{locale}: message from undeclared participant {src!r}"
        assert dst in ids, f"{locale}: message to undeclared participant {dst!r}"


@pytest.mark.parametrize("locale", (None,) + LOCALES)
def test_the_load_bearing_facts_appear_in_every_language(locale):
    """The identifiers a reader would use to check the claim themselves. A case study that cannot be
    verified from its own text is a press release."""
    text = _path(CASE, locale).read_text(encoding="utf-8")
    for fact in ("mom-31eb7bc4971644ba",            # the finding
                 "3fc44790",                        # the commit that was built
                 "sha256:2b5bcf23",                 # the digest that was promoted
                 "sha256:272146c4",                 # the rollback target
                 "gated=candidate", "gated=live",   # the two gates
                 "402",                             # the behaviour that proves the fix
                 "pull_momus_fixes.sh"):            # the validator the sidecar satisfies
        assert fact in text, f"{locale} omits {fact!r}"


@pytest.mark.parametrize("locale", (None,) + LOCALES)
def test_the_case_study_states_its_own_limits(locale):
    """It must keep saying what it does NOT prove, in every language — the fixture, the one-service
    allowlist, and that a `fixed` verdict is not a judgement on the patch."""
    text = _path(CASE, locale).read_text(encoding="utf-8")
    assert "escalation_for" in text, f"{locale} omits the security-core carve-out"
    assert "canary" in text
    assert text.count("fix-provenance") >= 1, f"{locale} does not point at the merge policy"


def test_found_and_fixed_no_longer_claims_it_never_happened():
    """That page's central claim was retired by this run. A prominent, load-bearing, now-false
    statement is the worst kind of stale doc, so all five copies must have moved on."""
    for locale in (None,) + LOCALES:
        text = _path("found-and-fixed", locale).read_text(encoding="utf-8")
        assert "first-self-heal" in text, f"found-and-fixed[{locale}] does not link the run"
        for stale in ("has never autonomously authored", "ни разу не написала автономно",
                      "nunca ha escrito de forma autónoma", "n'a jamais écrit de façon autonome",
                      "从来没有自主写出过"):
            assert stale not in text, f"found-and-fixed[{locale}] still claims it never happened"
