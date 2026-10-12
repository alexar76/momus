"""Independent verification — turns a raw Finding into a signed Verdict.

The whole payout model rests on a verdict coming from a key that is NOT the scanner and NOT the
treasury. Two independent verifier sources are supported:

* ``metis`` — route the finding to an external Metis ``/v1/verify`` endpoint and let its
  cognitive stack judge whether the described contract violation reproduces. Metis signs with
  its own key, so the verdict is genuinely independent of MOMUS.
* ``replay`` — re-execute the finding's probe from a SECOND MOMUS instance that holds a DIFFERENT
  verifier key (a distinct principal / second box). Deterministic contract probes (signature
  integrity, ceiling enforcement) reproduce exactly, which is what makes them safe to auto-verify.

A ``Verifier`` holds exactly one verifier key and signs verdicts with it. The economics layer
independently checks that this key differs from the scanner and treasury keys — a verifier that
lies about its own independence still cannot satisfy the gate, because the gate compares the
actual public keys, not the verifier's say-so.
"""

from __future__ import annotations

from typing import Any

from dataclasses import dataclass

import re

import httpx

from momus.findings import Finding, FindingSigner, Verdict, finding_digest


#: Probe categories where a language model reading the evidence is the WRONG instrument.
#:
#: A deterministic contract probe has a ground truth: run it and the answer is the same every
#: time. Asking a model whether a signature verifies, from a description of the response, is
#: asking for an opinion about a fact — and it produced exactly the failure you would expect.
#: Measured on the live canary: the manifest signature genuinely does NOT verify, and the
#: judge returned "does_not_reproduce" with 0.92 confidence.
#:
#: A false refutation is harmless today, because only a CONFIRMED verdict moves the dispatch
#: bar. A false confirmation would not be. So for these categories the judgement is recorded
#: for a human to read and is never allowed to count.
_DETERMINISTIC_CATEGORIES = frozenset({
    "integrity",     # signatures, digests, canonical forms — verifiable by running the check
    "settlement",    # on-chain and ledger facts
    "replay",        # nonce and idempotency behaviour
    "authz",         # a ceiling either holds or it does not
})


def _model_can_judge(finding: Finding) -> bool:
    """Is a language model the right instrument for this probe?

    Yes for anything whose answer is a judgement (is this output harmful, is this prompt
    injection, is this claim plausible). No for anything with a ground truth a re-run would
    settle — for those the right verifier is a second principal running the probe, which is
    what `verify_via_replay` is for and what MOMUS_EXTERNAL_VERIFIERS exists to trust.
    """
    return str(getattr(finding, "category", "") or "").lower() not in _DETERMINISTIC_CATEGORIES


@dataclass
class ReplaySubject:
    """What a replaying instance needs, and nothing it has no business holding.

    A second principal asked to re-run a probe does not need the original signed document —
    it needs to know which target, which probe, which bug, and the digest of the observation
    it is being asked about. Shipping the whole finding would hand a redacted-tier reader the
    evidence the disclosure rule withholds.
    """

    finding_id: str
    finding_digest: str
    target: str
    probe: str
    category: str = ""
    severity: str = ""


class Verifier:
    def __init__(self, signer: FindingSigner, verifier_id: str):
        self._signer = signer
        self.verifier_id = verifier_id

    @property
    def pubkey(self) -> str:
        return self._signer.pubkey

    def _verdict(self, finding: Finding | ReplaySubject, verdict: str, method: str, score: float,
                 rationale: str, finding_id: str | None = None) -> Verdict:
        """`finding_id` overrides which BUG this verdict is about.

        A rediscovery mints a fresh id for the observation while the corpus keeps the first
        one as the bug's identity. A verdict filed under the observation's id is invisible to
        every reader that looks the bug up — which is how three real verdicts sat in the table
        while every projection reported none. The digest still covers the exact observation
        that was judged, so the two fields say different, true things: which bug, and which
        sighting of it.
        """
        # A replay is asked to re-run a probe, not handed the signed document, so its subject
        # carries the digest it was asked about rather than one this instance can recompute.
        digest = getattr(finding, "finding_digest", None) or finding_digest(finding)
        v = Verdict(
            finding_id=finding_id or finding.finding_id,
            finding_digest=digest,
            verdict=verdict, method=method, score=score, rationale=rationale,
            verifier_id=self.verifier_id,
            # Both Finding and ReplaySubject carry these, so every verdict path records the
            # subject it judged rather than only the claim it was asked about.
            subject_target=str(getattr(finding, "target", "") or ""),
            subject_probe=str(getattr(finding, "probe", "") or ""),
        )
        return self._signer.sign_verdict(v)

    async def verify_via_metis(self, finding: Finding, metis_url: str,
                               *, timeout_s: float = 30.0, api_key: str = "",
                               route: str = "thinking", finding_id: str | None = None) -> Verdict:
        """Ask an external Metis to judge the finding. Metis returning an error or being
        unreachable yields an ``inconclusive`` verdict — never a false ``confirmed``.

        That safety property has a failure mode of its own: a misconfiguration is
        indistinguishable from a target that behaves. The first live run of this verifier
        answered 401 on every finding and dutifully recorded "inconclusive — Metis
        unreachable", which is honest and completely silent. So the reason names the status.
        """
        if not _model_can_judge(finding):
            return self._verdict(
                finding, "inconclusive", "metis:/v1/verify (out of scope)", 0.0,
                f"'{finding.category}' is a deterministic contract probe: it has a ground "
                f"truth a re-run would settle, and a model reading a description of the "
                f"response is the wrong instrument. Verify it by replay from a second "
                f"principal.", finding_id=finding_id)
        prompt = _finding_to_verify_input(finding)
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        try:
            async with httpx.AsyncClient(timeout=timeout_s) as client:
                # The route matters. Unset, Metis falls to its configured default, which is
                # the full council — minutes of deliberation for a question that is "does this
                # evidence show a violation". The first live attempt read-timed-out for exactly
                # that reason. Judging evidence is a reasoning task, not a research one.
                r = await client.post(metis_url.rstrip("/") + "/v1/verify",
                                      json={"input": prompt, "route": route}, headers=headers)
                r.raise_for_status()
                data = r.json()
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            hint = " (no MOMUS_VERIFIER_METIS_KEY set?)" if code in (401, 403) and not api_key else ""
            return self._verdict(finding, "inconclusive", "metis:/v1/verify", 0.0,
                                 f"Metis refused the request: HTTP {code}{hint}", finding_id=finding_id)
        except (httpx.HTTPError, ValueError) as exc:
            return self._verdict(finding, "inconclusive", "metis:/v1/verify", 0.0,
                                 f"Metis unreachable/error: {type(exc).__name__}",
                                 finding_id=finding_id)
        # Read what the judge SAID, not whether it said it well.
        #
        # `data["verified"]` is Metis reporting that its own generated answer passed its own
        # delivery critic. It is not a statement about the finding. Reading it as one turned
        # the judge into a rubber stamp: any well-formed reply became "confirmed", including
        # a reply whose text said the finding does not reproduce. The Playground learned this
        # the same way and requires an explicit label from the answer for exactly this reason.
        score = _read_score(data)
        well_formed = bool(data.get("verified")) if isinstance(data, dict) else False
        stated = _stated_verdict(data)

        if stated == "reproduces":
            # The critic's opinion of the answer's quality is a secondary gate, never the
            # verdict itself: a confident judgement delivered badly is still a judgement,
            # but it should not carry a confident score.
            confidence = max(score, 0.6) if well_formed else min(max(score, 0.5), 0.6)
            return self._verdict(finding, "confirmed", "metis:/v1/verify", confidence,
                                 "Metis judged the evidence and stated the finding reproduces.", finding_id=finding_id)
        if stated == "does_not_reproduce":
            return self._verdict(finding, "refuted", "metis:/v1/verify", max(score, 0.6),
                                 "Metis judged the evidence and stated it shows no violation.",
                                 finding_id=finding_id)
        if stated == "unclear":
            return self._verdict(finding, "inconclusive", "metis:/v1/verify", 0.0,
                                 "Metis judged the evidence insufficient to decide.", finding_id=finding_id)
        # No label at all. The judge answered something, but not the question it was asked —
        # and an unlabelled answer is precisely what used to be scored as agreement.
        return self._verdict(finding, "inconclusive", "metis:/v1/verify", 0.0,
            "Metis returned no VERDICT line; an unlabelled answer is not a judgement.", finding_id=finding_id)

    def verify_via_replay(self, finding: Finding | ReplaySubject, *, reproduced: bool,
                          detail: str = "", finding_id: str | None = None) -> Verdict:
        """Record a verdict from a deterministic re-run done by a distinct verifier principal.

        The caller (a second MOMUS instance with its own key) re-ran the exact probe and reports
        whether the contract violation reproduced. Because the probe is deterministic, this is a
        strong, cheap independent confirmation — as long as the key really is a different one,
        which the economics gate verifies."""
        if reproduced:
            return self._verdict(finding, "confirmed", "replay", 0.95,
                                 detail or "Deterministic probe re-ran on an independent instance and reproduced.",
                                 finding_id=finding_id)
        return self._verdict(finding, "refuted", "replay", 0.9,
                             detail or "Deterministic probe did not reproduce on an independent instance.",
                             finding_id=finding_id)


#: How much of a snippet to hand the verifier. Evidence snippets are already redacted at
#: capture; this bounds a pathological one rather than trusting it to be short.
_SNIPPET_LIMIT = 2000


def _finding_to_verify_input(finding: Finding) -> str:
    """Everything the verifier needs to reach its OWN conclusion.

    This used to send eight lines of prose with the observable removed — no digests, and
    neither snippet, including ``response_snippet``, which is the acceptance criterion the
    rest of the loop treats as load-bearing. A verifier asked "is this real?" about a
    description of a response it was not shown is not verifying anything; it is agreeing.

    The verdict this produces is the one the payout model and the dispatch policy rest on,
    so the evidence goes with the question.
    """
    ev = finding.evidence
    lines = [
        "A red-team probe reports a contract violation. Decide whether it is real and reproduces.",
        "Judge the EVIDENCE below, not the claim. If the observed response does not actually",
        "violate the stated contract, say so — a false 'confirmed' costs more than a miss.",
        "",
        f"Target: {finding.target} ({finding.target_kind})",
        f"Probe: {finding.probe} / {finding.category}",
        f"Severity claimed: {finding.severity}",
        f"Title: {finding.title}",
        f"Detail: {finding.detail}",
        f"Reproducer: {ev.reproducer}",
        f"Observed status: {ev.status_code}",
        f"Request digest: {ev.request_digest}",
        f"Response digest: {ev.response_digest}",
    ]
    if ev.request_snippet:
        lines += ["", "REQUEST (redacted at capture):", ev.request_snippet[:_SNIPPET_LIMIT]]
    if ev.response_snippet:
        # The acceptance criterion. Withheld from the public disclosure tier, and the reason
        # this function has to be given the finding rather than its public projection.
        lines += ["", "RESPONSE — this is the acceptance criterion:",
                  ev.response_snippet[:_SNIPPET_LIMIT]]
    else:
        lines += ["", "NOTE: this finding carries no response snippet. Without the observed",
                  "response there is no evidence to judge — prefer 'inconclusive' over a guess."]
    lines += [
        "",
        "Answer with this line FIRST, exactly, then your reasoning:",
        "  VERDICT: reproduces      — the evidence shows the stated contract IS violated",
        "  VERDICT: does_not_reproduce — the evidence does not show a violation",
        "  VERDICT: unclear         — the evidence is insufficient to decide",
    ]
    return "\n".join(lines)


#: The verdict line the judge is asked for. Anchored to a line start so a verdict quoted
#: inside prose ("the probe claims VERDICT: reproduces") is not mistaken for the answer.
_VERDICT_LINE = re.compile(r"(?im)^\s*VERDICT\s*:\s*(reproduces|does_not_reproduce|unclear)\b")


def _stated_verdict(data: Any) -> str:
    """What the judge actually said — "", "reproduces", "does_not_reproduce" or "unclear"."""
    if not isinstance(data, dict):
        return ""
    for key in ("answer", "content", "output", "text"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            match = _VERDICT_LINE.search(value)
            if match:
                return match.group(1).lower()
    return ""


def _read_score(data: Any) -> float:
    if not isinstance(data, dict):
        return 0.0
    for key in ("verify_score", "score", "confidence"):
        v = data.get(key)
        if isinstance(v, (int, float)):
            return max(0.0, min(1.0, float(v)))
    # Some Metis envelopes nest under "verdict"/"result".
    for key in ("verdict", "result", "output"):
        inner = data.get(key)
        if isinstance(inner, dict):
            s = _read_score(inner)
            if s:
                return s
    return 0.0
