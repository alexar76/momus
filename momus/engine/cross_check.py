"""Check a signature probe's answer against a SECOND implementation of the contract.

A replay by a second instance proves the finding is not a flake and not a fabrication by the
instance that reported it. It cannot prove the probe is asking the right question: both
instances run the same probe code, so they share its mistakes and agree confidently on them.

That is not hypothetical here. ``manifest_canonical`` has eight independent implementations in
this tree, and one of them has already taken the whole federation down once — the hub added a
fifth field, the oracle copy did not follow, and every oracle manifest failed verification. A
probe computing the wrong canonical form would fail every CORRECT signature, and a replay
would confirm it twice.

So the verifier computes the canonical form a second way, using the protocol's own conformance
reference — written for the spec, not copied from ``oracle_core`` — and reports what it finds:

* both implementations agree the signature fails  → the finding stands, and now on two
  independent readings of the contract;
* both agree it verifies                          → the probe is wrong, not the target;
* the two disagree about the canonical string     → the implementations have drifted, which is
  a defect in its own right and makes the probe's verdict untrustworthy either way.

The reference is loaded from a path, not imported as a package, because it is a conformance
script rather than a library. If it is absent the cross-check reports "unavailable" and the
replay verdict stands on its own — degraded, and saying so.
"""

from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass
from typing import Any, Callable

#: Where the protocol's conformance reference lives inside the image. Overridable so a
#: developer running outside a container can point at the checkout.
REFERENCE_PATH = os.environ.get(
    "MOMUS_PROTOCOL_REFERENCE", "/app/protocol-conformance/run.py")

_reference: Any | None = None
_reference_error: str = ""


def _load_reference() -> Any | None:
    """Import the conformance script once, by path. Returns None if it is not there."""
    global _reference, _reference_error
    if _reference is not None or _reference_error:
        return _reference
    path = REFERENCE_PATH
    if not os.path.isfile(path):
        _reference_error = f"protocol reference not found at {path}"
        return None
    try:
        spec = importlib.util.spec_from_file_location("aimarket_protocol_reference", path)
        if spec is None or spec.loader is None:
            _reference_error = "protocol reference could not be loaded"
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 - a broken reference must not break a scan
        _reference_error = f"protocol reference failed to load: {type(exc).__name__}"
        return None
    if not callable(getattr(module, "manifest_canonical", None)):
        _reference_error = "protocol reference has no manifest_canonical"
        return None
    _reference = module
    return _reference


@dataclass
class CrossCheck:
    """What a second implementation says about the same manifest."""

    available: bool
    #: Do the two implementations produce the same canonical string?
    canonical_agrees: bool = False
    #: Does the signature verify under the REFERENCE's canonical form?
    reference_verifies: bool | None = None
    #: Does it verify under the probe's own canonical form?
    probe_verifies: bool | None = None
    detail: str = ""

    @property
    def supports_the_finding(self) -> bool:
        """Both implementations agree the signature does not verify."""
        return (self.available and self.canonical_agrees
                and self.reference_verifies is False and self.probe_verifies is False)

    @property
    def contradicts_the_finding(self) -> bool:
        """The reference says the signature is fine — so the probe, not the target, is wrong."""
        return self.available and self.reference_verifies is True


def cross_check_manifest(manifest: dict, probe_canonical: Callable[[dict], str],
                         verify: Callable[[str, str, str], bool]) -> CrossCheck:
    """Recompute and re-verify a manifest signature with the protocol's own reference.

    ``probe_canonical`` and ``verify`` come from the probe's implementation, so this compares
    two readings of one contract rather than re-running one reading twice.
    """
    module = _load_reference()
    if module is None:
        return CrossCheck(available=False, detail=_reference_error)

    sig = manifest.get("signature") or {}
    value = str(sig.get("value") or "")
    pubkey = str(sig.get("public_key") or sig.get("pubkey") or "")
    if not value or not pubkey:
        return CrossCheck(available=False,
                          detail="manifest carries no signature value or public key")

    try:
        ours = probe_canonical(manifest)
        theirs = module.manifest_canonical(manifest)
    except Exception as exc:  # noqa: BLE001
        return CrossCheck(available=False,
                          detail=f"canonical form could not be computed: {type(exc).__name__}")

    agrees = str(ours) == str(theirs)
    try:
        probe_ok = bool(verify(str(ours), value, pubkey))
        ref_ok = bool(verify(str(theirs), value, pubkey))
    except Exception as exc:  # noqa: BLE001
        return CrossCheck(available=True, canonical_agrees=agrees,
                          detail=f"verification raised: {type(exc).__name__}")

    if not agrees:
        detail = ("the probe's canonical form and the protocol reference DISAGREE — the "
                  "implementations have drifted, so this probe's verdict cannot be trusted "
                  "in either direction")
    elif ref_ok:
        detail = ("the signature verifies under the protocol reference: the probe is wrong, "
                  "not the target")
    else:
        detail = ("two independent implementations of the canonical form both reject this "
                  "signature")
    return CrossCheck(available=True, canonical_agrees=agrees,
                      reference_verifies=ref_ok, probe_verifies=probe_ok, detail=detail)
