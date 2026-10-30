#!/usr/bin/env python3
"""AIMarket Protocol conformance runner.

Two modes, and they answer different questions:

    python3 conformance/run.py                      # vectors only — is my crypto right?
    python3 conformance/run.py --hub https://host   # + live checks against a running hub

What this proves, stated honestly: that an implementation agrees with the normative test
vectors and that a live hub's discovery surface matches the specification. It does not
prove the hub behaves correctly under payment, load or adversarial peers. Passing is
necessary, not sufficient — see GOVERNANCE.md § Conformance.

Exit code 0 when every check passes, 1 otherwise. No output is written anywhere.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTORS = ROOT / "test-vectors"
NEGATIVE = VECTORS / "negative"
TEST_PUBKEY_B64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"
if not sys.stdout.isatty():
    GREEN = RED = YELLOW = DIM = RESET = ""

results: list[tuple[bool, str, str]] = []


# Ed25519 points of small order (orders 1, 2, 4, 8; sign bit cleared), as libsodium checks them.
# `cryptography` (OpenSSL) accepts, under such a key, a signature valid for EVERY message, and no
# secret exists for these keys — so a key or R among them is refused before verifying. 2026-10-12.
_ED25519_SMALL_ORDER = frozenset(bytes.fromhex(h) for h in (
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
))


def _ed25519_small_order(point: bytes) -> bool:
    return len(point) == 32 and (point[:31] + bytes([point[31] & 0x7F])) in _ED25519_SMALL_ORDER


def record(ok: bool, name: str, detail: str = "") -> None:
    results.append((ok, name, detail))
    mark = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    print(f"  {mark}  {name}" + (f"  {DIM}{detail}{RESET}" if detail else ""))


def skip(name: str, why: str) -> None:
    print(f"  {YELLOW}SKIP{RESET}  {name}  {DIM}{why}{RESET}")


SIGNATURE_OBJECT_SHAPE = '{"algorithm": "ed25519", "public_key": "<base64>", "value": "<base64>"}'
_JSON_TYPE_NAMES = {str: "a string", list: "an array", bool: "a boolean", int: "a number",
                    float: "a number", type(None): "null"}


def signature_shape_problem(sig) -> str:
    """Why `sig` is not a §7.3.1 signature OBJECT, or "" when it is one.

    Both independent implementations that knocked on modelmarket.dev in October 2026 published
    the base64 signature as a bare string, and this runner answered them with
    "'str' object has no attribute 'get'". The shape is the implementer's to fix, so say how.
    """
    if isinstance(sig, dict):
        value = sig.get("value")
        if not isinstance(value, str) or not value.strip():
            return 'the signature object has no "value" string (§7.3.1)'
        return ""
    kind = _JSON_TYPE_NAMES.get(type(sig), "not an object")
    return (f"signature is {kind}, not an object (§7.3.1): publish {SIGNATURE_OBJECT_SHAPE}, "
            f"with the base64 Ed25519 signature in value")


# ── crypto ──────────────────────────────────────────────────────────

def _verifier():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return None

    def verify(pub_b64: str, canonical: str, sig_b64: str) -> bool:
        try:
            key, sig = base64.b64decode(pub_b64), base64.b64decode(sig_b64)
            if _ed25519_small_order(key) or _ed25519_small_order(sig[:32]):
                return False
            Ed25519PublicKey.from_public_bytes(key).verify(sig, canonical.encode())
            return True
        except Exception:
            return False

    return verify


def digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


def manifest_canonical(m: dict) -> str:
    return (
        f"capabilities_count:{m.get('capabilities_count', 0)}"
        f"|generated_at:{m.get('generated_at', '')}"
        f"|protocol_version:{m.get('protocol_version', 'v1')}"
        f"|tools_hash:{digest(m.get('tools', []))}"
        f"|by_hub_hash:{digest(m.get('by_hub', {}))}"
    )


# Fields only the v2 canonical binds. A receipt carrying any of them requires v2.
RECEIPT_V2_FIELDS = (
    "type", "channel_id", "category", "plugin", "reason", "verify_score",
    "delivery_reasons", "trace_id", "refunded",
)


def fields_digest(obj: dict, names: tuple[str, ...]) -> str:
    """Compact separators here, unlike the manifest digests — see spec §7.3.1."""
    payload = {name: obj.get(name) for name in names}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False,
                   separators=(",", ":"), default=str).encode()
    ).hexdigest()


def required_receipt_version(r: dict) -> int:
    return 2 if any(name in r for name in RECEIPT_V2_FIELDS) else 1


def signed_receipt_version(r: dict) -> int:
    sig = r.get("signature")
    if not isinstance(sig, dict) or not sig.get("value"):
        return 0
    try:
        version = int(sig.get("version", 1))
    except (TypeError, ValueError):
        return 0
    return version if version >= 1 else 0


def receipt_canonical(r: dict, version: int | None = None) -> str:
    base = (
        f"nonce:{r.get('nonce', '')}"
        f"|product_id:{r.get('product_id', '')}"
        f"|capability_id:{r.get('capability_id', '')}"
        f"|price_usd:{r.get('price_usd', 0)}"
        f"|timestamp:{r.get('timestamp', '')}"
        f"|success:{1 if r.get('success') else 0}"
        f"|latency_ms:{r.get('latency_ms', 0)}"
    )
    if version is None:
        version = signed_receipt_version(r) or 1
    if version < 2:
        return base
    return f"{base}|v:2|fields:{fields_digest(r, RECEIPT_V2_FIELDS)}"


def announce_canonical(a: dict) -> str:
    return (
        f"hub_url:{a.get('hub_url', '')}"
        f"|well_known_url:{a.get('well_known_url', '')}"
        f"|capabilities_count:{a.get('capabilities_count', 0)}"
    )


CANONICALS = {
    "manifest": manifest_canonical,
    "receipt": receipt_canonical,
    "announce": announce_canonical,
}


def kind_of(filename: str) -> str | None:
    if filename.startswith("manifest"):
        return "manifest"
    if filename.startswith("receipt"):
        return "receipt"
    if filename.startswith("announce") or filename.startswith("federation-announce"):
        return "announce"
    return None


# ── vector checks ───────────────────────────────────────────────────

def hybrid_verifier(verify):
    """§7.3.8 policy over `verify` (Ed25519, §7.3.7 included). None without dilithium-py."""
    try:
        from dilithium_py.ml_dsa import ML_DSA_65
    except ImportError:
        return None

    def check(sig: dict, canonical: str, pins: dict, require_pq: bool = False) -> bool:
        if not verify(pins.get("ed25519", ""), canonical, sig.get("value", "")):
            return False                                         # rule 1
        if not sig.get("pq_value"):
            return not require_pq                                # rules 2 and 5
        if sig.get("pq_algorithm") != "ml-dsa-65":
            return False
        pinned = pins.get("ml-dsa-65")
        if pinned and sig.get("pq_public_key") != pinned:
            return False                                         # rule 4
        try:
            return bool(ML_DSA_65.verify(base64.b64decode(sig.get("pq_public_key", "")),
                                         canonical.encode(), base64.b64decode(sig["pq_value"])))
        except Exception:
            return False                                         # rule 3, fail closed

    return check


def check_positive_vectors(verify) -> None:
    print("\nPositive vectors — these MUST verify")
    for name in ("manifest-signed.json", "receipt-signed.json", "receipt-v2-signed.json",
                 "federation-announce-signed.json", "receipt-hybrid-signed.json"):
        path = VECTORS / name
        if not path.exists():
            record(False, name, "file missing")
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        kind = kind_of(name)
        sig = (doc.get("signature") or {}).get("value", "")
        ok = bool(sig) and verify(TEST_PUBKEY_B64, CANONICALS[kind](doc), sig)
        record(ok, name, "" if ok else "signature did not verify against the documented canonical")
        if (doc.get("signature") or {}).get("pq_value"):
            hybrid = hybrid_verifier(verify)
            if hybrid is None:
                skip(f"{name} — ML-DSA-65 half", "dilithium-py not installed")
            else:
                hok = hybrid(doc["signature"], CANONICALS[kind](doc), doc.get("_pins", {}), require_pq=True)
                record(hok, f"{name} — hybrid (§7.3.8)", "" if hok else "ML-DSA-65 half did not verify")

        if kind == "receipt":
            # A positive vector must be unambiguous: the version it is signed at must be the
            # version its content requires. A v1-signed receipt carrying v2 evidence is the
            # case §7.3.4 has to reason about, and it does not belong in reference material.
            required = required_receipt_version(doc)
            signed = signed_receipt_version(doc)
            record(
                signed == required, f"{name} — signature version covers its content",
                f"signed v{signed}, content requires v{required}",
            )


def check_negative_vectors(verify) -> None:
    print("\nNegative vectors — these MUST be rejected")
    if not NEGATIVE.is_dir():
        skip("negative/", "directory not present — run test-vectors/generate_negative.py")
        return
    for path in sorted(NEGATIVE.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        expect = doc.get("_expect", {})
        kind = kind_of(path.name)
        if not kind:
            skip(path.name, "no canonical known for this vector kind")
            continue
        raw_sig = doc.get("signature")
        sig = raw_sig.get("value", "") if isinstance(raw_sig, dict) else ""

        if expect.get("reason") == "signature-not-an-object":
            # The bytes are right on purpose: the vector is broken if they would not verify,
            # and what must refuse it is the shape check, not a failed signature.
            bytes_valid = isinstance(raw_sig, str) and verify(
                TEST_PUBKEY_B64, CANONICALS[kind](doc), raw_sig)
            shape = signature_shape_problem(raw_sig)
            ok = bytes_valid and bool(shape)
            record(ok, path.name, "rejected: valid bytes, not a §7.3.1 object" if ok else
                   "vector is not exercising the shape rule")
            continue

        if expect.get("reason") == "version-under-covers-content":
            # The signature is genuinely valid over what it covers — that is the point. What
            # must be detected is that it covers LESS than the receipt's content requires.
            signed = signed_receipt_version(doc)
            required = required_receipt_version(doc)
            covers = bool(sig) and verify(TEST_PUBKEY_B64, receipt_canonical(doc, signed), sig)
            ok = covers and signed < required
            record(ok, path.name,
                   f"detected: signed v{signed}, content requires v{required}" if ok
                   else "vector is not exercising a downgrade")
            continue

        if expect.get("reason") == "key-not-pinned":
            # Signed by the wrong key: it verifies against the key it carries and must
            # still be rejected, because a verifier trusts the key it PINNED, not the one
            # the document supplies. Getting this right is the whole point of the vector.
            embedded = (doc.get("signature") or {}).get("public_key", "")
            self_consistent = bool(sig) and verify(embedded, CANONICALS[kind](doc), sig)
            against_pin = bool(sig) and verify(TEST_PUBKEY_B64, CANONICALS[kind](doc), sig)
            ok = self_consistent and not against_pin
            record(ok, path.name, "rejected: signer is not the pinned key" if ok else
                   "vector is not exercising what it claims")
            continue

        if expect.get("reason") == "small-order-key":
            # Verified against the key the document carries — the point is that a strict
            # verifier refuses it even then, while the bare library accepts it (§7.3.7).
            embedded = (doc.get("signature") or {}).get("public_key", "")
            strict = bool(sig) and verify(embedded, CANONICALS[kind](doc), sig)
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                Ed25519PublicKey.from_public_bytes(base64.b64decode(embedded)).verify(
                    base64.b64decode(sig), CANONICALS[kind](doc).encode())
                permissive = True
            except Exception:
                permissive = False
            record(not strict, path.name,
                   ("rejected (the bare library accepts it)" if permissive else "rejected")
                   if not strict else "ACCEPTED — a small-order key signs every message")
            continue

        if expect.get("reason", "").startswith("pq-"):
            hybrid = hybrid_verifier(verify)
            if hybrid is None:
                skip(path.name, "dilithium-py not installed")
                continue
            canonical = CANONICALS[kind](doc)
            pins = doc.get("_pins", {})
            ed_valid = bool(sig) and verify(pins.get("ed25519", ""), canonical, sig)
            accepted = hybrid(doc.get("signature") or {}, canonical, pins,
                              require_pq=bool(expect.get("require_pq")))
            ok = ed_valid and not accepted
            record(ok, path.name, "rejected (Ed25519 half valid)" if ok else
                   ("ACCEPTED — the PQ layer is decoration" if accepted else "vector is not exercising the PQ layer"))
            continue

        accepted = bool(sig) and verify(TEST_PUBKEY_B64, CANONICALS[kind](doc), sig)
        record(not accepted, path.name,
               "rejected" if not accepted else "ACCEPTED — a verifier written this way is exploitable")


# ── live hub checks ─────────────────────────────────────────────────

def fetch(url: str, timeout: float = 15.0):
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "AIMarketConformance/1.0",
        "X-AIMarket-Crawler": "https://conformance.invalid",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def check_live_hub(base: str) -> None:
    base = base.rstrip("/")
    print(f"\nLive hub — {base}")

    try:
        status, wk = fetch(f"{base}/.well-known/ai-market.json")
    except Exception as exc:
        record(False, "GET /.well-known/ai-market.json", str(exc)[:80])
        return
    record(status == 200, "GET /.well-known/ai-market.json", f"HTTP {status}")

    record(isinstance(wk.get("protocol_versions"), list) and wk.get("protocol_versions"),
           "well-known declares protocol_versions", str(wk.get("protocol_versions")))
    record(bool(wk.get("manifest_url")), "well-known declares manifest_url",
           str(wk.get("manifest_url", ""))[:60])

    # The Internet-Draft's names (ietf/): the same document under
    # /.well-known/agent-marketplace with `catalogue_url` and `signature_profile`, served
    # beside the legacy path. A hub that predates the drafts serves only the legacy path;
    # that is a skip, not a failure — the drafts are proposals, the legacy path the contract.
    try:
        d_status, draft = fetch(f"{base}/.well-known/agent-marketplace")
    except Exception as exc:
        d_status, draft = 0, {}
        skip("GET /.well-known/agent-marketplace", str(exc)[:80])
    if d_status == 200 and isinstance(draft, dict):
        record(True, "GET /.well-known/agent-marketplace (draft name)", "HTTP 200")
        record(bool(draft.get("catalogue_url")) and draft.get("catalogue_url") == wk.get("manifest_url"),
               "draft catalogue_url equals legacy manifest_url",
               str(draft.get("catalogue_url", ""))[:60])
        record(draft.get("signer_public_key") == wk.get("signer_public_key"),
               "draft and legacy documents advertise one signer key")
        record(draft.get("signature_profile") == "ed25519-pipe-2",
               "draft names its signature profile", str(draft.get("signature_profile")))
        d_peers = draft.get("peers")
        record(isinstance(d_peers, list) and all(isinstance(p, str) for p in d_peers),
               "draft peers are discovery-document URIs")
        try:
            req = urllib.request.Request(f"{base}/.well-known/agent-marketplace", method="HEAD")
            with urllib.request.urlopen(req, timeout=15) as resp:
                record(resp.status == 200, "HEAD /.well-known/agent-marketplace", f"HTTP {resp.status}")
        except Exception as exc:
            record(False, "HEAD /.well-known/agent-marketplace", str(exc)[:80])
    elif d_status:
        skip("GET /.well-known/agent-marketplace", f"HTTP {d_status}: hub serves only the legacy name")

    # §2.4(5): a pending peer must never be republished to the network.
    peers = wk.get("peers")
    if isinstance(peers, list):
        leaked = [p for p in peers if isinstance(p, dict) and p.get("status") == "pending"]
        record(not leaked, "§2.4(5) no pending peer in published well-known",
               "" if not leaked else f"{len(leaked)} pending peer(s) republished")
    else:
        skip("§2.4(5) pending-peer leak", "well-known carries no peers array")

    try:
        status, peers_doc = fetch(f"{base}/ai-market/v2/federation/peers")
        record(status == 200, "GET /ai-market/v2/federation/peers", f"HTTP {status}")
        if isinstance(peers_doc, dict):
            record(isinstance(peers_doc.get("peers"), list),
                   "peers endpoint returns a peers array")
            if "pending" in peers_doc:
                pend = peers_doc.get("pending")
                record(isinstance(pend, list), "§2.4 pending queue exposed separately",
                       f"{len(pend) if isinstance(pend, list) else '?'} pending")
                bad = [p for p in (pend or []) if isinstance(p, dict) and p.get("trusted")]
                record(not bad, "§2.4(1) no pending peer is marked trusted")
            else:
                skip("§2.4 pending queue", "hub predates the admission model")
    except Exception as exc:
        record(False, "GET /ai-market/v2/federation/peers", str(exc)[:80])

    # §7.3.6 — schemas must be dereferenceable if the hub publishes $id under its own host.
    try:
        status, schema = fetch(f"{base}/schemas/well-known.json")
        ok = status == 200 and isinstance(schema, dict) and "$id" in schema
        record(ok, "GET /schemas/well-known.json resolves", f"HTTP {status}")
    except urllib.error.HTTPError as exc:
        skip("/schemas/ hosting", f"HTTP {exc.code} — optional, but $id then dangles")
    except Exception as exc:
        skip("/schemas/ hosting", str(exc)[:60])

    # A signed manifest is the one thing every federating peer must be able to verify.
    murl = wk.get("manifest_url") or f"{base}/ai-market/v2/manifest"
    try:
        status, manifest = fetch(murl)
        if not isinstance(manifest, dict):
            record(False, "GET manifest", "the manifest is not a JSON object")
            return
        raw_sig = manifest.get("signature")
        shape = signature_shape_problem(raw_sig) if raw_sig else ""
        sig = raw_sig if isinstance(raw_sig, dict) else {}
        pub = sig.get("public_key") or wk.get("signer_public_key") or ""
        verify = _verifier()
        if shape:
            # A shape error needs no cryptography to see, so it is reported even without it.
            record(False, "live manifest signature is a §7.3.1 object", shape)
        elif not verify:
            skip("live manifest signature", "pip install cryptography>=44")
        elif not sig.get("value"):
            record(False, "live manifest is signed", "no signature block")
        elif not pub:
            record(False, "live manifest signature verifiable", "no public key advertised")
        else:
            ok = verify(pub, manifest_canonical(manifest), sig["value"])
            record(ok, "live manifest verifies under §7.3.2 canonical",
                   "" if ok else "canonical mismatch — this hub cannot federate")
    except Exception as exc:
        record(False, "GET manifest", str(exc)[:80])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hub", help="Base URL of a running hub to check live")
    args = ap.parse_args()

    print("AIMarket Protocol conformance runner")
    verify = _verifier()
    if not verify:
        print(f"\n{RED}cryptography>=44 is required for vector checks:{RESET} pip install cryptography")
        return 1

    check_positive_vectors(verify)
    check_negative_vectors(verify)
    if args.hub:
        check_live_hub(args.hub)

    failed = [r for r in results if not r[0]]
    total = len(results)
    print()
    if failed:
        print(f"{RED}{len(failed)} of {total} checks failed{RESET}")
        for _, name, detail in failed:
            print(f"  · {name}: {detail}")
        return 1
    print(f"{GREEN}all {total} checks passed{RESET}")
    print(f"{DIM}Conformance to the vectors and the discovery surface. Not a security audit.{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
