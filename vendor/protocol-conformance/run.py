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


def record(ok: bool, name: str, detail: str = "") -> None:
    results.append((ok, name, detail))
    mark = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    print(f"  {mark}  {name}" + (f"  {DIM}{detail}{RESET}" if detail else ""))


def skip(name: str, why: str) -> None:
    print(f"  {YELLOW}SKIP{RESET}  {name}  {DIM}{why}{RESET}")


# ── crypto ──────────────────────────────────────────────────────────

def _verifier():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return None

    def verify(pub_b64: str, canonical: str, sig_b64: str) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(
                base64.b64decode(sig_b64), canonical.encode()
            )
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

def check_positive_vectors(verify) -> None:
    print("\nPositive vectors — these MUST verify")
    for name in ("manifest-signed.json", "receipt-signed.json", "receipt-v2-signed.json",
                 "federation-announce-signed.json"):
        path = VECTORS / name
        if not path.exists():
            record(False, name, "file missing")
            continue
        doc = json.loads(path.read_text(encoding="utf-8"))
        kind = kind_of(name)
        sig = (doc.get("signature") or {}).get("value", "")
        ok = bool(sig) and verify(TEST_PUBKEY_B64, CANONICALS[kind](doc), sig)
        record(ok, name, "" if ok else "signature did not verify against the documented canonical")

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
        sig = (doc.get("signature") or {}).get("value", "")

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
        sig = (manifest.get("signature") or {})
        pub = sig.get("public_key") or wk.get("signer_public_key") or ""
        verify = _verifier()
        if not verify:
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
