# MOMUS canary — a deliberately non-conforming fixture

A detection pipeline you have never seen fire is a pipeline you cannot trust. The ecosystem's real
components pass their own contract checks (which is the point of building them carefully), so a
clean MOMUS scan proves nothing about MOMUS. This canary is the fix: a service that advertises a
contract and then knowingly breaks it, so the whole loop can be exercised against a **real** finding.

**Two things stay true, and both matter for honesty:**

- The **finding is genuine** — MOMUS detects an actual contract violation with no special-casing and
  signs it with its real scanner key. Nothing on the probe path is faked or stubbed.
- The **target is a fixture**, not a production service that was found broken. Any report of a canary
  cycle must say so plainly. Presenting it as a real ecosystem vulnerability would be a lie.

## What it violates

| Probe | Violation while broken |
|---|---|
| `free_tier_ceiling_bypass` | declares `free_tier_max: {n: 100}`, then serves `n > 100` unpaid with 200 |
| `receipt_signature_integrity` | returns no signed receipt at all |
| `manifest_signature_integrity` | manifest signature does not verify against its declared key |
| `unpaid_invoke_refused` (hub probe) | serves a capability priced at $0.05 with no payment context |

## Run it

```bash
CANARY_TOKEN=$(openssl rand -hex 16) CANARY_PORT=9450 python -m canary.canary
```

Register it with MOMUS as an allowlisted target (operator environment only — nothing MOMUS reads off
the wire can add a target):

```bash
MOMUS_EXTRA_TARGETS="canary|http://127.0.0.1:9450|oracle"
```

Then drive the cycle: scan → it finds the violations → `POST /canary/fix` (stands in for "the Factory
shipped a patch and the service redeployed") → MOMUS's `/retest` gate confirms `fixed` → the Treasury
splits the bounty in UNI simulation. `POST /canary/break` puts it back.

Both control routes require `x-canary-token`, and the canary binds to loopback only — it is an
internal fixture, never a public endpoint.
