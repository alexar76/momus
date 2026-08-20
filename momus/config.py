"""MOMUS runtime configuration — env-driven, fail-closed in production.

Everything here reads from the environment with safe defaults, matching the rest of the
ecosystem (see gaia/gaia/app.py). Two conventions are load-bearing:

* ``AIFACTORY_PROD=1`` turns on production posture: sim/self-attack control planes are not
  mounted, and any economics action that cannot be independently verified fails CLOSED.
* ``AIFACTORY_CRYPTO_ENABLED`` is the ecosystem-wide master switch for real settlement. When it
  is off (the public-demo default), MOMUS still signs findings and runs the whole bounty
  bookkeeping, but no payout is ever *released* — the ledger records intents, not transfers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from momus.providers import LLMConfig


def _truthy(val: str | None) -> bool:
    return (val or "").strip().lower() in ("1", "true", "yes", "on")


def is_prod() -> bool:
    return _truthy(os.environ.get("AIFACTORY_PROD"))


def crypto_enabled() -> bool:
    return _truthy(os.environ.get("AIFACTORY_CRYPTO_ENABLED"))


def self_attack_enabled() -> bool:
    """Whether MOMUS may run probes against the ecosystem's OWN components (self-audit).

    This is on by default in dev (self-audit is the point) and fail-closed in production
    unless an operator explicitly opts in, because a self-audit run makes real (if safe,
    read-only) requests to sibling services and should be a deliberate choice in prod.
    """
    explicit = os.environ.get("MOMUS_SELF_ATTACK", "").strip()
    if explicit:
        return _truthy(explicit)
    return not is_prod()


@dataclass
class TargetEndpoint:
    """A component MOMUS is allowed to probe. The allowlist is explicit: MOMUS never probes a
    host that is not named here, so it can never be pointed at a third party."""

    name: str
    base_url: str
    kind: str  # "oracle" | "hub" | "metis" | "escrow" | "self"
    enabled: bool = True


@dataclass
class MomusConfig:
    port: int = 9400
    public_url: str = "http://localhost:9400"
    cors_origins: str = "*"
    data_dir: str = "data"
    signing_key_path: str = "data/momus_signing_key"
    invoke_rate_limit: int = 120
    scan_rate_limit: int = 30
    llm: LLMConfig = field(default_factory=LLMConfig.from_env)
    targets: list[TargetEndpoint] = field(default_factory=list)
    prod: bool = False
    crypto: bool = False
    self_attack: bool = False
    # A2A peer that conducts remediation (SKOPOS). When set, a confirmed finding is delegated to it
    # as an A2A task; SKOPOS drives the AI-Factory to produce a fix and calls MOMUS back to re-test.
    skopos_url: str = ""

    @classmethod
    def from_env(cls) -> "MomusConfig":
        port = int(os.environ.get("MOMUS_PORT", "9400"))
        return cls(
            port=port,
            public_url=os.environ.get("MOMUS_PUBLIC_URL", f"http://localhost:{port}"),
            cors_origins=os.environ.get("MOMUS_CORS_ORIGINS", "*"),
            data_dir=os.environ.get("MOMUS_DATA_DIR", "data"),
            signing_key_path=os.environ.get("MOMUS_SIGNING_KEY_PATH", "data/momus_signing_key"),
            invoke_rate_limit=int(os.environ.get("MOMUS_INVOKE_RATE_LIMIT", "120")),
            scan_rate_limit=int(os.environ.get("MOMUS_SCAN_RATE_LIMIT", "30")),
            llm=LLMConfig.from_env(),
            targets=_targets_from_env(),
            prod=is_prod(),
            crypto=crypto_enabled(),
            self_attack=self_attack_enabled(),
            skopos_url=os.environ.get("MOMUS_SKOPOS_URL", ""),
        )


# Default self-audit targets — the ecosystem's own services, by their in-cluster service names on
# the shared 'ecosystem' Docker network (overridable per-URL by env). All probes against these are
# SAFE: read-only assertions against each service's OWN declared contract. Nothing here is a third
# party. Override any URL with MOMUS_TARGET_<NAME>_URL, or disable with MOMUS_TARGET_<NAME>=off.
_DEFAULT_TARGETS = [
    ("oracles", "http://oracle-family:9200", "oracle"),
    ("gaia", "http://gaia-backend:9320", "oracle"),
    ("metis", "http://metis:9100", "metis"),
    ("hub", "http://hub:9085", "hub"),
]


def _targets_from_env() -> list[TargetEndpoint]:
    out: list[TargetEndpoint] = []
    for name, default_url, kind in _DEFAULT_TARGETS:
        toggle = os.environ.get(f"MOMUS_TARGET_{name.upper()}", "").strip().lower()
        if toggle in ("off", "0", "false", "no"):
            continue
        url = os.environ.get(f"MOMUS_TARGET_{name.upper()}_URL", default_url)
        out.append(TargetEndpoint(name=name, base_url=url, kind=kind, enabled=True))
    # Operator-added targets: MOMUS_EXTRA_TARGETS="name|url|kind,name|url|kind".
    # This is still an ALLOWLIST — it is read from the operator's environment at startup, never
    # from a request, a peer's A2A task, or a fetched threat-intel report. Nothing MOMUS reads off
    # the wire can add a target; that is what keeps a probe from ever being pointed at a stranger.
    extra = os.environ.get("MOMUS_EXTRA_TARGETS", "").strip()
    if extra:
        known_kinds = {"oracle", "hub", "metis"}
        for spec in extra.split(","):
            parts = [p.strip() for p in spec.split("|")]
            if len(parts) != 3 or not parts[0] or not parts[1]:
                continue
            name, url, kind = parts
            if kind not in known_kinds:
                kind = "oracle"
            if any(t.name == name for t in out):
                continue
            out.append(TargetEndpoint(name=name, base_url=url, kind=kind, enabled=True))
    return out
