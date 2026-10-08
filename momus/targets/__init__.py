"""Targets — the components MOMUS is allowed to probe.

Every target is on the operator's explicit allowlist (momus.config). MOMUS never probes a host
that is not named there, so it can never be pointed at a third party. Every probe is SAFE:
read-only assertions against the target's OWN declared contract (its manifest, its free-tier
ceiling, its signature scheme). Nothing here performs a destructive action or moves real funds —
this is conformance and adversarial *testing*, the offensive complement to ARGUS's defensive WARDEN.
"""

from momus.targets.base import ProbeContext, ProbeResult, Target
from momus.targets.oracle import OracleTarget
from momus.targets.hub import HubTarget
from momus.targets.injection import InjectionTarget

__all__ = [
    "ProbeContext",
    "ProbeResult",
    "Target",
    "OracleTarget",
    "HubTarget",
    "InjectionTarget",
    "build_targets",
]


def build_targets(config) -> list[Target]:
    """Instantiate the concrete targets for the operator's allowlisted endpoints."""
    out: list[Target] = []
    for ep in config.targets:
        if not ep.enabled:
            continue
        if ep.kind in ("oracle",):
            out.append(OracleTarget(ep.name, ep.base_url))
        elif ep.kind == "hub":
            out.append(HubTarget(ep.name, ep.base_url))
        elif ep.kind in ("metis",):
            # A cognitive/LLM-backed node: probe its contract like an oracle AND its
            # prompt-injection surface. The injection target gets a DISTINCT name — the runtime
            # registry is keyed by name with setdefault, so sharing one silently dropped the
            # injection probes and advertised a boundary that was never tested.
            out.append(OracleTarget(ep.name, ep.base_url))
            out.append(InjectionTarget(f"{ep.name}-injection", ep.base_url))
    return out
