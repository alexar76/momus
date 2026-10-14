"""A2A (Agent2Agent) surface for MOMUS — how MOMUS talks to other AGENTS, not tools.

MCP already covers agent→tool (MOMUS probing a capability). But remediation is agent↔agent: MOMUS
hands a confirmed finding to SKOPOS (the remediation conductor), SKOPOS hands a fix task to the
AI-Factory, and SKOPOS asks MOMUS back to re-test the patched build as the deploy gate. Those are
delegations and negotiations between peers, which is exactly what A2A is for.

This module is a lightweight, spec-aligned subset of the A2A protocol:

* an **Agent Card** (served at ``/.well-known/agent-card.json``) advertising MOMUS's skills
  (``scan``, ``retest``, ``selfaudit``) so a peer can discover what it can delegate;
* a minimal **Task** model (states: submitted → working → completed/failed) with typed artifacts;
* a client to **delegate** a task to a peer agent (SKOPOS) and a server side to **receive** one
  (the ``retest`` deploy-gate task).

Trust boundary, unchanged: an A2A task can ask MOMUS to *scan* or *re-test* — read-only work it
would do anyway — but nothing arriving over A2A can add a target off the allowlist, authorize a
payout, or make MOMUS deploy code. Peers exchange signed evidence; they do not exchange authority.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx

from momus import __version__


@dataclass
class AgentSkill:
    id: str
    name: str
    description: str
    tags: list[str] = field(default_factory=list)


def agent_card(public_url: str) -> dict[str, Any]:
    """The A2A discovery document. A peer fetches this to learn what it can delegate to MOMUS."""
    base = public_url.rstrip("/")
    return {
        "protocolVersion": "0.2",
        "name": "MOMUS",
        "description": "Autonomous adversarial-audit agent. Finds and signs contract violations in "
                       "the ecosystem's own components; re-tests fixes as a deploy gate. Finds and "
                       "signs — never pays or deploys.",
        "url": base,
        "version": __version__,
        "provider": {"organization": "AICOM / AIMarket", "url": base},
        "capabilities": {"streaming": False, "pushNotifications": True, "stateTransitionHistory": True},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            asdict(AgentSkill(
                "scan", "Adversarial scan",
                "Run safe, read-only conformance/adversarial probes against an allowlisted target "
                "and return signed findings.",
                ["security", "red-team", "audit"])),
            asdict(AgentSkill(
                "retest", "Fix re-test (deploy gate)",
                "Re-run a specific finding's probe against a (patched) target and return a signed "
                "fixed / still-vulnerable verdict. Intended as a pre-promotion deploy gate.",
                ["security", "regression", "ci", "deploy-gate"])),
            asdict(AgentSkill(
                "selfaudit", "Self-audit",
                "Run MOMUS's own invariant self-audit (key separation, self-verification rejection, "
                "fail-closed).",
                ["security", "assurance"])),
            asdict(AgentSkill(
                "threat-intel", "Signed threat feed for a firewall",
                "Return confirmed third-party threat records, signed Ed25519 over the RFC 8785 "
                "canonical form, in the exact format ARGUS's WARDEN firewall verifies. The red team "
                "feeding the blue team. Read-only, no authority granted, and it carries no record "
                "about a first-party component — a deny pattern matching our own services would be "
                "a signed, fleet-wide outage.",
                ["security", "threat-intel", "firewall", "blue-team"])),
        ],
        # Where a peer sends A2A tasks.
        "endpoints": {"tasks": f"{base}/a2a/tasks"},
    }


# A2A task lifecycle states (subset).
STATE_SUBMITTED = "submitted"
STATE_WORKING = "working"
STATE_COMPLETED = "completed"
STATE_FAILED = "failed"
STATE_REJECTED = "rejected"


@dataclass
class A2ATask:
    """A unit of delegated work between agents. ``skill`` selects what to do; ``input`` carries the
    typed payload; ``artifacts`` carry the signed results back."""

    skill: str
    input: dict[str, Any] = field(default_factory=dict)
    task_id: str = field(default_factory=lambda: f"task-{uuid.uuid4().hex[:16]}")
    state: str = STATE_SUBMITTED
    from_agent: str = "momus"
    to_agent: str = ""
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def remediation_task(ticket: dict[str, Any], *, to_agent: str = "skopos") -> A2ATask:
    """Build the A2A task MOMUS delegates to SKOPOS: 'a confirmed finding needs a fix + redeploy'.

    The task carries the signed remediation ticket (Blame + reproducer + the probe to re-run as the
    gate). SKOPOS is expected to drive the AI-Factory to produce a patch, then call MOMUS's
    ``retest`` skill and only redeploy on a signed ``fixed`` verdict."""
    return A2ATask(
        skill="remediate",
        to_agent=to_agent,
        input={
            "ticket": ticket,
            "gate": {"agent": "momus", "skill": "retest",
                     "probe": ticket.get("probe"), "target": ticket.get("target"),
                     "finding_id": ticket.get("finding_id")},
            "route": ticket.get("route"),
        },
        message=f"Confirmed {ticket.get('severity')} finding on {ticket.get('component')} — "
                f"please orchestrate a fix; MOMUS will gate the redeploy by re-testing "
                f"{ticket.get('probe')}.",
    )


class A2AClient:
    """Delegate an A2A task to a peer agent (e.g. SKOPOS). Offline-safe: if no peer URL is
    configured or the peer is unreachable, the task is returned unsent with a clear state so the
    caller can fall back to recording the ticket for human pickup."""

    def __init__(self, peer_url: str | None, timeout_s: float = 20.0, token: str | None = None,
                 transport: Any = None):
        self.peer_url = (peer_url or "").strip().rstrip("/")
        self._timeout = timeout_s
        # Shared A2A peer token. The conductor's ingress can start a Factory patch and end in a
        # signed DeployOrder, so it authenticates its peers; MOMUS presents the same secret.
        import os as _os
        self._token = (token if token is not None else _os.environ.get("SKOPOS_A2A_TOKEN", "")).strip()
        # Test hook: an httpx.ASGITransport so the live delegate path can be exercised in-process
        # (the offline path returns early, which is how a broken __init__ once went unnoticed).
        self._transport = transport

    @property
    def configured(self) -> bool:
        return bool(self.peer_url)

    async def delegate(self, task: A2ATask) -> dict[str, Any]:
        if not self.configured:
            return {"delivered": False, "task": task.to_dict(),
                    "note": "no peer configured (MOMUS_SKOPOS_URL unset) — ticket recorded for pickup"}
        try:
            headers = {"x-a2a-token": self._token} if self._token else {}
            kwargs: dict[str, Any] = {"timeout": self._timeout, "headers": headers}
            if self._transport is not None:
                kwargs["transport"] = self._transport
            async with httpx.AsyncClient(**kwargs) as client:
                r = await client.post(self.peer_url + "/a2a/tasks", json=task.to_dict())
                r.raise_for_status()
                return {"delivered": True, "response": r.json()}
        except (httpx.HTTPError, ValueError) as exc:
            return {"delivered": False, "task": task.to_dict(),
                    "note": f"peer unreachable: {type(exc).__name__} — ticket recorded for pickup"}
