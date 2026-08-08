"""Target and probe abstractions.

A ``Target`` is a component MOMUS probes; a ``ProbeStrategy`` (momus.engine.strategies) is one
adversarial test; a ``ProbeResult`` is its structured outcome, which the scan runner turns into a
signed Finding. The HTTP client here is deliberately conservative: short timeouts, small response
caps, no redirects off the target host, and it records digests of what it sent/received so a
finding is reproducible without shipping raw payloads.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx

from momus.findings import Outcome, Severity


@dataclass
class ProbeResult:
    """Structured outcome of one probe against a target."""

    probe: str
    category: str
    outcome: Outcome
    severity: Severity
    title: str
    detail: str
    request_summary: str = ""
    response_summary: str = ""
    status_code: int | None = None
    reproducer: str = ""
    raw_request: Any = None
    raw_response: Any = None

    def digests(self) -> tuple[str, str]:
        req = json.dumps(self.raw_request, sort_keys=True, default=str) if self.raw_request is not None else self.request_summary
        resp = json.dumps(self.raw_response, sort_keys=True, default=str) if self.raw_response is not None else self.response_summary
        return (
            "sha256-" + hashlib.sha256(req.encode()).hexdigest(),
            "sha256-" + hashlib.sha256(resp.encode()).hexdigest(),
        )


@dataclass
class ProbeContext:
    """Shared services a probe may use: a safe HTTP client and (optionally) an LLM for mutating
    adversarial inputs. The LLM is an idea generator only; a probe's verdict never depends on
    trusting model output."""

    client: "SafeHttpClient"
    llm: Any = None  # momus.providers.LLMProvider | None
    findings_seen: set[str] = field(default_factory=set)
    seed_hints: list[str] = field(default_factory=list)  # adversarial-shape hints from learned intel


class SafeHttpClient:
    """A thin httpx wrapper that keeps probes safe and bounded."""

    MAX_BYTES = 64_000

    def __init__(self, base_url: str, timeout_s: float = 8.0, *, transport: Any = None):
        self.base_url = base_url.rstrip("/")
        # ``transport`` lets a test drive an in-process ASGI app (httpx.ASGITransport) instead of a
        # real socket — the same probes, no network. Production passes None (a real transport).
        kwargs: dict[str, Any] = {"base_url": self.base_url, "timeout": timeout_s,
                                  "follow_redirects": False}
        if transport is not None:
            kwargs["transport"] = transport
        self._client = httpx.AsyncClient(**kwargs)

    async def request(self, method: str, path: str, *, json_body: Any = None,
                      headers: dict[str, str] | None = None) -> tuple[int | None, Any, str]:
        """Return (status_code, parsed_or_text, error). Never raises — a transport failure is a
        legitimate probe outcome (target down → inconclusive), not a crash."""
        try:
            r = await self._client.request(method, path, json=json_body, headers=headers or {})
        except httpx.HTTPError as exc:
            return None, None, f"{type(exc).__name__}: {exc}"
        body_text = r.text[: self.MAX_BYTES]
        parsed: Any
        try:
            parsed = r.json()
        except (json.JSONDecodeError, ValueError):
            parsed = body_text
        return r.status_code, parsed, ""

    async def aclose(self) -> None:
        await self._client.aclose()


class Target(ABC):
    """A probed component. Subclasses declare which strategies apply and how to read the target's
    own declared contract (its manifest / well-known doc)."""

    kind: str = "generic"

    def __init__(self, name: str, base_url: str, *, transport: Any = None):
        self.name = name
        self.base_url = base_url
        self.transport = transport  # test hook: an httpx.ASGITransport for in-process probing

    @abstractmethod
    def strategies(self) -> list["ProbeStrategy"]:
        """The probes this target supports."""

    async def discover(self, ctx: ProbeContext) -> dict[str, Any]:
        """Read the target's self-description (manifest / well-known). Default: none."""
        _ = ctx
        return {}


class ProbeStrategy(ABC):
    """One adversarial test. SAFE by construction: it asserts against the target's own contract."""

    probe_id: str = "abstract"
    category: str = "generic"

    @abstractmethod
    async def run(self, target: Target, ctx: ProbeContext, discovery: dict[str, Any]) -> list[ProbeResult]:
        ...
