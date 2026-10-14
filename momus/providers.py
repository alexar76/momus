"""Multi-LLM provider layer for MOMUS — self-contained.

MOMUS is a standalone project: in Docker it builds with only ``oracle-core`` as a local
dependency, so this module deliberately does NOT import metis or the top-level ``llm/``
package. It mirrors the shape of ``metis/metis/models/provider.py`` (the house abstraction)
but re-implements it here so the satellite has no cross-satellite import.

Named provider choices, exactly as the operator asked for:

    anthropic     native /v1/messages (Claude)                api.anthropic.com
    openai        OpenAI-compatible /v1/chat/completions      api.openai.com/v1
    deepseek      the ecosystem's own DeepSeek V4 Pro          api.deepseek.com/v1
    ollama        local Ollama, OpenAI-compat surface          http://host:11434/v1
    lmstudio      local LM Studio, OpenAI-compat surface        http://host:1234/v1

``deepseek``/``ollama``/``lmstudio``/``openai`` share one wire implementation (OpenAI
chat-completions); they differ only in default base_url, default model and default api_key.
They are exposed as *named presets* because the operator wanted to pick them by name, not
because the code forks. ``deepseek`` is the PROD default (server 2 / modeldev.modelmarket.dev):
DeepSeek V4 Pro is a remote API, so MOMUS needs no heavy local-model container on a box with
modest RAM, and it matches the model the rest of the factory already runs on.

There is also an ``offline`` provider (deterministic, no network) so the entire engine — and
its whole test suite — runs with no model reachable, the same way GAIA ships a deterministic
simulator. The engine treats the LLM as an *idea generator and triager only*; nothing a model
returns can authorize a payout (that is momus.economics's job, behind a different key).
"""

from __future__ import annotations

import hashlib
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx


class ProviderKind(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI_COMPAT = "openai_compat"
    OLLAMA = "ollama"
    LMSTUDIO = "lmstudio"
    METIS = "metis"      # borrow the cognitive tier's reasoning stack via its /v1/verify surface
    OFFLINE = "offline"  # deterministic, no network — the default when nothing is configured


# Named presets → (kind, default base_url, default model, default api_key). ``host.docker.internal``
# lets a container reach an Ollama/LM Studio running on the host; override MOMUS_LLM_BASE_URL to
# point elsewhere. Anthropic/OpenAI keys are read from the environment and never defaulted.
_PRESETS: dict[str, dict[str, str]] = {
    "offline": {"kind": ProviderKind.OFFLINE.value, "base_url": "", "model": "momus-offline", "api_key": ""},
    "anthropic": {
        "kind": ProviderKind.ANTHROPIC.value,
        "base_url": "https://api.anthropic.com",
        "model": "claude-sonnet-4-5",
        "api_key": "",
    },
    "openai": {
        "kind": ProviderKind.OPENAI_COMPAT.value,
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "api_key": "",
    },
    # The ecosystem's own model — the factory, alien-monitor and Platon already default to it.
    # Key comes from DEEPSEEK_API_KEY (see MOMUS_LLM_API_KEY resolution / the prod compose file).
    "deepseek": {
        "kind": ProviderKind.OPENAI_COMPAT.value,
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-v4-pro",
        "api_key": "",
    },
    "ollama": {
        "kind": ProviderKind.OLLAMA.value,
        "base_url": "http://host.docker.internal:11434/v1",
        "model": "llama3.1",
        "api_key": "ollama",
    },
    # Metis's own cognitive stack — "the wisdom of Metis" — reached through its /v1/verify surface
    # on the shared ecosystem network. Used for adversarial-input generation and report distilling;
    # never for authorizing a payout (that stays behind the treasury + verifier keys).
    "metis": {
        "kind": ProviderKind.METIS.value,
        "base_url": "http://metis:9100",
        "model": "metis-council",
        "api_key": "",
    },
    "lmstudio": {
        "kind": ProviderKind.LMSTUDIO.value,
        "base_url": "http://host.docker.internal:1234/v1",
        "model": "local-model",
        "api_key": "lm-studio",
    },
}

# Accept a few aliases the operator might reasonably type.
_ALIASES = {
    "claude": "anthropic",
    "anthropic_compat": "anthropic",
    "openai_compatible": "openai",
    "oai": "openai",
    "lm_studio": "lmstudio",
    "lm-studio": "lmstudio",
    "deep-seek": "deepseek",
    "deepseek_api": "deepseek",
    "none": "offline",
    "mock": "offline",
    "": "offline",
}


@dataclass
class Message:
    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class LLMConfig:
    """Provider selection, resolved from a named preset then overlaid with explicit values."""

    provider: str = "offline"
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    temperature: float = 0.4
    max_tokens: int = 1024
    timeout_s: float = 60.0
    extra_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """Build from MOMUS_LLM_* env vars.

        MOMUS_LLM_PROVIDER  one of: offline | anthropic | openai | ollama | lmstudio
        MOMUS_LLM_MODEL     override the preset model
        MOMUS_LLM_BASE_URL  override the preset base_url (e.g. a self-hosted vLLM)
        MOMUS_LLM_API_KEY   provider key (required for anthropic/openai; ignored offline)
        MOMUS_LLM_TEMPERATURE / MOMUS_LLM_MAX_TOKENS  generation knobs
        """
        raw = (os.environ.get("MOMUS_LLM_PROVIDER") or "offline").strip().lower()
        name = _ALIASES.get(raw, raw)
        preset = _PRESETS.get(name)
        if preset is None:
            # Unknown provider name never silently downgrades to a network call — fail to offline
            # so a typo can't accidentally send probes' adversarial prompts to the wrong endpoint.
            preset = _PRESETS["offline"]
        model = (os.environ.get("MOMUS_LLM_MODEL") or "").strip() or preset["model"]
        base_url = (os.environ.get("MOMUS_LLM_BASE_URL") or "").strip() or preset["base_url"]
        api_key = (os.environ.get("MOMUS_LLM_API_KEY") or "").strip() or preset["api_key"]
        # The DeepSeek preset shares the ecosystem's DEEPSEEK_API_KEY when no MOMUS-specific key
        # is set, so a server-2 deploy that already exports it needs no extra secret.
        if not api_key and name == "deepseek":
            api_key = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
        temp = _float_env("MOMUS_LLM_TEMPERATURE", 0.4)
        max_tokens = _int_env("MOMUS_LLM_MAX_TOKENS", 1024)
        return cls(
            provider=preset["kind"],
            model=model,
            base_url=base_url,
            api_key=api_key,
            temperature=temp,
            max_tokens=max_tokens,
        )


def _float_env(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, "").strip() or default)
    except ValueError:
        return default


def _int_env(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, "").strip() or default)
    except ValueError:
        return default


class LLMProvider(ABC):
    """Minimal async interface — one method, plus a health probe and cleanup."""

    kind: ProviderKind
    model: str

    @abstractmethod
    async def complete(self, messages: list[Message], *, temperature: float | None = None,
                       max_tokens: int | None = None) -> str:
        ...

    async def complete_text(self, system: str, user: str, **kwargs: Any) -> str:
        return await self.complete([Message("system", system), Message("user", user)], **kwargs)

    async def health(self) -> dict[str, Any]:
        """Cheap reachability check. Never raises; returns a status dict."""
        return {"provider": self.kind.value, "model": self.model, "reachable": True}

    async def aclose(self) -> None:  # pragma: no cover - trivial
        pass


class OfflineProvider(LLMProvider):
    """Deterministic, network-free provider.

    Produces stable, seeded pseudo-text from the prompt so the engine's LLM-assisted steps
    (adversarial-input mutation, finding triage) are exercised end-to-end in CI without any
    model. It is honest about being offline: callers that need a real judgement must configure
    a real provider. It never fabricates a *verdict* — it only mutates/echoes inputs — because
    nothing here is trusted to authorize money regardless of provider.
    """

    kind = ProviderKind.OFFLINE

    def __init__(self, config: LLMConfig):
        self.model = config.model or "momus-offline"

    async def complete(self, messages: list[Message], *, temperature: float | None = None,
                       max_tokens: int | None = None) -> str:
        blob = "\n".join(f"{m.role}:{m.content}" for m in messages)
        digest = hashlib.sha256(blob.encode()).hexdigest()
        # A compact, JSON-shaped deterministic response so triage code that expects JSON still
        # parses. The engine has a non-LLM fallback for every step, so this is only a stand-in.
        return json.dumps({
            "offline": True,
            "note": "MOMUS offline provider — deterministic stand-in, no model configured",
            "seed": digest[:16],
            "mutations": [f"boundary::{digest[:8]}", f"overflow::{digest[8:16]}"],
        })

    async def health(self) -> dict[str, Any]:
        return {"provider": "offline", "model": self.model, "reachable": True, "offline": True}


class OpenAICompatProvider(LLMProvider):
    """OpenAI chat-completions wire format — covers OpenAI, Ollama (/v1), LM Studio, vLLM, DeepSeek."""

    def __init__(self, config: LLMConfig, kind: ProviderKind = ProviderKind.OPENAI_COMPAT):
        self.kind = kind
        self.model = config.model
        self._cfg = config
        headers = {"Content-Type": "application/json"}
        if config.api_key:
            headers["Authorization"] = f"Bearer {config.api_key}"
        for k, v in (config.extra_headers or {}).items():
            headers[str(k)] = str(v)
        self._client = httpx.AsyncClient(
            base_url=config.base_url.rstrip("/"),
            headers=headers,
            timeout=config.timeout_s,
        )

    async def complete(self, messages: list[Message], *, temperature: float | None = None,
                       max_tokens: int | None = None) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": self._cfg.temperature if temperature is None else temperature,
            "max_tokens": max_tokens or self._cfg.max_tokens,
        }
        r = await self._client.post("/chat/completions", json=payload)
        r.raise_for_status()
        data = r.json()
        choice = data["choices"][0]["message"]
        # Reasoning models may put the answer in reasoning_content when content is empty.
        return (choice.get("content") or choice.get("reasoning_content") or "").strip()

    async def health(self) -> dict[str, Any]:
        try:
            # /models is the cheapest OpenAI-compatible liveness probe.
            r = await self._client.get("/models", timeout=5.0)
            return {"provider": self.kind.value, "model": self.model, "reachable": r.status_code < 500}
        except Exception as exc:  # noqa: BLE001 - health never raises
            return {"provider": self.kind.value, "model": self.model, "reachable": False,
                    "error": type(exc).__name__}

    async def aclose(self) -> None:
        await self._client.aclose()


class AnthropicProvider(LLMProvider):
    """Native Anthropic /v1/messages adapter (mirrors metis/metis/models/anthropic.py)."""

    kind = ProviderKind.ANTHROPIC

    def __init__(self, config: LLMConfig):
        self.model = config.model
        self._cfg = config
        base = config.base_url.rstrip("/")
        if base.endswith("/v1"):
            base = base[: -len("/v1")]
        self._url = f"{base}/v1/messages"
        self._client = httpx.AsyncClient(
            headers={
                "x-api-key": config.api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            timeout=config.timeout_s,
        )

    async def complete(self, messages: list[Message], *, temperature: float | None = None,
                       max_tokens: int | None = None) -> str:
        system_parts = [m.content for m in messages if m.role == "system"]
        turns = [
            {"role": "user" if m.role == "user" else "assistant", "content": m.content}
            for m in messages
            if m.role in ("user", "assistant")
        ]
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens or self._cfg.max_tokens,
            "messages": turns or [{"role": "user", "content": ""}],
            "temperature": self._cfg.temperature if temperature is None else temperature,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        r = await self._client.post(self._url, json=payload)
        r.raise_for_status()
        data = r.json()
        return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text").strip()

    async def health(self) -> dict[str, Any]:
        # Anthropic has no free liveness endpoint; report configured, not reached, so a health
        # check never spends tokens. reachable=None means "not probed".
        return {"provider": "anthropic", "model": self.model,
                "reachable": bool(self._cfg.api_key) or None, "probed": False}

    async def aclose(self) -> None:
        await self._client.aclose()


class MetisProvider(LLMProvider):
    """Reach Metis's cognitive stack through its ``/v1/verify`` surface.

    Metis exposes ``POST /v1/verify {input}`` which runs any input through its council/reasoning
    stack and returns a structured result. We use it as a completion backend for MOMUS's OFFENSIVE
    reasoning only — generating adversarial-input ideas and distilling threat reports. This is a
    separate concern from Metis's role as an independent VERIFIER (momus.engine.verify), which
    signs verdicts with Metis's own key; borrowing Metis for idea-generation never lets Metis (or
    MOMUS) authorize a payout.
    """

    kind = ProviderKind.METIS

    def __init__(self, config: LLMConfig):
        self.model = config.model or "metis-council"
        self._cfg = config
        headers = {"Content-Type": "application/json"}
        if config.api_key:
            headers["Authorization"] = f"Bearer {config.api_key}"
        self._client = httpx.AsyncClient(
            base_url=config.base_url.rstrip("/"), headers=headers, timeout=config.timeout_s)

    async def complete(self, messages: list[Message], *, temperature: float | None = None,
                       max_tokens: int | None = None) -> str:
        combined = "\n\n".join(f"[{m.role}]\n{m.content}" for m in messages)
        r = await self._client.post("/v1/verify", json={"input": combined})
        r.raise_for_status()
        data = r.json()
        return _read_metis_text(data)

    async def health(self) -> dict[str, Any]:
        try:
            r = await self._client.get("/health", timeout=5.0)
            return {"provider": "metis", "model": self.model, "reachable": r.status_code < 500}
        except Exception as exc:  # noqa: BLE001
            return {"provider": "metis", "model": self.model, "reachable": False,
                    "error": type(exc).__name__}

    async def aclose(self) -> None:
        await self._client.aclose()


def _read_metis_text(data: Any) -> str:
    """Pull a human-readable answer out of Metis's verify envelope, defensively."""
    if isinstance(data, str):
        return data.strip()
    if isinstance(data, dict):
        for key in ("answer", "output", "summary", "result", "text", "verdict"):
            v = data.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
            if isinstance(v, dict):
                nested = _read_metis_text(v)
                if nested:
                    return nested
    return json.dumps(data, ensure_ascii=False)[:2000]


def create_provider(config: LLMConfig | None = None) -> LLMProvider:
    """Factory — resolves a config into a live provider. Defaults to offline."""
    cfg = config or LLMConfig.from_env()
    kind = ProviderKind(cfg.provider) if not isinstance(cfg.provider, ProviderKind) else cfg.provider
    if kind == ProviderKind.OFFLINE:
        return OfflineProvider(cfg)
    if kind == ProviderKind.ANTHROPIC:
        if not cfg.api_key:
            # Fail closed to offline rather than firing keyless requests that 401 mid-scan.
            return OfflineProvider(cfg)
        return AnthropicProvider(cfg)
    if kind == ProviderKind.METIS:
        return MetisProvider(cfg)
    # openai / ollama / lmstudio all speak OpenAI chat-completions.
    return OpenAICompatProvider(cfg, kind=kind)


def provider_choices() -> list[dict[str, str]]:
    """Public catalogue of selectable providers — used by /health and the live panel UI."""
    out = []
    for name, p in _PRESETS.items():
        out.append({
            "name": name,
            "kind": p["kind"],
            "default_model": p["model"],
            "default_base_url": p["base_url"],
            "needs_key": name in ("anthropic", "openai", "deepseek"),
            "local": name in ("ollama", "lmstudio"),
            "ecosystem": name == "metis",
        })
    return out
