"""Provider selection — named presets, DeepSeek prod default, offline fallback, Metis wisdom."""

from __future__ import annotations

import pytest

from momus.providers import (
    LLMConfig,
    OfflineProvider,
    ProviderKind,
    create_provider,
    provider_choices,
)


def test_offline_is_default(monkeypatch):
    monkeypatch.delenv("MOMUS_LLM_PROVIDER", raising=False)
    cfg = LLMConfig.from_env()
    assert cfg.provider == ProviderKind.OFFLINE.value
    assert isinstance(create_provider(cfg), OfflineProvider)


def test_unknown_provider_falls_to_offline(monkeypatch):
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "totally-bogus")
    cfg = LLMConfig.from_env()
    assert cfg.provider == ProviderKind.OFFLINE.value


def test_deepseek_preset_uses_deepseek_api_key(monkeypatch):
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "deepseek")
    monkeypatch.delenv("MOMUS_LLM_API_KEY", raising=False)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-deepseek-xyz")
    cfg = LLMConfig.from_env()
    assert cfg.provider == ProviderKind.OPENAI_COMPAT.value
    assert cfg.model == "deepseek-v4-pro"
    assert cfg.base_url == "https://api.deepseek.com/v1"
    assert cfg.api_key == "sk-deepseek-xyz"


def test_anthropic_without_key_fails_closed_to_offline(monkeypatch):
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("MOMUS_LLM_API_KEY", raising=False)
    cfg = LLMConfig.from_env()
    prov = create_provider(cfg)
    assert isinstance(prov, OfflineProvider)  # no key -> offline, never a keyless 401 storm


def test_local_presets(monkeypatch):
    for name, host in (("ollama", "11434"), ("lmstudio", "1234")):
        monkeypatch.setenv("MOMUS_LLM_PROVIDER", name)
        cfg = LLMConfig.from_env()
        assert host in cfg.base_url


def test_metis_preset(monkeypatch):
    monkeypatch.setenv("MOMUS_LLM_PROVIDER", "metis")
    cfg = LLMConfig.from_env()
    assert cfg.provider == ProviderKind.METIS.value
    prov = create_provider(cfg)
    assert prov.kind == ProviderKind.METIS


def test_provider_choices_catalogue():
    names = {c["name"] for c in provider_choices()}
    assert {"offline", "anthropic", "openai", "deepseek", "ollama", "lmstudio", "metis"} <= names
    dpk = next(c for c in provider_choices() if c["name"] == "deepseek")
    assert dpk["needs_key"] is True


@pytest.mark.asyncio
async def test_offline_provider_deterministic():
    p = OfflineProvider(LLMConfig())
    from momus.providers import Message
    a = await p.complete([Message("system", "s"), Message("user", "u")])
    b = await p.complete([Message("system", "s"), Message("user", "u")])
    assert a == b  # deterministic
    assert (await p.health())["offline"] is True
