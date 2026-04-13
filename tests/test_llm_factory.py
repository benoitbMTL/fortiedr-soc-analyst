from __future__ import annotations

import pytest

from fortiedr_mcp.errors import FortiEDRLLMConfigurationError
from fortiedr_mcp.llm.factory import build_llm_client, get_available_llm_options, probe_remote_llm_server
from fortiedr_mcp.llm.openai import OpenAIStructuredLLMClient
from fortiedr_mcp.llm.anthropic import AnthropicStructuredLLMClient
from fortiedr_mcp.llm.ollama import OllamaStructuredLLMClient


def test_build_llm_client_auto_prefers_openai(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("fortiedr_mcp.llm.factory._load_project_dotenv", lambda: None)
    monkeypatch.delenv("FORTIEDR_ANALYSIS_ENGINE_SOURCE", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4.1-mini")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")

    client = build_llm_client("auto")

    assert isinstance(client, OpenAIStructuredLLMClient)


def test_build_llm_client_auto_falls_back_to_anthropic(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("fortiedr_mcp.llm.factory._load_project_dotenv", lambda: None)
    monkeypatch.delenv("FORTIEDR_ANALYSIS_ENGINE_SOURCE", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")

    client = build_llm_client("auto")

    assert isinstance(client, AnthropicStructuredLLMClient)


def test_build_llm_client_requires_supported_credentials(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("fortiedr_mcp.llm.factory._load_project_dotenv", lambda: None)
    monkeypatch.delenv("FORTIEDR_ANALYSIS_ENGINE_SOURCE", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    monkeypatch.delenv("FORTIEDR_LLM_SERVER_PROVIDER", raising=False)
    monkeypatch.delenv("FORTIEDR_LLM_SERVER_URL", raising=False)
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)

    with pytest.raises(FortiEDRLLMConfigurationError):
        build_llm_client("auto")


def test_build_llm_client_supports_ollama(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("fortiedr_mcp.llm.factory._load_project_dotenv", lambda: None)
    monkeypatch.delenv("FORTIEDR_ANALYSIS_ENGINE_SOURCE", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    monkeypatch.setenv("FORTIEDR_LLM_SERVER_PROVIDER", "ollama")
    monkeypatch.setenv("FORTIEDR_LLM_SERVER_URL", "http://10.163.3.76:11434/")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:14b")

    client = build_llm_client("auto")

    assert isinstance(client, OllamaStructuredLLMClient)


def test_build_llm_client_private_engine_source_forces_ollama(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("fortiedr_mcp.llm.factory._load_project_dotenv", lambda: None)
    monkeypatch.setenv("FORTIEDR_ANALYSIS_ENGINE_SOURCE", "private")
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4.1-mini")
    monkeypatch.setenv("FORTIEDR_LLM_SERVER_PROVIDER", "ollama")
    monkeypatch.setenv("FORTIEDR_LLM_SERVER_URL", "http://10.163.3.76:11434/")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:14b")

    client = build_llm_client("auto")

    assert isinstance(client, OllamaStructuredLLMClient)


def test_get_available_llm_options_includes_ollama(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("fortiedr_mcp.llm.factory._load_project_dotenv", lambda: None)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_AVAILABLE_MODELS", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    monkeypatch.delenv("ANTHROPIC_AVAILABLE_MODELS", raising=False)
    monkeypatch.delenv("OLLAMA_AVAILABLE_MODELS", raising=False)
    monkeypatch.setenv("FORTIEDR_ANALYSIS_ENGINE_SOURCE", "private")
    monkeypatch.setenv("FORTIEDR_LLM_SERVER_PROVIDER", "ollama")
    monkeypatch.setenv("FORTIEDR_LLM_SERVER_URL", "http://10.163.3.76:11434/")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:14b")
    monkeypatch.setattr(
        "fortiedr_mcp.llm.factory.OllamaStructuredLLMClient.list_models",
        classmethod(lambda cls, *, base_url, timeout_seconds=5.0: ["qwen2.5:14b", "llama3.2:latest"]),
    )

    options = get_available_llm_options()

    assert options["engine_source"] == "private"
    assert options["default"]["provider"] == "ollama"
    assert options["public_options"] == []
    assert [option["provider"] for option in options["private_options"]] == ["ollama", "ollama"]
    assert [option["model_name"] for option in options["options"]] == ["qwen2.5:14b", "llama3.2:latest"]


def test_probe_remote_llm_server_lists_ollama_models(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "fortiedr_mcp.llm.factory.OllamaStructuredLLMClient.list_models",
        classmethod(lambda cls, *, base_url, timeout_seconds=5.0: ["qwen2.5:14b"]),
    )

    result = probe_remote_llm_server("ollama", base_url="http://10.163.3.76:11434/")

    assert result == {
        "provider": "ollama",
        "base_url": "http://10.163.3.76:11434",
        "models": ["qwen2.5:14b"],
    }
