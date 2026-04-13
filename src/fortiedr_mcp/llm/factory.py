from __future__ import annotations

from pathlib import Path
import os

from dotenv import load_dotenv

from fortiedr_mcp.errors import FortiEDRLLMConfigurationError
from fortiedr_mcp.llm.anthropic import AnthropicStructuredLLMClient
from fortiedr_mcp.llm.ollama import OllamaStructuredLLMClient, normalize_ollama_base_url
from fortiedr_mcp.llm.openai import OpenAIStructuredLLMClient


DEFAULT_OPENAI_MODELS = [
    "gpt-4.1-nano",
    "gpt-4.1-mini",
    "gpt-4.1",
    "gpt-4o-mini",
    "gpt-4o",
]
DEFAULT_OLLAMA_PROVIDER = "ollama"
PUBLIC_LLM_PROVIDERS = {"openai", "anthropic"}


def _load_project_dotenv() -> None:
    dotenv_path = Path(__file__).resolve().parents[3] / ".env"
    if dotenv_path.exists():
        load_dotenv(dotenv_path, override=False)


def _csv_models(env_name: str, default_model: str | None, *, fallback_models: list[str] | None = None) -> list[str]:
    configured = [item.strip() for item in os.getenv(env_name, "").split(",") if item.strip()]
    models: list[str] = []
    candidates = [default_model, *configured]
    if not configured and fallback_models:
        candidates.extend(fallback_models)
    for candidate in candidates:
        if candidate and candidate not in models:
            models.append(candidate)
    return models


def _configured_remote_llm_provider() -> str | None:
    provider = os.getenv("FORTIEDR_LLM_SERVER_PROVIDER", "").strip().lower()
    if provider:
        return provider
    if os.getenv("FORTIEDR_LLM_SERVER_URL") or os.getenv("OLLAMA_BASE_URL"):
        return DEFAULT_OLLAMA_PROVIDER
    return None


def _configured_engine_source() -> str:
    configured = os.getenv("FORTIEDR_ANALYSIS_ENGINE_SOURCE", "").strip().lower()
    if configured in {"public", "private"}:
        return configured
    if _configured_remote_llm_url() and not (
        (os.getenv("OPENAI_API_KEY") and os.getenv("OPENAI_MODEL"))
        or (os.getenv("ANTHROPIC_API_KEY") and os.getenv("ANTHROPIC_MODEL"))
    ):
        return "private"
    return "public"


def _configured_remote_llm_url() -> str:
    return os.getenv("FORTIEDR_LLM_SERVER_URL") or os.getenv("OLLAMA_BASE_URL", "")


def _ollama_models_from_env() -> list[str]:
    base_url = _configured_remote_llm_url()
    configured_default = os.getenv("OLLAMA_MODEL", "")
    fallback_models = _csv_models("OLLAMA_AVAILABLE_MODELS", configured_default)
    if not base_url:
        return fallback_models

    timeout_raw = os.getenv("OLLAMA_DISCOVERY_TIMEOUT_SECONDS", "5")
    try:
        timeout_seconds = float(timeout_raw)
    except ValueError:
        timeout_seconds = 5.0

    try:
        discovered_models = OllamaStructuredLLMClient.list_models(
            base_url=base_url,
            timeout_seconds=max(1.0, timeout_seconds),
        )
    except Exception:
        discovered_models = []

    models: list[str] = []
    for candidate in [configured_default, *discovered_models, *fallback_models]:
        if candidate and candidate not in models:
            models.append(candidate)
    return models


def get_available_llm_options() -> dict:
    _load_project_dotenv()
    options: list[dict[str, str]] = []
    public_options: list[dict[str, str]] = []
    private_options: list[dict[str, str]] = []

    openai_default = os.getenv("OPENAI_MODEL", "")
    if os.getenv("OPENAI_API_KEY"):
        for model_name in _csv_models(
            "OPENAI_AVAILABLE_MODELS",
            openai_default,
            fallback_models=DEFAULT_OPENAI_MODELS,
        ):
            option = {
                "provider": "openai",
                "model_name": model_name,
                "label": f"OpenAI · {model_name}",
            }
            public_options.append(option)

    anthropic_default = os.getenv("ANTHROPIC_MODEL", "")
    if os.getenv("ANTHROPIC_API_KEY"):
        for model_name in _csv_models("ANTHROPIC_AVAILABLE_MODELS", anthropic_default):
            option = {
                "provider": "anthropic",
                "model_name": model_name,
                "label": f"Anthropic · {model_name}",
            }
            public_options.append(option)

    if _configured_remote_llm_provider() == DEFAULT_OLLAMA_PROVIDER:
        for model_name in _ollama_models_from_env():
            option = {
                "provider": DEFAULT_OLLAMA_PROVIDER,
                "model_name": model_name,
                "label": f"Ollama · {model_name}",
            }
            private_options.append(option)

    options.extend(public_options)
    options.extend(private_options)
    engine_source = _configured_engine_source()
    if engine_source == "private":
        default_option = private_options[0] if private_options else public_options[0] if public_options else None
    else:
        default_option = public_options[0] if public_options else private_options[0] if private_options else None

    return {
        "engine_source": engine_source,
        "default": default_option,
        "options": options,
        "public_options": public_options,
        "private_options": private_options,
    }


def build_llm_client(provider: str = "auto", *, model_name: str | None = None):
    _load_project_dotenv()
    normalized = provider.strip().lower()
    if normalized == "auto":
        engine_source = _configured_engine_source()
        if engine_source == "private":
            if _configured_remote_llm_provider() == DEFAULT_OLLAMA_PROVIDER and _configured_remote_llm_url():
                return OllamaStructuredLLMClient.from_env(model_name=model_name)
            raise FortiEDRLLMConfigurationError(
                "Private LLM server mode is enabled, but remote Ollama settings are incomplete."
            )
        if os.getenv("OPENAI_API_KEY") and os.getenv("OPENAI_MODEL"):
            return OpenAIStructuredLLMClient.from_env(model_name=model_name)
        if os.getenv("ANTHROPIC_API_KEY") and os.getenv("ANTHROPIC_MODEL"):
            return AnthropicStructuredLLMClient.from_env(model_name=model_name)
        if os.getenv("OPENAI_API_KEY"):
            return OpenAIStructuredLLMClient.from_env(model_name=model_name)
        if os.getenv("ANTHROPIC_API_KEY"):
            return AnthropicStructuredLLMClient.from_env(model_name=model_name)
        if _configured_remote_llm_provider() == DEFAULT_OLLAMA_PROVIDER and _configured_remote_llm_url():
            return OllamaStructuredLLMClient.from_env(model_name=model_name)
        raise FortiEDRLLMConfigurationError(
            "No supported LLM credentials configured. Set OpenAI, Anthropic, or remote Ollama settings."
        )
    if normalized == "openai":
        return OpenAIStructuredLLMClient.from_env(model_name=model_name)
    if normalized == "anthropic":
        return AnthropicStructuredLLMClient.from_env(model_name=model_name)
    if normalized == DEFAULT_OLLAMA_PROVIDER:
        return OllamaStructuredLLMClient.from_env(model_name=model_name)
    raise FortiEDRLLMConfigurationError(f"Unsupported LLM provider: {provider}")


def probe_remote_llm_server(provider: str, *, base_url: str) -> dict:
    normalized = provider.strip().lower()
    if normalized == DEFAULT_OLLAMA_PROVIDER:
        normalized_url = normalize_ollama_base_url(base_url)
        models = OllamaStructuredLLMClient.list_models(base_url=normalized_url, timeout_seconds=5.0)
        return {
            "provider": DEFAULT_OLLAMA_PROVIDER,
            "base_url": normalized_url,
            "models": models,
        }
    raise FortiEDRLLMConfigurationError(f"Unsupported remote LLM provider: {provider}")
