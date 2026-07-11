from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.errors import ConfigError


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    LLM_PROVIDER: Literal["deepseek", "openai_compatible"] = "deepseek"
    LLM_API_KEY: str | None = None
    LLM_BASE_URL: str | None = None
    LLM_MODEL: str | None = None
    LLM_TEMPERATURE: float = 0.2
    LLM_TIMEOUT_SECONDS: int = 60

    DEEPSEEK_API_KEY: str | None = None
    DEEPSEEK_BASE_URL: str | None = None
    DEEPSEEK_MODEL: str | None = None
    DEEPSEEK_THINKING_ENABLED: bool = True
    DEEPSEEK_REASONING_EFFORT: str = "high"

    EMBEDDING_PROVIDER: Literal["openai_compatible", "gemini", "local", ""] = ""
    EMBEDDING_API_KEY: str | None = None
    EMBEDDING_BASE_URL: str | None = None
    EMBEDDING_MODEL: str | None = None
    LOCAL_EMBEDDING_MODEL: str | None = None
    GEMINI_API_KEY: str | None = None
    GEMINI_EMBEDDING_MODEL: str | None = None
    GEMINI_EMBEDDING_TASK_TYPE: str = "RETRIEVAL_DOCUMENT"
    GEMINI_EMBEDDING_OUTPUT_DIMENSION: int | None = None

    CHROMA_PERSIST_DIR: str = "./data/chroma"
    CHROMA_COLLECTION_NAME: str = "security_knowledge"

    DATABASE_URL: str | None = None

    SIEM_API_URL: str | None = None
    SIEM_API_KEY: str | None = None
    SIEM_VENDOR: str | None = None
    SIEM_VERIFY_SSL: bool = True

    EDR_API_URL: str | None = None
    EDR_API_KEY: str | None = None
    EDR_VENDOR: str | None = None
    EDR_VERIFY_SSL: bool = True

    FIREWALL_API_URL: str | None = None
    FIREWALL_API_KEY: str | None = None
    FIREWALL_VENDOR: str | None = None
    FIREWALL_VERIFY_SSL: bool = True

    NVD_API_KEY: str | None = None
    CISA_KEV_SOURCE_URL: str | None = None
    MITRE_ATTACK_SOURCE_URL: str | None = None
    OWASP_SOURCE_URL: str | None = None

    APP_ENV: str = "development"
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    FRONTEND_PORT: int = 5173

    @property
    def database_url_resolved(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return f"sqlite:///{PROJECT_ROOT / 'data' / 'security_agent.db'}"

    @field_validator("GEMINI_EMBEDDING_OUTPUT_DIMENSION", mode="before")
    @classmethod
    def blank_int_to_none(cls, value):
        if value == "":
            return None
        return value

    @property
    def chroma_persist_path(self) -> Path:
        path = Path(self.CHROMA_PERSIST_DIR)
        return path if path.is_absolute() else PROJECT_ROOT / path

    @property
    def raw_data_dir(self) -> Path:
        return PROJECT_ROOT / "data" / "raw"

    @property
    def log_data_dir(self) -> Path:
        return PROJECT_ROOT / "data" / "logs"


@lru_cache
def get_settings() -> Settings:
    return Settings()


def require_llm_config(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if settings.LLM_PROVIDER == "deepseek":
        missing = [
            key
            for key, value in {
                "DEEPSEEK_API_KEY": settings.DEEPSEEK_API_KEY,
                "DEEPSEEK_BASE_URL": settings.DEEPSEEK_BASE_URL,
                "DEEPSEEK_MODEL": settings.DEEPSEEK_MODEL,
            }.items()
            if not value
        ]
        if missing:
            raise ConfigError(f"Missing DeepSeek configuration: {', '.join(missing)}")
    elif settings.LLM_PROVIDER == "openai_compatible":
        missing = [
            key
            for key, value in {
                "LLM_API_KEY": settings.LLM_API_KEY,
                "LLM_BASE_URL": settings.LLM_BASE_URL,
                "LLM_MODEL": settings.LLM_MODEL,
            }.items()
            if not value
        ]
        if missing:
            raise ConfigError(f"Missing OpenAI-compatible LLM configuration: {', '.join(missing)}")


def require_embedding_config(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    if settings.EMBEDDING_PROVIDER == "openai_compatible":
        missing = [
            key
            for key, value in {
                "EMBEDDING_API_KEY": settings.EMBEDDING_API_KEY,
                "EMBEDDING_BASE_URL": settings.EMBEDDING_BASE_URL,
                "EMBEDDING_MODEL": settings.EMBEDDING_MODEL,
            }.items()
            if not value
        ]
        if missing:
            raise ConfigError(f"Missing embedding configuration: {', '.join(missing)}")
    elif settings.EMBEDDING_PROVIDER == "local":
        if not settings.LOCAL_EMBEDDING_MODEL:
            raise ConfigError("Missing embedding configuration: LOCAL_EMBEDDING_MODEL")
    elif settings.EMBEDDING_PROVIDER == "gemini":
        missing = [
            key
            for key, value in {
                "GEMINI_API_KEY": settings.GEMINI_API_KEY,
                "GEMINI_EMBEDDING_MODEL": settings.GEMINI_EMBEDDING_MODEL,
            }.items()
            if not value
        ]
        if missing:
            raise ConfigError(f"Missing Gemini embedding configuration: {', '.join(missing)}")
    else:
        raise ConfigError("Embedding is not configured. Set EMBEDDING_PROVIDER and model settings.")


def missing_required_config(settings: Settings | None = None) -> list[str]:
    settings = settings or get_settings()
    missing: list[str] = []
    try:
        require_llm_config(settings)
    except ConfigError as exc:
        missing.extend(_extract_names(str(exc)))
    try:
        require_embedding_config(settings)
    except ConfigError as exc:
        missing.extend(_extract_names(str(exc)))
    return sorted(set(missing))


def _extract_names(message: str) -> list[str]:
    names = []
    for token in message.replace(":", " ").replace(",", " ").split():
        if token.isupper() and "_" in token:
            names.append(token)
    if "Embedding is not configured" in message:
        names.append("EMBEDDING_PROVIDER")
    return names
