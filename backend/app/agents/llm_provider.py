from __future__ import annotations

from langchain_openai import ChatOpenAI

from app.config import Settings, get_settings, require_llm_config


def get_chat_model(settings: Settings | None = None) -> ChatOpenAI:
    settings = settings or get_settings()
    require_llm_config(settings)

    if settings.LLM_PROVIDER == "deepseek":
        extra_body = None
        if settings.DEEPSEEK_THINKING_ENABLED:
            extra_body = {"reasoning_effort": settings.DEEPSEEK_REASONING_EFFORT}
        kwargs = {
            "api_key": settings.DEEPSEEK_API_KEY,
            "base_url": settings.DEEPSEEK_BASE_URL,
            "model": settings.DEEPSEEK_MODEL,
            "temperature": settings.LLM_TEMPERATURE,
            "timeout": settings.LLM_TIMEOUT_SECONDS,
        }
        if extra_body:
            kwargs["extra_body"] = extra_body
        return ChatOpenAI(**kwargs)

    return ChatOpenAI(
        api_key=settings.LLM_API_KEY,
        base_url=settings.LLM_BASE_URL,
        model=settings.LLM_MODEL,
        temperature=settings.LLM_TEMPERATURE,
        timeout=settings.LLM_TIMEOUT_SECONDS,
    )


def check_llm_status(settings: Settings | None = None) -> tuple[str, str | None]:
    settings = settings or get_settings()
    try:
        require_llm_config(settings)
        return "ok", None
    except Exception as exc:
        return "missing_config", str(exc)
