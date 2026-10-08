from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from urllib.parse import urlparse

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

SERVICE_NAME = "AI-Security-Local-Model"
LEGACY_SERVICE_NAME = "AI-Security-Local-DeepSeek"
ACCOUNT_NAME = "default"

PROVIDER_PRESETS: dict[str, dict[str, object]] = {
    "deepseek": {
        "label": "DeepSeek",
        "base_url": "https://api.deepseek.com",
        "default_model": "deepseek-chat",
        "models": ["deepseek-chat", "deepseek-reasoner"],
    },
    "openai-compatible": {
        "label": "OpenAI-compatible",
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-5",
        "models": ["gpt-5"],
    },
    "custom": {
        "label": "自定义兼容接口",
        "base_url": "http://127.0.0.1:11434/v1",
        "default_model": "local-model",
        "models": [],
    },
}


@dataclass
class ModelConfig:
    provider: str = "deepseek"
    model: str = "deepseek-chat"
    base_url: str = "https://api.deepseek.com"


class ConfigStore:
    def __init__(self) -> None:
        provider = os.getenv("MODEL_PROVIDER", "deepseek").strip() or "deepseek"
        if provider not in PROVIDER_PRESETS:
            provider = "custom"
        preset = PROVIDER_PRESETS[provider]
        model = (
            os.getenv("MODEL_NAME")
            or os.getenv("DEEPSEEK_MODEL")
            or str(preset["default_model"])
        )
        base_url = (
            os.getenv("MODEL_BASE_URL")
            or os.getenv("DEEPSEEK_BASE_URL")
            or str(preset["base_url"])
        )
        self._runtime_key = ""
        self._config = ModelConfig(provider=provider, model=model, base_url=base_url)
        self._lock = threading.Lock()

    def api_key(self) -> str:
        environment_key = (
            os.getenv("MODEL_API_KEY") or os.getenv("DEEPSEEK_API_KEY") or ""
        ).strip()
        if environment_key:
            return environment_key
        with self._lock:
            if self._runtime_key:
                return self._runtime_key
        stored = self._read_stored()
        if not stored:
            return ""
        try:
            payload = json.loads(stored)
        except (TypeError, ValueError, json.JSONDecodeError):
            return stored
        if not isinstance(payload, dict):
            return ""
        self._apply_stored_config(payload)
        return str(payload.get("api_key", ""))

    def _read_stored(self) -> str:
        for service in (SERVICE_NAME, LEGACY_SERVICE_NAME):
            try:
                stored = keyring.get_password(service, ACCOUNT_NAME) or ""
            except KeyringError:
                continue
            if stored:
                return stored
        return ""

    def _apply_stored_config(self, payload: dict[str, object]) -> None:
        if "MODEL_NAME" in os.environ or "MODEL_BASE_URL" in os.environ:
            return
        provider = str(payload.get("provider", "deepseek"))
        if provider not in PROVIDER_PRESETS:
            provider = "custom"
        model = str(payload.get("model", "")).strip()
        base_url = str(payload.get("base_url", "")).strip()
        if not model:
            model = str(PROVIDER_PRESETS[provider]["default_model"])
        if not base_url:
            base_url = str(PROVIDER_PRESETS[provider]["base_url"])
        try:
            _validate_base_url(base_url)
        except ValueError:
            return
        with self._lock:
            self._config = ModelConfig(provider, model, base_url)

    def public(self) -> dict[str, object]:
        key = self.api_key()
        preset = PROVIDER_PRESETS.get(self._config.provider, PROVIDER_PRESETS["custom"])
        return {
            "configured": bool(key),
            "masked_key": f"{key[:3]}***{key[-4:]}" if len(key) >= 8 else "",
            "provider": self._config.provider,
            "provider_label": preset["label"],
            "model": self._config.model,
            "base_url": self._config.base_url,
            "storage": "环境变量或 Windows 凭据管理器",
            "providers": [
                {
                    "id": provider_id,
                    "label": item["label"],
                    "base_url": item["base_url"],
                    "default_model": item["default_model"],
                    "models": item["models"],
                }
                for provider_id, item in PROVIDER_PRESETS.items()
            ],
        }

    def configure(
        self,
        api_key: str,
        model: str,
        persist: bool,
        provider: str = "deepseek",
        base_url: str = "",
    ) -> dict[str, object]:
        key = api_key.strip()
        if len(key) < 8:
            raise ValueError("API Key 长度不正确")
        if provider not in PROVIDER_PRESETS:
            raise ValueError("不支持的模型供应商")
        selected_model = model.strip()
        if not selected_model or len(selected_model) > 128:
            raise ValueError("模型名称不正确")
        selected_url = base_url.strip() or str(PROVIDER_PRESETS[provider]["base_url"])
        _validate_base_url(selected_url)
        with self._lock:
            self._config = ModelConfig(
                provider, selected_model, selected_url.rstrip("/")
            )
            self._runtime_key = key
        if persist:
            try:
                keyring.set_password(
                    SERVICE_NAME,
                    ACCOUNT_NAME,
                    json.dumps(
                        {
                            "api_key": key,
                            "provider": provider,
                            "model": selected_model,
                            "base_url": selected_url.rstrip("/"),
                        }
                    ),
                )
            except KeyringError as error:
                raise ValueError(f"无法写入 Windows 凭据管理器：{error}") from error
        return self.public()

    def clear(self) -> dict[str, object]:
        with self._lock:
            self._runtime_key = ""
        for service in (SERVICE_NAME, LEGACY_SERVICE_NAME):
            try:
                keyring.delete_password(service, ACCOUNT_NAME)
            except (KeyringError, PasswordDeleteError):
                pass
        return self.public()

    @property
    def model(self) -> str:
        return self._config.model

    @property
    def provider(self) -> str:
        return self._config.provider

    @property
    def base_url(self) -> str:
        return self._config.base_url.rstrip("/")


def _validate_base_url(value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("接口地址必须是有效的 HTTP(S) URL")
    if parsed.scheme == "http" and parsed.hostname not in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        raise ValueError("非本机模型接口必须使用 HTTPS")


config_store = ConfigStore()
