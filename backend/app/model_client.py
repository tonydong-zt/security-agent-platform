from __future__ import annotations

from typing import Any

import httpx
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.prompts import ChatPromptTemplate
from pydantic import Field, SecretStr

from .config import config_store


class ModelNotConfiguredError(RuntimeError):
    """Analysis must never silently fall back to a model-free report."""


class ModelExecutionError(RuntimeError):
    def __init__(
        self,
        stage: str,
        code: str,
        message: str,
        diagnostic: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.code = code
        self.message = message
        self.diagnostic = diagnostic or {}


def require_model() -> None:
    if not config_store.api_key():
        raise ModelNotConfiguredError(
            "未配置大模型，无法启动研判。请先在“模型供应商”中配置并测试连接。"
        )


def get_transport() -> httpx.AsyncBaseTransport | None:
    """Production uses real HTTP; tests may inject an isolated MockTransport."""
    return None


class CompatibleChatModel(BaseChatModel):
    """Native async LangChain chat model for the existing compatible providers."""

    api_key: SecretStr = Field(exclude=True, repr=False)
    base_url: str
    model_name: str
    provider: str
    max_tokens: int = 4_500
    transport: Any = Field(default=None, exclude=True, repr=False)
    request_tools: list[dict[str, Any]] | None = Field(default=None, exclude=True)

    @property
    def _llm_type(self) -> str:
        return "security-openai-compatible"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {"model": self.model_name, "provider": self.provider}

    def _generate(
        self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs
    ) -> ChatResult:
        raise NotImplementedError(
            "Use ainvoke: this model performs native asynchronous HTTP requests."
        )

    async def _agenerate(
        self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs
    ) -> ChatResult:
        roles = {"system": "system", "human": "user", "ai": "assistant"}
        payload: dict[str, Any] = {
            "model": self.model_name,
            "messages": [
                {"role": roles[item.type], "content": item.content} for item in messages
            ],
            "stream": False,
            "max_tokens": self.max_tokens,
        }
        if stop:
            payload["stop"] = stop
        if self.request_tools:
            payload.update(tools=self.request_tools, tool_choice="auto")
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(180.0, connect=20.0), transport=self.transport
        ) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key.get_secret_value()}"},
                json=payload,
            )
        response.raise_for_status()
        data = response.json()
        choices = data.get("choices") or []
        if not choices:
            raise ValueError("模型接口未返回 choices")
        choice = choices[0]
        if choice.get("finish_reason") in {"length", "content_filter"}:
            raise ValueError("模型输出被截断或过滤，不能作为完整推理结果")
        message = choice.get("message") or {}
        content = message.get("content") or ""
        if not isinstance(content, str) or (
            not content.strip() and not message.get("tool_calls")
        ):
            raise ValueError("模型接口未返回有效内容")
        metadata = {
            "model": data.get("model", self.model_name),
            "provider": self.provider,
            "usage": data.get("usage") or {},
            "tool_calls": message.get("tool_calls") or [],
        }
        return ChatResult(
            generations=[
                ChatGeneration(
                    message=AIMessage(content=content, response_metadata=metadata)
                )
            ]
        )


async def chat(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 4_500,
    transport: httpx.AsyncBaseTransport | None = None,
    tools: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    require_model()
    model = CompatibleChatModel(
        api_key=SecretStr(config_store.api_key()),
        base_url=config_store.base_url,
        model_name=config_store.model,
        provider=config_store.provider,
        max_tokens=max_tokens,
        transport=transport if transport is not None else get_transport(),
        request_tools=tools,
        cache=False,
    )
    # Prompt values are data: braces in alerts/feedback cannot alter the template.
    prompt = ChatPromptTemplate.from_messages(
        [("system", "{policy}"), ("human", "{context}")]
    )
    chain = (prompt | model).with_config(run_name="security_llm_call")
    response = await chain.ainvoke({"policy": system_prompt, "context": user_prompt})
    return {"content": response.content, **response.response_metadata}
