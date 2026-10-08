from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .agent_tools import tool_registry
from .analysis import analyze, chain_definition
from .config import config_store
from .knowledge import get_knowledge_service
from .memory import memory_store
from .model_client import ModelExecutionError, ModelNotConfiguredError, chat

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"


class SearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2_000)
    limit: int = Field(default=6, ge=1, le=12)


class AnalyzeRequest(BaseModel):
    alert: dict[str, Any] | str
    requirement: str = Field(default="", max_length=4_000)
    use_model: bool = True
    use_deepseek: bool | None = None


class ToolExecuteRequest(BaseModel):
    tool: str = Field(min_length=1, max_length=80)
    arguments: dict[str, Any] = Field(default_factory=dict)


class FeedbackRequest(BaseModel):
    memory_id: str = Field(min_length=8, max_length=64)
    liked: bool
    comment: str = Field(default="", max_length=2_000)
    learn: bool = False


class ConfigRequest(BaseModel):
    api_key: str = Field(min_length=8, max_length=512)
    provider: str = "deepseek"
    model: str = "deepseek-chat"
    base_url: str = ""
    persist: bool = True


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    service = get_knowledge_service()
    if not service.status()["ready"]:
        raise RuntimeError("内置 Chroma 知识库为空")
    yield


app = FastAPI(
    title="AI Security Local",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
    lifespan=lifespan,
)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    status = get_knowledge_service().status()
    return {
        "status": "ok",
        "database": "not-used",
        "chroma_chunks": status["chunk_count"],
        "model_configured": config_store.public()["configured"],
        "deepseek_configured": config_store.public()["configured"],
        "memory_inputs": memory_store.status()["input_count"],
    }


@app.get("/api/knowledge/status")
def knowledge_status() -> dict[str, Any]:
    return get_knowledge_service().status()


@app.post("/api/knowledge/search")
def knowledge_search(payload: SearchRequest) -> dict[str, Any]:
    return {
        "query": payload.query,
        "results": get_knowledge_service().search(payload.query, payload.limit),
    }


@app.get("/api/tools")
def list_tools() -> dict[str, Any]:
    tools = tool_registry.catalog()
    return {"tools": tools, "total": len(tools), "execution_policy": "read-only"}


@app.get("/api/agent/chain")
def agent_chain() -> dict[str, Any]:
    return {
        "nodes": chain_definition(),
        "framework": "langchain",
        "llm_required": True,
        "policy": "LLM 证据研判、报告生成、独立复核为必经节点；无模型或失败不生成报告。工具只读，历史经验不是当前证据。",
    }


@app.post("/api/tools/execute")
def execute_tool(payload: ToolExecuteRequest) -> dict[str, Any]:
    try:
        return tool_registry.execute(payload.tool, payload.arguments)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.get("/api/memory/status")
def memory_status() -> dict[str, Any]:
    return memory_store.status()


@app.get("/api/memory/recent")
def memory_recent(limit: int = 20) -> dict[str, Any]:
    return {"records": memory_store.recent(max(1, min(limit, 100)))}


@app.post("/api/memory/feedback")
async def memory_feedback(payload: FeedbackRequest) -> dict[str, Any]:
    try:
        return await memory_store.submit_feedback(
            payload.memory_id,
            payload.liked,
            payload.comment,
            payload.learn,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/analyze")
async def analyze_alert(payload: AnalyzeRequest) -> dict[str, Any]:
    try:
        if payload.use_deepseek is False:
            raise ValueError("不支持关闭模型；请移除 use_deepseek=false 并配置模型。")
        return await analyze(payload.alert, payload.requirement, payload.use_model)
    except ModelNotConfiguredError as error:
        raise HTTPException(
            status_code=503,
            detail={"code": "MODEL_NOT_CONFIGURED", "message": str(error)},
        ) from error
    except ModelExecutionError as error:
        diagnostic = error.diagnostic if isinstance(error.diagnostic, dict) else {}
        raise HTTPException(
            status_code=502,
            detail={
                "code": error.code,
                "stage": error.stage,
                "message": error.message,
                "diagnostic": diagnostic,
            },
        ) from error
    except json.JSONDecodeError as error:
        raise HTTPException(
            status_code=422, detail=f"告警 JSON 无效：{error}"
        ) from error
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except httpx.HTTPStatusError as error:
        detail = _model_http_error(error.response)
        raise HTTPException(status_code=502, detail=detail) from error
    except httpx.HTTPError as error:
        raise HTTPException(
            status_code=502, detail=f"模型接口连接失败：{error}"
        ) from error


@app.get("/api/config/model")
def model_config() -> dict[str, object]:
    return config_store.public()


@app.put("/api/config/model")
def save_model_config(payload: ConfigRequest) -> dict[str, object]:
    try:
        return config_store.configure(
            payload.api_key,
            payload.model,
            payload.persist,
            payload.provider,
            payload.base_url,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.delete("/api/config/model")
def clear_model_config() -> dict[str, object]:
    return config_store.clear()


@app.post("/api/config/model/test")
async def test_model() -> dict[str, Any]:
    try:
        result = await chat(
            "你是 API 连通性测试助手。", "只回复：连接成功", max_tokens=30
        )
        return {"ok": True, **result}
    except (ValueError, ModelNotConfiguredError) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except httpx.HTTPStatusError as error:
        raise HTTPException(
            status_code=502, detail=_model_http_error(error.response)
        ) from error
    except httpx.HTTPError as error:
        raise HTTPException(
            status_code=502, detail=f"模型接口连接失败：{error}"
        ) from error


# 兼容旧前端和已有自动化调用；新界面统一使用 /api/config/model。
app.add_api_route("/api/config/deepseek", model_config, methods=["GET"])
app.add_api_route("/api/config/deepseek", save_model_config, methods=["PUT"])
app.add_api_route("/api/config/deepseek", clear_model_config, methods=["DELETE"])
app.add_api_route("/api/config/deepseek/test", test_model, methods=["POST"])


if (FRONTEND_DIST / "assets").exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")


@app.get("/{path:path}", response_class=HTMLResponse)
def frontend(path: str = "") -> HTMLResponse:
    if path == "api" or path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API endpoint not found")
    index = FRONTEND_DIST / "index.html"
    if not index.exists():
        raise HTTPException(
            status_code=503, detail="前端尚未构建，请运行 npm run build"
        )
    return HTMLResponse(index.read_text(encoding="utf-8"))


def _model_http_error(response: httpx.Response) -> str:
    try:
        payload = response.json()
        message = payload.get("error", {}).get("message") or payload.get("message")
    except ValueError:
        message = ""
    return f"模型 API 返回 HTTP {response.status_code}：{message or '请求失败'}"
