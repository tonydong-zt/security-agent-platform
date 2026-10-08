from __future__ import annotations

import json

import httpx
import pytest
from app import config, memory, model_client
from app.config import config_store
from app.llm_reasoning import REPORT_SECTIONS


@pytest.fixture(autouse=True)
def isolated_memory(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    memory_root = tmp_path / "memory"
    monkeypatch.setattr(memory, "MEMORY_ROOT", memory_root)
    monkeypatch.setattr(memory, "INPUTS_PATH", memory_root / "inputs.jsonl")
    monkeypatch.setattr(memory, "RESULTS_PATH", memory_root / "results.jsonl")
    monkeypatch.setattr(memory, "FEEDBACK_PATH", memory_root / "feedback.jsonl")
    monkeypatch.setattr(memory, "LEARNED_PATH", memory_root / "learned_patterns.jsonl")


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch):
    # Never read, write or delete the user's Windows credentials during tests.
    for name in ("MODEL_API_KEY", "DEEPSEEK_API_KEY", "MODEL_NAME", "MODEL_BASE_URL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config_store, "_runtime_key", "")
    monkeypatch.setattr(config_store, "_config", config.ModelConfig())
    credentials = {}
    monkeypatch.setattr(
        config.keyring,
        "get_password",
        lambda service, account: credentials.get((service, account)),
    )
    monkeypatch.setattr(
        config.keyring,
        "set_password",
        lambda service, account, password: credentials.update(
            {(service, account): password}
        ),
    )
    monkeypatch.setattr(
        config.keyring,
        "delete_password",
        lambda service, account: credentials.pop((service, account), None),
    )


@pytest.fixture
def mock_llm(monkeypatch):
    """HTTP-only test double: real LCEL, prompts, model adapter and parsers execute."""
    config_store.configure("sk-isolated-test-key", "test-model", persist=False)
    requests = []
    overrides = {}

    def handler(request):
        payload = json.loads(request.content)
        messages = payload["messages"]
        policy = messages[0]["content"]
        context = json.loads(messages[1]["content"])
        if "FeedbackLesson" in policy:
            stage = "feedback_learning"
            comment = context["feedback"]["comment"]
            value = {
                "learnable": True,
                "reason": "模拟模型识别出具体可核验的反馈。",
                "error_pattern": "缺少执行证据却提升确定性。",
                "correction": "用户指出" + comment + "；必须独立核查当前证据。",
                "applicability": "相似告警缺少执行侧证据时",
                "verification_steps": ["核对执行日志，避免仅凭HTTP状态确认利用。"],
            }
        elif "ReviewDecision" in policy:
            stage = "report_review"
            value = {"approved": True, "issues": [], "correction_instructions": []}
        elif "Assessment" in policy:
            stage = "evidence_reasoning"
            current = [
                item
                for item in context["evidence_store"]["items"]
                if item["applicable"]
                and item["provenance"]["event_layer"] == 0
                and item["provenance"]["describes_current_event"]
            ]
            value = {
                "conclusion": "模拟模型结论：现有证据不足以确认利用成功，需要执行侧证据。",
                "primary_scenario": "模拟模型独立场景判断",
                "verdict": "insufficient_evidence",
                "confidence": 37,
                "confirmed_facts": [
                    {
                        "statement": "已观察到输入字段。",
                        "evidence_ids": [current[0]["evidence_id"]],
                    }
                ]
                if current
                else [],
                "hypotheses": ["需进一步核验异常请求的实际影响。"],
                "evidence_gaps": ["缺少可交叉验证的执行记录。"],
                "recommended_checks": ["核查相关执行审计。"],
                "feedback_checks": [
                    {
                        "lesson_id": item["lesson_id"],
                        "applicable": True,
                        "check": "已核查纠错原则：" + item["learning_directive"],
                    }
                    for item in context.get("memory_insights", [])
                ],
            }
        else:
            stage = "report_generation"
            # Deliberately synthetic report, never used by application production code.
            body = (
                "这是自动化测试模拟的模型报告，不能用于真实事件处置。当前事实范围仅限提供的告警证据。"
                "应核对应用访问日志、认证上下文、账号授权范围和执行侧审计，并保留时间与来源的对应关系。"
                "字段未提供时应列为待确认，不应补全成肯定结论；工具风险分数属于规则计算指标，不代表模型判断概率。"
                "相关检查建议由分析员审批后开展，本报告没有执行任何操作。历史反馈仅作为自检提示，必须由当前证据重新验证。"
            )
            value = "# 模拟 LLM 报告\n" + context["llm_assessment"]["conclusion"] + "\n"
            value += "\n".join(
                f"## {section}\n\n{body}\n" for section in REPORT_SECTIONS
            )
            value += "\n".join(
                f"[{item['id']}] 知识引用" for item in context["citations"]
            )
            value += "\n".join(
                f"<!-- chart:{item['id']} -->" for item in context["charts"]
            )
        requests.append({"stage": stage, "context": context, "payload": payload})
        override = overrides.get(stage)
        if override is not None:
            if isinstance(override, Exception):
                raise override
            if callable(override):
                value = override(value, context)
            elif isinstance(override, httpx.Response):
                return override
            else:
                value = override
        content = (
            value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        )
        return httpx.Response(
            200,
            json={
                "model": "test-model",
                "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 20,
                    "total_tokens": 30,
                },
            },
        )

    monkeypatch.setattr(
        model_client, "get_transport", lambda: httpx.MockTransport(handler)
    )
    return {"requests": requests, "overrides": overrides}
