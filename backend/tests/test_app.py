from __future__ import annotations

import asyncio
import json
from dataclasses import replace

import httpx
import pytest
from app.agent_tools import (
    ToolExecutionError,
    assess_event_layers,
    build_timeline,
    calculate_risk,
    detect_contradictions,
    evidence_matrix,
    extract_iocs,
    extract_security_entities,
    tool_registry,
)
from app.analysis import analyze
from app.business_context import infer_business_context
from app.config import config_store
from app.embeddings import LocalSecurityEmbeddings
from app.main import app
from app.model_client import chat
from app.normalization import (
    normalize_alert,
    parse_http_request,
    parse_http_response,
)
from app.review import semantic_review
from app.scenarios import generate_scene_candidates, select_primary_scene
from fastapi.testclient import TestClient


def test_local_embeddings_are_deterministic_and_normalized() -> None:
    embeddings = LocalSecurityEmbeddings()
    first = embeddings.embed_query("SQL 注入 参数化查询")
    second = embeddings.embed_query("SQL 注入 参数化查询")
    assert first == second
    assert len(first) == 384
    assert abs(sum(value * value for value in first) - 1.0) < 1e-9


def test_bundled_chroma_and_llm_analysis_are_ready(mock_llm) -> None:
    with TestClient(app) as client:
        health = client.get("/healthz")
        assert health.status_code == 200
        assert health.json()["database"] == "not-used"
        assert health.json()["chroma_chunks"] > 1_000

        search = client.post(
            "/api/knowledge/search",
            json={"query": "SQL 注入 参数化查询", "limit": 4},
        )
        assert search.status_code == 200
        assert search.json()["results"]

        analysis = client.post(
            "/api/analyze",
            json={
                "alert": {"name": "SQL 注入", "url": "?id=1 UNION SELECT"},
                "use_deepseek": True,
            },
        )
        assert analysis.status_code == 200
        payload = analysis.json()
        assert payload["database_used"] is False
        assert payload["citations"]
        assert payload["charts"]
        assert len(payload["reasoning_trace"]) == 10
        assert [item["agent_id"] for item in payload["agent_chain"]] == [
            "planner",
            "evidence",
            "memory",
            "risk",
            "report",
            "review",
        ]
        assert payload["review"]["approved"] is True
        assert payload["memory_id"].startswith("MEM-")
        assert payload["summary"]["risk_score"] > 0
        assert payload["summary"]["confidence_level"] in {"低", "中", "高"}
        assert "<!-- chart:risk-dimensions -->" in payload["report_markdown"]
        assert len(payload["report_markdown"]) >= 2400
        assert payload["framework"] == "langchain"
        assert payload["summary"]["key_finding"] == payload["llm_assessment"]["conclusion"]
        assert payload["summary"]["confidence_score"] == 37
        assert payload["summary"]["primary_scenario"] == "模拟模型独立场景判断"
        assert [call["stage"] for call in payload["model_calls"]] == [
            "evidence_reasoning", "report_generation", "report_review"
        ]
        assert payload["usage"]["total_tokens"] == 90
        assert all(call["success"] and not call["fallback_used"] for call in payload["model_calls"])


def test_memory_records_every_input_and_learns_only_after_explicit_feedback_authorization(mock_llm) -> None:
    with TestClient(app) as client:
        first = client.post(
            "/api/analyze",
            json={
                "alert": {
                    "name": "SQL 注入",
                    "url": "?id=1 UNION SELECT",
                    "srcIp": "198.51.100.10",
                },
                "use_model": True,
            },
        )
        assert first.status_code == 200
        memory_id = first.json()["memory_id"]

        status = client.get("/api/memory/status")
        assert status.status_code == 200
        assert status.json()["input_count"] == 1
        assert status.json()["learned_count"] == 0

        feedback = client.post(
            "/api/memory/feedback",
            json={
                "memory_id": memory_id,
                "liked": True,
                "comment": "SQL 注入研判和证据矩阵有帮助",
                "learn": True,
            },
        )
        assert feedback.status_code == 200
        assert feedback.json()["learning"]["created"] is True

        second = client.post(
            "/api/analyze",
            json={
                "alert": {"name": "SQL 注入", "url": "?id=1 UNION SELECT"},
                "use_model": True,
            },
        )
        assert second.status_code == 200
        assert second.json()["memory_insights"]
        assert second.json()["llm_assessment"]["feedback_checks"]

        recent = client.get("/api/memory/recent")
        assert recent.status_code == 200
        assert len(recent.json()["records"]) == 2


def test_negative_feedback_can_be_learned_as_a_negative_sample(mock_llm) -> None:
    with TestClient(app) as client:
        analysis = client.post(
            "/api/analyze",
            json={
                "alert": {"name": "命令注入", "url": "/run?cmd=id"},
                "use_model": True,
            },
        )
        assert analysis.status_code == 200
        memory_id = analysis.json()["memory_id"]

        feedback = client.post(
            "/api/memory/feedback",
            json={
                "memory_id": memory_id,
                "liked": False,
                "comment": "风险等级偏高，缺少可验证的执行证据",
                "learn": True,
            },
        )
        assert feedback.status_code == 200
        payload = feedback.json()
        assert payload["liked"] is False
        assert payload["learning"]["created"] is True
        assert "反面可学习样例" in payload["message"]

        status = client.get("/api/memory/status")
        assert status.json()["feedback_count"] == 1
        assert status.json()["liked_count"] == 0
        assert status.json()["learned_count"] == 1

        second = client.post(
            "/api/analyze",
            json={
                "alert": {"name": "命令注入", "url": "/run?cmd=id"},
                "use_model": True,
            },
        )
        assert second.status_code == 200
        insight = second.json()["memory_insights"][0]
        assert insight["feedback_type"] == "negative"
        assert "反面经验提示" in insight["lesson"]
        assert "风险等级偏高" in insight["learning_directive"]


def test_tool_catalog_and_react_workbench_endpoint() -> None:
    with TestClient(app) as client:
        chain = client.get("/api/agent/chain")
        assert chain.status_code == 200
        assert [node["id"] for node in chain.json()["nodes"]] == [
            "planner",
            "evidence",
            "memory",
            "risk",
            "report",
            "review",
        ]

        catalog = client.get("/api/tools")
        assert catalog.status_code == 200
        assert catalog.json()["total"] >= 10
        names = {item["name"] for item in catalog.json()["tools"]}
        assert {
            "extract_iocs",
            "extract_security_entities",
            "assess_event_layers",
            "detect_contradictions",
            "calculate_risk",
            "search_knowledge",
            "build_improvement_plan",
        } <= names

        execution = client.post(
            "/api/tools/execute",
            json={
                "tool": "extract_iocs",
                "arguments": {
                    "alert": {
                        "srcIp": "198.51.100.10",
                        "hash": "a" * 64,
                    }
                },
            },
        )
        assert execution.status_code == 200
        assert execution.json()["status"] == "success"
        assert execution.json()["output"]["total"] == 2


def test_semantic_time_ioc_event_layers_and_risk_are_auditable() -> None:
    alert = {
        "url": "/api/users/1",
        "requestHead": {"Cookie": "session-redacted"},
        "responseHead": {"status": 200},
        "responseBody": '{"email":"user@example.com","passwordHash":"redacted"}',
        "srcIp": "198.51.100.8",
        "dstIp": "10.0.0.8",
        "eventTime": 0,
        "timeRegion": 12,
        "apiId": "a" * 64,
        "server": "Microsoft-IIS ASP.NET",
        "fileSha256": "b" * 64,
    }
    timeline = build_timeline({"alert": alert})
    assert timeline["total"] == 0
    assert timeline["unrecorded"] == [
        {"source": "alert.eventTime", "value": "0", "reason": "未记录"}
    ]
    assert timeline["ignored_fields"] == [
        {"source": "alert.timeRegion", "reason": "字段名不表示事件发生时间"}
    ]

    iocs = extract_iocs({"alert": alert})
    indicator_values = {item["value"] for item in iocs["indicators"]}
    assert "b" * 64 in indicator_values
    assert "a" * 64 not in indicator_values
    assert not any(
        item["type"] == "domain" and item["value"] == "asp.net"
        for item in iocs["indicators"]
    )
    assert any(item["value"] == "a" * 64 for item in iocs["excluded"])

    entities = extract_security_entities({"alert": alert})
    categories = {item["category"] for item in entities["entities"]}
    assert {"应用/系统标识符", "文件/样本", "技术栈", "敏感数据", "资产"} <= categories

    assessment = assess_event_layers({"alert": alert})
    layers = {item["id"]: item for item in assessment["layers"]}
    assert layers["server_processed"]["status"] == "✅ 已覆盖"
    assert layers["valid_business_response"]["status"] == "✅ 已覆盖"
    assert layers["sensitive_exposure"]["status"] == "✅ 已覆盖"
    assert layers["authorization"]["status"] != "✅ 已覆盖"
    assert "不能据此确认" in layers["authorization"]["conclusion"]

    matrix = evidence_matrix(
        {"alert": alert, "event_assessment": assessment, "timeline": timeline}
    )
    risk = calculate_risk(
        {"alert": alert, "event_assessment": assessment, "evidence": matrix}
    )
    assert sum(item["weight"] for item in risk["dimensions"]) == 1
    assert {item["value"] for item in risk["dimensions"]} <= {0, 25, 50, 75, 100}
    assert risk["score"] in {0, 25, 50, 75, 100}
    assert risk["confidence_level"] in {"低", "中", "高"}
    assert "Risk = 0.30" in risk["formula"]
    assert (
        next(row for row in matrix["rows"] if row["label"] == "认证与授权")["status"]
        != "✅ 已覆盖"
    )

    no_auth = assess_event_layers(
        {"alert": {"url": "/api/users/1", "responseHead": {"status": 200}}}
    )
    no_auth_layer = {item["id"]: item for item in no_auth["layers"]}["authorization"]
    assert no_auth_layer["status"] == "❌ 缺失"
    assert "缺失 Authorization 不能证明未认证" in no_auth_layer["conclusion"]

    error_response = assess_event_layers(
        {
            "alert": {
                "responseHead": {"status": 200},
                "responseBody": {"error": "permission denied"},
            }
        }
    )
    error_business_layer = {item["id"]: item for item in error_response["layers"]}[
        "valid_business_response"
    ]
    assert error_business_layer["status"] == "⚠️ 部分覆盖"
    assert "不能据此确认有效业务处理" in error_business_layer["conclusion"]

    protocol_business = assess_event_layers(
        {
            "responseHead": {"status": 200},
            "responseBody": {"success": False, "error": "invalid password"},
        }
    )
    assert any(
        item["area"] == "HTTP 状态与业务状态"
        for item in protocol_business["semantic_conflicts"]
    )


def test_semantic_conflicts_and_timestamp_deduplication_are_visible(mock_llm) -> None:
    alert = {
        "name": "非敏感内容访问规则",
        "dstIp": "10.0.0.8",
        "requestHead": {"Host": "10.0.0.9:8080"},
        "responseHead": {
            "status": 200,
            "Date": "Sat, 30 Aug 2026 00:00:00 GMT",
        },
        "responseBody": {"sysPassword": "redacted"},
        "eventTime": "2026-08-30T12:00:00+00:00",
        "occurTimestamp": "2026-08-30T12:00:00+00:00",
        "tcpElapsedTime": 20,
    }
    assessment = assess_event_layers({"alert": alert})
    assert {item["area"] for item in assessment["semantic_conflicts"]} == {
        "目标地址与 HTTP Host",
        "告警规则语义与响应内容",
        "告警时间与 HTTP Date",
    }
    timeline = build_timeline({"alert": alert})
    assert timeline["total"] == 2
    assert timeline["raw_total"] == 3
    assert any(
        item["source"] == "alert.tcpElapsedTime" for item in timeline["ignored_fields"]
    )
    matrix = evidence_matrix(
        {"alert": alert, "event_assessment": assessment, "timeline": timeline}
    )
    assert matrix["conflicts"] == 3
    assert any(row["status"] == "⚡ 存在冲突" for row in matrix["rows"])
    consistency = detect_contradictions(
        {
            "alert": alert,
            "event_assessment": assessment,
            "timeline": timeline,
            "evidence": matrix,
        }
    )
    assert consistency["consistent"] is False

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze", json={"alert": alert, "use_deepseek": True}
        )
        assert response.status_code == 200
        assert response.json()["run_status"] == "completed"
        assert response.json()["review_status"] == "failed"
        assert response.json()["report_available"] is False
        assert response.json()["review"]["error_scope"] == "analysis"


def test_contradiction_detector_rejects_inconsistent_agent_outputs() -> None:
    assessment = {
        "layers": [
            {
                "id": "server_processed",
                "status": "✅ 已覆盖",
                "evidence": ["alert.responseHead.status"],
                "conclusion": "服务器返回 2xx。",
            }
        ]
    }
    result = detect_contradictions(
        {
            "event_assessment": assessment,
            "timeline": {"total": 1, "events": [{"source": "alert.eventTime"}]},
            "evidence": {
                "coverage": 40,
                "rows": [
                    {"label": "服务器处理", "status": "❌ 缺失"},
                    {"label": "时间与关联", "status": "❌ 缺失"},
                ],
            },
            "risk": {"confidence_level": "高"},
        }
    )
    assert result["consistent"] is False
    assert {item["area"] for item in result["conflicts"]} == {
        "时间线",
        "服务器处理",
        "研判置信度",
    }


def test_candidate_scenarios_ignore_rule_name_and_risk_is_scenario_specific() -> None:
    rule_only = assess_event_layers(
        {"alert": {"name": "SQL 注入告警", "riskLevel": 5, "url": "/health"}}
    )
    assert rule_only["classification"] == "主要场景待确认"
    assert rule_only["candidate_scenarios"][0]["confidence"] == "低"
    assert not any("SQL" in item["name"] for item in rule_only["candidate_scenarios"])

    auth = assess_event_layers(
        {
            "alert": {
                "url": "/login",
                "requestHead": {"Authorization": "Bearer null"},
                "responseHead": {"status": 200},
                "responseBody": {"success": False, "error": "invalid password"},
            }
        }
    )
    auth_risk = calculate_risk({"alert": {}, "event_assessment": auth})
    assert "凭据敏感性" in auth_risk["formula"]
    assert {item["value"] for item in auth_risk["dimensions"]} <= {0, 25, 50, 75, 100}

    data = assess_event_layers(
        {
            "alert": {
                "url": "/api/profile",
                "responseHead": {"status": 200},
                "responseBody": {"password": "redacted"},
            }
        }
    )
    data_risk = calculate_risk({"alert": {}, "event_assessment": data})
    assert "数据敏感性" in data_risk["formula"]


def test_model_key_is_never_returned_to_browser() -> None:
    with TestClient(app) as client:
        response = client.put(
            "/api/config/model",
            json={
                "api_key": "sk-test-only-1234567890",
                "provider": "custom",
                "model": "security-model",
                "base_url": "http://127.0.0.1:11434/v1",
                "persist": False,
            },
        )
        assert response.status_code == 200
        assert response.json()["configured"] is True
        assert response.json()["provider"] == "custom"
        assert "sk-test-only-1234567890" not in response.text
        client.delete("/api/config/model")


def test_provider_neutral_openai_compatible_request_contract() -> None:
    config_store.configure("sk-contract-test-123456", "security-model", persist=False)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/chat/completions"
        assert request.headers["Authorization"] == "Bearer sk-contract-test-123456"
        payload = __import__("json").loads(request.content)
        assert payload["model"] == "security-model"
        assert "thinking" not in payload
        return httpx.Response(
            200,
            json={
                "model": "security-model",
                "choices": [{"message": {"content": "连接成功"}}],
                "usage": {"total_tokens": 3},
            },
        )

    result = asyncio.run(chat("system", "user", transport=httpx.MockTransport(handler)))
    assert result["content"] == "连接成功"
    assert result["provider"] == "deepseek"
    config_store.clear()


def test_normalization_parses_http_business_result_auth_and_applicability() -> None:
    raw = {
        "requestHead": (
            "POST /api/orders HTTP/1.1\r\n"
            "Host: shop.internal\r\n"
            "Authorization: Bearer secret-token\r\n"
            "Content-Type: application/json\r\n"
        ),
        "requestBody": '{"orderId":"O-100"}',
        "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n",
        "responseBody": '{"meta":{"status_code":200},"success":true,"message":"ok"}',
        "mysqlSuccess": 0,
    }
    event = normalize_alert(raw)
    assert event["http"]["method"] == "POST"
    assert event["http"]["path"] == "/api/orders"
    assert event["http"]["status_code"] == 200
    assert event["business_result"]["success"] is True
    assert event["business_result"]["code"] == 200
    assert event["authorization"] == {
        "present": True,
        "scheme": "Bearer",
        "value_state": "token_or_credential",
        "authentication_validity": "not_confirmed",
        "source": "request.headers.Authorization",
        "cookie_present": False,
        "cookie_source": None,
    }
    assert "secret-token" not in json.dumps(event, ensure_ascii=False)
    assert "_alert_for_applicability" not in event
    assert any(
        item["field"] == "alert.mysqlSuccess"
        for item in event["field_applicability"]["not_applicable"]
    )
    assert parse_http_request(raw)["headers"]["Authorization"] == "[敏感头已隐藏]"
    assert parse_http_response(raw)["status_code"] == 200


@pytest.mark.parametrize(
    ("label", "alert", "expected_scene"),
    [
        ("login_success", {"url": "/login", "responseBody": {"success": True, "token": "x"}}, "credential_authentication"),
        ("login_failure", {"url": "/login", "responseBody": {"success": False, "error": "invalid password"}}, "credential_authentication"),
        ("invalid_auth_header", {"url": "/login", "requestHead": {"Authorization": "Bearer null"}}, "credential_authentication"),
        ("profile_secret", {"url": "/api/profile", "responseBody": {"password": "redacted"}}, "data_exposure"),
        ("config_secret", {"url": "/api/config", "responseBody": {"apiKey": "redacted"}}, "data_exposure"),
        ("sql_union", {"url": "/api/search?id=1 UNION SELECT password FROM users"}, "injection"),
        ("path_traversal", {"url": "/download?path=../etc/passwd"}, "injection"),
        ("powershell", {"url": "/admin/exec", "requestBody": "powershell -enc payload"}, "command_execution"),
        ("whoami", {"url": "/admin/exec", "requestBody": "whoami"}, "command_execution"),
        ("xss", {"url": "/search?q=<script>alert(1)</script>"}, "xss"),
        ("upload", {"url": "/upload", "requestBody": {"filename": "sample.exe"}}, "malware_file"),
        ("scan", {"description": "scanner probing ports", "url": "/admin"}, "scanning"),
        ("generic", {"url": "/health", "responseHead": {"status": 200}}, "generic"),
    ],
)
def test_business_scene_candidates_cover_cross_scenario_inputs(
    label: str, alert: dict[str, object], expected_scene: str
) -> None:
    del label
    normalized = normalize_alert(alert)
    context = infer_business_context(normalized, alert)
    result = generate_scene_candidates(
        normalized,
        context,
        context["direct_evidence"],
        context["negative_evidence"],
        alert,
    )
    selected = select_primary_scene(result)
    assert selected["scene_id"] == expected_scene
    assert selected["evidence_template"]
    assert result["inputs"]["alert_metadata_used_as_fact"] is False


def test_analysis_debug_trace_exposes_real_chain_without_secrets(monkeypatch: pytest.MonkeyPatch, mock_llm) -> None:
    monkeypatch.setenv("ANALYSIS_DEBUG", "true")
    alert = {
        "name": "SQL Injection rule label",
        "requestHead": "GET /api/search?id=1 UNION SELECT HTTP/1.1\r\nAuthorization: Bearer secret-token\r\n",
        "responseHead": "HTTP/1.1 200 OK\r\n",
        "responseBody": {"success": True, "code": 200, "message": "ok"},
        "riskLevel": "critical",
    }
    result = asyncio.run(analyze(alert, "基于事实完成研判", True))
    trace = result["debug_trace"]
    assert trace["schema_version"] == "analysis-trace-v1"
    assert trace["selected_scene"]["scene_id"] == "injection"
    assert trace["risk"]["scene_id"] == "injection"
    assert "业务动作" in trace["knowledge"]["query"] or "database_query" in trace["knowledge"]["query"]
    stages = {item["stage"] for item in trace["execution_events"]}
    assert {"normalization", "business_context", "scene_classification", "risk", "report", "semantic_review"} <= stages
    assert "secret-token" not in json.dumps(trace, ensure_ascii=False)
    assert result["review"]["approved"] is True


def test_semantic_review_fails_on_final_markdown_state_mismatch() -> None:
    alert = {
        "url": "/api/profile",
        "requestHead": {"Authorization": "Bearer verified-later"},
        "responseHead": {"status": 200},
        "responseBody": {"success": True, "password": "redacted"},
        "mysqlSuccess": 0,
    }
    normalized = normalize_alert(alert)
    context = infer_business_context(normalized, alert)
    candidates = generate_scene_candidates(normalized, context, context["direct_evidence"], context["negative_evidence"], alert)
    assessment = assess_event_layers(
        {"alert": alert, "normalized_event": normalized, "business_context": context, "scene_result": candidates}
    )
    evidence = evidence_matrix({"alert": alert, "event_assessment": assessment})
    risk = calculate_risk({"alert": alert, "event_assessment": assessment, "evidence": evidence})

    mismatch = semantic_review(
        alert, normalized, context, assessment, evidence, risk,
        "HTTP 200，但没有 2xx；业务结果未知；未观察到 Authorization；mysqlSuccess=0，攻击已经发生。",
    )
    failed_checks = {item["check"] for item in mismatch["failures"]}
    assert mismatch["status"] == "FAIL"
    assert {"http_status_matches_report", "business_result_matches_report", "authorization_matches_report", "field_applicability_is_respected"} <= failed_checks

    wrong_scene_risk = dict(risk)
    wrong_scene_risk["scene_id"] = "injection"
    wrong_scene_risk["risk_profile"] = {**risk["risk_profile"], "scene_id": "injection"}
    scene_failure = semantic_review(alert, normalized, context, assessment, evidence, wrong_scene_risk, "事实范围与处置建议待核验。")
    assert any(item["check"] == "risk_profile_matches_scene" for item in scene_failure["failures"])


def test_model_failure_fails_closed(mock_llm) -> None:
    from app.memory import memory_store
    from app.model_client import ModelExecutionError

    mock_llm["overrides"]["evidence_reasoning"] = httpx.ReadTimeout("upstream unavailable")
    with pytest.raises(ModelExecutionError, match="evidence_reasoning"):
        asyncio.run(analyze({"url": "/api/search?id=1 UNION SELECT"}, "基于证据输出报告", True))
    assert memory_store.recent()[0]["status"] == "failed"
    assert [item["stage"] for item in mock_llm["requests"]] == ["evidence_reasoning"]


def test_tool_failure_keeps_tool_and_original_error_type(monkeypatch: pytest.MonkeyPatch) -> None:
    definition = tool_registry._tools["normalize_alert"]

    def fail_tool(arguments: dict[str, object]) -> dict[str, object]:
        del arguments
        raise LookupError("fixture failure")

    monkeypatch.setitem(
        tool_registry._tools,
        "normalize_alert",
        replace(definition, handler=fail_tool),
    )
    with pytest.raises(ToolExecutionError) as caught:
        tool_registry.execute("normalize_alert", {"alert": {}})
    assert caught.value.tool == "normalize_alert"
    assert caught.value.error_type == "LookupError"
    assert "fixture failure" in caught.value.message
