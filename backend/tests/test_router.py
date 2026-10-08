from __future__ import annotations

import asyncio
import json

import pytest
from app.analysis import analyze
from app.business_context import infer_business_context
from app.evidence_store import build_evidence_store
from app.normalization import normalize_alert
from app.review import semantic_review
from app.security_classifier import classify_security_problems
from app.workflows import route_workflow


def _route(alert: dict[str, object]) -> tuple[dict, dict, dict, dict, dict]:
    normalized = normalize_alert(alert)
    context = infer_business_context(normalized, alert)
    evidence_store = build_evidence_store(normalized, alert, context)
    security = classify_security_problems(normalized, context, evidence_store, alert)
    router = route_workflow(context, security, evidence_store)
    return normalized, context, evidence_store, security, router


@pytest.mark.parametrize(
    ("label", "alert", "context_id", "workflow_id"),
    [
        ("login", {"url": "/login", "responseBody": {"success": True, "token": "redacted"}}, "authentication", "auth_workflow"),
        ("logout", {"url": "/logout", "requestHead": {"Authorization": "Bearer redacted"}}, "logout", "auth_workflow"),
        ("password_change", {"url": "/account/password/change", "requestBody": {"oldPassword": "x"}}, "password_change", "auth_workflow"),
        ("profile_secret", {"url": "/api/profile", "responseBody": {"password": "redacted"}}, "resource_read", "data_exposure_workflow"),
        ("sql", {"url": "/api/search?id=1 UNION SELECT password FROM users"}, "database_query", "database_workflow"),
        ("command", {"url": "/admin/exec", "requestBody": "powershell -enc payload"}, "process_execution", "host_workflow"),
        ("upload", {"url": "/upload", "requestBody": {"filename": "sample.exe"}}, "file_upload", "file_workflow"),
        ("scan", {"description": "scanner probing ports", "url": "/admin"}, "network_connection", "network_workflow"),
        ("generic", {"url": "/health", "responseHead": {"status": 200}}, "resource_read", "generic_workflow"),
    ],
)
def test_context_and_router_are_separate_and_deterministic(
    label: str, alert: dict[str, object], context_id: str, workflow_id: str
) -> None:
    del label
    _, context, evidence_store, security, router = _route(alert)
    assert context["context_id"] == context_id
    assert isinstance(context["confidence_score"], float)
    assert router["primary_workflow"] == workflow_id
    assert router["risk_profile_id"]
    for candidate in security["candidates"]:
        for support in candidate["support"]:
            assert support["evidence_id"] in evidence_store["by_id"]


def test_embedded_log_is_layer_one_and_cannot_support_current_command() -> None:
    _, context, evidence_store, security, router = _route(
        {"url": "/access.log", "responseBody": {"log": "powershell whoami"}}
    )
    assert context["context_id"] == "log_access"
    embedded = [item for item in evidence_store["items"] if item["provenance"]["event_layer"] == 1]
    assert embedded
    assert all(item["provenance"]["describes_current_event"] is False for item in embedded)
    assert not any(item["scene_id"] in {"command_injection", "rce"} for item in security["candidates"])
    assert router["primary_workflow"] == "generic_workflow"


def test_normal_login_token_is_not_data_exposure() -> None:
    _, context, _, security, router = _route(
        {"url": "/login", "responseBody": {"success": True, "token": "redacted"}}
    )
    assert context["context_id"] == "authentication"
    assert security["candidates"][0]["scene_id"] == "normal_behavior"
    assert router["primary_workflow"] == "auth_workflow"
    assert "data_exposure_workflow" not in router["secondary_workflows"]


def test_http_200_is_not_process_execution() -> None:
    _, _, _, security, router = _route(
        {"url": "/health", "responseHead": "HTTP/1.1 200 OK"}
    )
    assert not any(item["scene_id"] in {"rce", "command_injection", "persistence"} for item in security["candidates"])
    assert router["primary_workflow"] == "generic_workflow"


def test_review_rejects_embedded_evidence_as_main_support() -> None:
    alert = {"url": "/access.log", "responseBody": {"log": "powershell whoami"}}
    normalized, context, evidence_store, security, router = _route(alert)
    embedded_id = next(
        item["evidence_id"]
        for item in evidence_store["items"]
        if item["provenance"]["event_layer"] == 1
    )
    tampered_security = json.loads(json.dumps(security, ensure_ascii=False))
    tampered_security["candidates"][0]["support"] = [{"evidence_id": embedded_id, "reason": "tampered"}]
    assessment = {
        "selected_scene": {"scene_id": "generic", "security_problem_id": "unknown"},
        "scene_id": "generic",
        "event_assessment": {"layers": []},
    }
    evidence = {"coverage": 0, "conflicts": 0}
    risk = {"scene_id": "generic", "risk_profile_id": router["risk_profile_id"], "risk_profile": {"scene_id": "generic"}}
    result = semantic_review(
        alert,
        normalized,
        context,
        assessment,
        evidence,
        risk,
        "事实范围与待核验项。",
        router=router,
        evidence_store=evidence_store,
        security_result=tampered_security,
        workflow_result={"workflow_id": router["workflow_id"], "evidence_schema": ["request"]},
    )
    assert result["status"] == "FAIL"
    assert any(item["check"] == "main_scene_uses_current_evidence" for item in result["failures"])


def test_real_router_trace_is_returned_without_secret(monkeypatch: pytest.MonkeyPatch, mock_llm) -> None:
    monkeypatch.setenv("ANALYSIS_DEBUG", "true")
    secret = "super-secret-token"
    result = asyncio.run(
        analyze(
            {
                "requestHead": f"GET /login HTTP/1.1\r\nAuthorization: Bearer {secret}\r\n",
                "responseBody": {"success": True, "token": secret},
            },
            "按当前证据研判",
            True,
        )
    )
    trace = result["debug_trace"]
    assert trace["router"]["primary_workflow"] == "auth_workflow"
    assert trace["workflow"]["workflow_id"] == "auth_workflow"
    assert trace["evidence_store"]["schema_version"] == "unified-evidence-store-v1"
    assert secret not in json.dumps(trace, ensure_ascii=False)
    assert result["summary"]["context_id"] == "authentication"
