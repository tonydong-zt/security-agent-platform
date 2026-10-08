from __future__ import annotations

from app.llm_reasoning import _structured_json
from app.review import (
    report_policy_check,
    review_rule_registry,
    semantic_review,
    structured_state_review,
)


def _state_parts() -> tuple[dict, dict, dict, dict, dict, dict, dict, dict, dict]:
    normalized = {
        "http": {"method": "GET", "path": "/api/resource", "status_code": 200},
        "business_result": {"success": True, "code": "SUCCESS"},
        "authorization": {"present": True, "state": "session_present_unvalidated"},
        "field_applicability": {"not_applicable_fields": []},
    }
    business = {
        "action": "resource_access",
        "context_id": "resource_read",
        "confidence_score": 0.9,
    }
    scene = {
        "selected_scene": {"scene_id": "data_exposure"},
        "event_assessment": {"layers": []},
    }
    evidence_store = {
        "items": [
            {
                "evidence_id": "E001",
                "applicable": True,
                "provenance": {
                    "event_layer": 0,
                    "describes_current_event": True,
                },
            }
        ]
    }
    security = {
        "candidates": [
            {"scene_id": "data_exposure", "support": [{"evidence_id": "E001"}]}
        ]
    }
    router = {
        "selected_scene_id": "data_exposure",
        "workflow_id": "data_exposure_workflow",
        "risk_profile_id": "DATA_EXPOSURE_RISK",
        "workflow": {"label": "data exposure"},
        "eligibility": {"eligible": True},
    }
    workflow = {
        "workflow_id": "data_exposure_workflow",
        "evidence_schema": ["response", "authorization"],
        "eligibility": {"eligible": True},
    }
    evidence = {"coverage": 30, "conflicts": 0}
    risk = {
        "scene_id": "data_exposure",
        "risk_profile_id": "DATA_EXPOSURE_RISK",
        "risk_profile": {"scene_id": "data_exposure"},
    }
    return normalized, business, scene, evidence, risk, router, evidence_store, security, workflow


def test_structured_state_review_routes_business_context_failure_upstream() -> None:
    normalized, business, scene, evidence, risk, router, store, security, workflow = _state_parts()
    business.pop("confidence_score")
    result = structured_state_review(
        {}, normalized, business, scene, evidence, risk,
        router=router, evidence_store=store, security_result=security, workflow_result=workflow,
    )
    assert result["approved"] is False
    assert result["error_category"] == "BUSINESS_CONTEXT_ERROR"
    assert result["error_scope"] == "analysis"
    assert result["rollback_target"] == "business_context"
    assert "RULE_BUSINESS_CONTEXT_SCHEMA" in result["failure_rules"]


def test_structured_state_review_rejects_ineligible_workflow() -> None:
    normalized, business, scene, evidence, risk, router, store, security, workflow = _state_parts()
    router["eligibility"] = {"eligible": False, "reason": "缺少文件证据"}
    workflow["eligibility"] = router["eligibility"]
    result = structured_state_review(
        {}, normalized, business, scene, evidence, risk,
        router=router, evidence_store=store, security_result=security, workflow_result=workflow,
    )
    assert result["approved"] is False
    assert result["error_category"] == "WORKFLOW_ELIGIBILITY_ERROR"
    assert result["rollback_target"] == "workflow_router"


def test_final_report_semantic_review_does_not_hide_http_200_fact() -> None:
    normalized, business, scene, evidence, risk, router, store, security, workflow = _state_parts()
    result = semantic_review(
        {}, normalized, business, scene, evidence, risk,
        "没有 2xx；业务结果未知。",
        router=router, evidence_store=store, security_result=security, workflow_result=workflow,
    )
    assert result["approved"] is False
    assert "RULE_HTTP_200_NOT_EXECUTION" in result["failure_rules"]
    assert result["error_category"] == "REPORT_FACT_ERROR"
    assert result["error_scope"] == "report"
    assert result["rollback_target"] == "report"


def test_security_claim_rule_ignores_boundary_and_hypothesis_wording() -> None:
    normalized, business, scene, evidence, risk, router, store, security, workflow = _state_parts()
    result = semantic_review(
        {}, normalized, business, scene, evidence, risk,
        "不得把攻击成功、数据已外泄或未授权访问成功写成已确认；必须有直接证据。",
        router=router, evidence_store=store, security_result=security, workflow_result=workflow,
    )
    assert "security_claims_have_evidence" not in {item["check"] for item in result["failures"]}


def test_security_claim_rule_ignores_quoted_knowledge_criteria() -> None:
    normalized, business, scene, evidence, risk, router, store, security, workflow = _state_parts()
    result = semantic_review(
        {}, normalized, business, scene, evidence, risk,
        "## 知识库依据\n[K-01] 中的判定条件包括“攻击已经成功”与“成功利用”，但当前事件不满足直接证据要求。",
        router=router, evidence_store=store, security_result=security, workflow_result=workflow,
    )
    assert "security_claims_have_evidence" not in {item["check"] for item in result["failures"]}


def test_security_claim_rule_still_blocks_explicit_success_claim() -> None:
    normalized, business, scene, evidence, risk, router, store, security, workflow = _state_parts()
    result = semantic_review(
        {}, normalized, business, scene, evidence, risk,
        "## 研判结论\n攻击已经成功利用该漏洞并读取数据。",
        router=router, evidence_store=store, security_result=security, workflow_result=workflow,
    )
    assert "security_claims_have_evidence" in {item["check"] for item in result["failures"]}


def test_security_claim_rule_ignores_uncertainty_terms() -> None:
    normalized, business, scene, evidence, risk, router, store, security, workflow = _state_parts()
    result = semantic_review(
        {}, normalized, business, scene, evidence, risk,
        "## 研判结论\n当前无法确认攻击成功与否，攻击成功性和成功利用条件均待核验。",
        router=router, evidence_store=store, security_result=security, workflow_result=workflow,
    )
    assert "security_claims_have_evidence" not in {item["check"] for item in result["failures"]}


def test_report_policy_requires_real_headings_and_current_references() -> None:
    result = report_policy_check(
        "## 执行摘要\n当前证据不足。",
        required_sections=("执行摘要", "证据范围"),
        known_knowledge_ids={"K-01"},
        known_evidence_ids={"E001"},
        chart_ids=["risk"],
        minimum_characters=10,
        state_version=2,
        generated_from_state_version=1,
    )
    assert result["approved"] is False
    assert "证据范围" in result["missing_sections"]
    assert "RULE_REPORT_STRUCTURE" in result["failure_rules"]
    assert "RULE_REPORT_STATE_VERSION" in result["failure_rules"]
    assert result["rollback_target"] == "report"


def test_report_policy_length_message_matches_pass_status() -> None:
    result = report_policy_check("x" * 10, minimum_characters=10)
    check = next(item for item in result["checks"] if item["id"] == "report_minimum_structure")
    assert check["status"] == "PASS"
    assert "达到最小要求" in check["message"]


def test_report_policy_accepts_heading_aliases() -> None:
    result = report_policy_check(
        "## 事件摘要\n当前事件仍待核验。",
        required_sections=("执行摘要",),
        minimum_characters=1,
    )
    assert result["approved"] is True


def test_review_rule_registry_exposes_categories_and_rollback_targets() -> None:
    rules = review_rule_registry()
    by_id = {item["rule_id"]: item for item in rules}
    assert by_id["RULE_BUSINESS_CONTEXT_SCHEMA"]["category"] == "BUSINESS_CONTEXT_ERROR"
    assert by_id["RULE_REVIEW_REPAIR_LOOP"]["rollback_target"] == "report"


def test_structured_json_accepts_truncated_markdown_fence_but_still_returns_one_object() -> None:
    assert _structured_json('```json\n{"approved": true}') == '{"approved": true}'


def test_structured_json_normalizes_safe_provider_dict_variants() -> None:
    assert '"approved": false' in _structured_json("{'approved': False, 'issues': [],}")


def test_structured_json_repairs_only_unescaped_quotes_inside_feedback_strings() -> None:
    content = '{"approved": false, "issues": ["报告中出现 "SQL syntax error" 的表述"], "correction_instructions": []}'
    parsed = _structured_json(content)
    assert 'SQL syntax error' in parsed
