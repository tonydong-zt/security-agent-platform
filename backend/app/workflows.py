"""Registry and deterministic router for scene-specific SOC workflows."""

from __future__ import annotations

from typing import Any

from .evidence_store import evidence_ids_for


WORKFLOW_REGISTRY: dict[str, dict[str, Any]] = {
    "auth_workflow": {
        "label": "认证与凭据 Workflow",
        "context_ids": ["authentication", "logout", "password_change"],
        "security_scenes": ["normal_behavior", "weak_credential", "brute_force", "credential_stuffing", "suspicious_behavior"],
        "required_tools": ["assess_event_layers", "build_timeline", "extract_security_entities"],
        "optional_tools": ["extract_iocs"],
        "evidence_schema": ["credential", "auth_result", "session", "account_sequence", "mfa", "post_auth_behavior"],
        "risk_profile_id": "AUTH_RISK",
        "knowledge_strategy": "authentication_outcome_and_account_correlation",
        "remediation_profile": "identity_session_and_mfa",
        "validation_profile": "normal_failure_success_and_session_lifecycle",
    },
    "authorization_workflow": {
        "label": "授权与权限 Workflow",
        "context_ids": ["resource_read", "resource_write", "configuration_access", "log_access", "admin_operation"],
        "security_scenes": ["unauthorized_access", "privilege_escalation"],
        "required_tools": ["assess_event_layers", "build_timeline", "extract_security_entities"],
        "optional_tools": ["extract_iocs"],
        "evidence_schema": ["subject", "resource", "ownership", "policy_decision", "role_change", "audit_result"],
        "risk_profile_id": "AUTHZ_RISK",
        "knowledge_strategy": "subject_resource_policy_decision",
        "remediation_profile": "object_authorization_and_least_privilege",
        "validation_profile": "authorized_unauthorized_and_cross_tenant_replay",
    },
    "web_attack_workflow": {
        "label": "Web 攻击 Workflow",
        "context_ids": ["resource_read", "resource_write", "content_rendering", "api_call", "process_execution"],
        "security_scenes": ["sql_injection", "command_injection", "rce", "xss", "ssrf", "path_traversal", "arbitrary_file_read", "injection"],
        "required_tools": ["assess_event_layers", "extract_iocs", "extract_security_entities", "build_timeline"],
        "optional_tools": [],
        "evidence_schema": ["payload", "sink", "server_processing", "execution_result", "response", "controlled_reproduction"],
        "risk_profile_id": "WEB_ATTACK_RISK",
        "knowledge_strategy": "payload_sink_processing_and_reproduction",
        "remediation_profile": "input_validation_parameterization_and_safe_rendering",
        "validation_profile": "controlled_payload_replay_and_server_side_observation",
    },
    "file_workflow": {
        "label": "文件与样本 Workflow",
        "context_ids": ["file_upload", "file_download", "resource_read"],
        "security_scenes": ["file_upload_abuse", "malware", "webshell", "malware_file"],
        "required_tools": ["assess_event_layers", "extract_iocs", "extract_security_entities", "build_timeline"],
        "optional_tools": [],
        "evidence_schema": ["file_identity", "hash", "delivery", "storage", "execution", "edr", "propagation"],
        "risk_profile_id": "FILE_RISK",
        "knowledge_strategy": "file_identity_storage_execution_and_edr",
        "remediation_profile": "upload_isolation_execution_control_and_sample_cleanup",
        "validation_profile": "isolated_sample_and_storage_replay",
    },
    "data_exposure_workflow": {
        "label": "数据暴露 Workflow",
        "context_ids": ["resource_read", "resource_write", "configuration_access", "log_access", "database_query"],
        "security_scenes": ["sensitive_data_exposure", "plaintext_credential", "data_exfiltration", "data_exposure"],
        "required_tools": ["assess_event_layers", "extract_security_entities", "build_timeline"],
        "optional_tools": ["extract_iocs"],
        "evidence_schema": ["data_type", "subject", "resource_scope", "authorization", "response", "external_transfer", "audit"],
        "risk_profile_id": "DATA_EXPOSURE_RISK",
        "knowledge_strategy": "data_sensitivity_authorization_scope_and_audit",
        "remediation_profile": "authorization_response_minimization_and_data_audit",
        "validation_profile": "subject_resource_scope_and_exfiltration_review",
    },
    "host_workflow": {
        "label": "主机与执行 Workflow",
        "context_ids": ["process_execution", "admin_operation", "container_operation"],
        "security_scenes": ["rce", "command_injection", "privilege_escalation", "persistence", "malware", "suspicious_behavior"],
        "required_tools": ["assess_event_layers", "extract_iocs", "extract_security_entities", "build_timeline"],
        "optional_tools": [],
        "evidence_schema": ["process", "parent_child", "command", "execution_result", "persistence", "edr", "host_impact"],
        "risk_profile_id": "HOST_RISK",
        "knowledge_strategy": "process_tree_execution_and_host_impact",
        "remediation_profile": "process_isolation_least_privilege_and_persistence_cleanup",
        "validation_profile": "process_tree_and_host_integrity_validation",
    },
    "network_workflow": {
        "label": "网络与横向 Workflow",
        "context_ids": ["network_connection", "cloud_operation"],
        "security_scenes": ["scan", "lateral_movement", "data_exfiltration", "suspicious_behavior"],
        "required_tools": ["assess_event_layers", "extract_iocs", "build_timeline"],
        "optional_tools": ["extract_security_entities"],
        "evidence_schema": ["source", "destination", "protocol", "target_scope", "rate", "authorization_window", "network_result"],
        "risk_profile_id": "NETWORK_RISK",
        "knowledge_strategy": "source_target_scope_rate_and_authorization_window",
        "remediation_profile": "rate_control_segmentation_and_exposure_governance",
        "validation_profile": "authorized_scan_and_lateral_path_validation",
    },
    "database_workflow": {
        "label": "数据库 Workflow",
        "context_ids": ["database_query", "database_write"],
        "security_scenes": ["sql_injection", "sensitive_data_exposure", "data_exfiltration", "misconfiguration"],
        "required_tools": ["assess_event_layers", "extract_security_entities", "build_timeline"],
        "optional_tools": ["extract_iocs"],
        "evidence_schema": ["query", "parameterization", "db_audit", "affected_rows", "data_scope", "privilege"],
        "risk_profile_id": "DATABASE_RISK",
        "knowledge_strategy": "query_audit_parameterization_and_database_privilege",
        "remediation_profile": "parameterized_query_least_privilege_and_audit",
        "validation_profile": "query_plan_and_database_audit_replay",
    },
    "cloud_workflow": {
        "label": "云与容器 Workflow",
        "context_ids": ["cloud_operation", "container_operation", "configuration_access"],
        "security_scenes": ["misconfiguration", "privilege_escalation", "sensitive_data_exposure", "persistence"],
        "required_tools": ["assess_event_layers", "extract_security_entities", "build_timeline"],
        "optional_tools": ["extract_iocs"],
        "evidence_schema": ["principal", "resource", "policy", "configuration", "control_plane_result", "workload"],
        "risk_profile_id": "CLOUD_RISK",
        "knowledge_strategy": "principal_resource_policy_and_control_plane_audit",
        "remediation_profile": "cloud_least_privilege_configuration_and_secret_hygiene",
        "validation_profile": "policy_simulation_and_control_plane_audit",
    },
    "generic_workflow": {
        "label": "通用安全异常 Workflow",
        "context_ids": ["unknown", "resource_read", "resource_write", "api_call", "email_operation"],
        "security_scenes": ["unknown", "OTHER", "suspicious_behavior", "normal_behavior"],
        "required_tools": ["assess_event_layers", "extract_iocs", "extract_security_entities", "build_timeline"],
        "optional_tools": [],
        "evidence_schema": ["request", "response", "identity", "authorization", "business_result", "impact"],
        "risk_profile_id": "GENERIC_RISK",
        "knowledge_strategy": "event_layer_and_evidence_gap_first",
        "remediation_profile": "evidence_preservation_and_contextual_validation",
        "validation_profile": "independent_log_correlation_and_controlled_replay",
    },
}


def workflow_for_id(workflow_id: str) -> dict[str, Any]:
    return WORKFLOW_REGISTRY.get(workflow_id, WORKFLOW_REGISTRY["generic_workflow"])


def workflow_eligibility(workflow_id: str, store: dict[str, Any]) -> dict[str, Any]:
    required_types = {
        "file_workflow": ("file_metadata", "file_upload_observation", "file_write_observation"),
        "host_workflow": ("execution_observation", "current_request_signal"),
        "data_exposure_workflow": ("current_response_field", "business_result", "current_request_signal"),
    }
    types = required_types.get(workflow_id, ())
    ids = evidence_ids_for(store, types) if types else []
    eligible = workflow_id in WORKFLOW_REGISTRY and (not types or bool(ids))
    return {"eligible": eligible, "support_evidence_ids": ids,
            "required_types": list(types), "reason": "" if eligible else "缺少与所选 Workflow 兼容的当前事件证据"}


def route_workflow(
    business_context: dict[str, Any],
    security_result: dict[str, Any],
    evidence_store: dict[str, Any],
) -> dict[str, Any]:
    """Route to the smallest relevant set of workflows, deterministically."""
    context_id = str(business_context.get("context_id") or business_context.get("action") or "unknown")
    candidates = [item for item in security_result.get("candidates", []) if isinstance(item, dict)]
    current_count = int(evidence_store.get("current_evidence_count", 0))
    route_scores: list[dict[str, Any]] = []
    for workflow_id, workflow in WORKFLOW_REGISTRY.items():
        score = 0.0
        reasons: list[str] = []
        if context_id in workflow["context_ids"]:
            score += 0.30
            reasons.append(f"context_id={context_id}")
        matching = [item for item in candidates if item.get("scene_id") in workflow["security_scenes"]]
        if matching:
            best = max(float(item.get("score", 0.0)) for item in matching)
            score += 0.55 * best
            reasons.append("security_problem=" + str(matching[0].get("scene_id")))
        if current_count:
            score += min(0.10, current_count * 0.01)
        eligibility = workflow_eligibility(workflow_id, evidence_store)
        if not eligibility["eligible"]:
            score = 0.0
            reasons.append("ineligible: " + eligibility["reason"])
        route_scores.append({"workflow_id": workflow_id, "score": round(min(1.0, score), 3), "reasons": reasons, "eligible": eligibility["eligible"]})
    route_scores.sort(key=lambda item: (-item["score"], item["workflow_id"]))
    top = route_scores[0]
    selected_candidate = candidates[0] if candidates else {"scene_id": "unknown", "score": 0.0}
    # A low-confidence/open-world result stays generic even when the business
    # context happens to resemble a specialized workflow.
    if selected_candidate.get("scene_id") in {"unknown", "OTHER"} or (
        float(selected_candidate.get("score", 0.0)) < 0.50
        and float(business_context.get("confidence_score", 0.0) or 0.0) < 0.50
    ):
        top = next(item for item in route_scores if item["workflow_id"] == "generic_workflow")
    primary = str(top["workflow_id"])
    if not top.get("eligible", True):
        primary = "generic_workflow"
    secondary: list[str] = []
    for item in route_scores:
        if item["workflow_id"] == primary or item["score"] < 0.42 or not item.get("eligible", True):
            continue
        if any(candidate.get("scene_id") in workflow_for_id(item["workflow_id"])["security_scenes"] for candidate in candidates[1:]):
            secondary.append(str(item["workflow_id"]))
        if len(secondary) >= 2:
            break
    workflow = workflow_for_id(primary)
    # Optional tools remain visible in the registry but are not automatically
    # executed.  The selected workflow may add one only when its evidence
    # needs it; this keeps routine auth/data cases from running every extractor.
    tool_plan = list(dict.fromkeys(workflow["required_tools"]))
    if selected_candidate.get("scene_id") in {"sql_injection", "path_traversal", "data_exfiltration"} and workflow["optional_tools"]:
        tool_plan.append(workflow["optional_tools"][0])
    return {
        "schema_version": "workflow-router-v1",
        "primary_workflow": primary,
        "workflow_id": primary,
        "secondary_workflows": secondary,
        "selected_scene_id": selected_candidate.get("scene_id", "unknown"),
        "risk_profile_id": workflow["risk_profile_id"],
        "confidence": round(float(top["score"]), 3),
        "reason": "；".join(top["reasons"]) or "低置信度或开放世界回退",
        "candidate_routes": route_scores,
        "tool_plan": tool_plan,
        "workflow": workflow,
        "eligibility": workflow_eligibility(primary, evidence_store),
        "routing_rule": "业务上下文与安全问题候选共同决定路由；低置信度、未知或开放世界候选回退 generic_workflow；不运行无关 Workflow。",
    }


def workflow_evidence_result(
    route: dict[str, Any], evidence_store: dict[str, Any], security_result: dict[str, Any]
) -> dict[str, Any]:
    workflow = route.get("workflow") or workflow_for_id(str(route.get("workflow_id", "generic_workflow")))
    selected = next(
        (item for item in security_result.get("candidates", []) if item.get("scene_id") == route.get("selected_scene_id")),
        {},
    )
    support_ids = [item.get("evidence_id") for item in selected.get("support", []) if item.get("evidence_id")]
    known_ids = set(evidence_ids_for(evidence_store))
    valid_support = [item for item in support_ids if item in known_ids]
    groups = {
        "request": ("request_target", "current_request_signal"),
        "response": ("current_response_field", "http_status"),
        "business_result": ("business_result",),
        "file_identity": ("file_metadata",),
        "hash": ("file_metadata",),
        "delivery": ("file_upload_observation",),
        "storage": ("file_write_observation",),
        "execution": ("execution_observation",),
        "execution_result": ("execution_observation",),
        "process": ("execution_observation",),
        "data_type": ("current_response_field",),
        "credential": ("authentication_observation",),
        "authorization": ("authorization_decision",),
        "policy_decision": ("authorization_decision",),
    }
    bindings = {group: evidence_ids_for(evidence_store, groups[group]) if group in groups else []
                for group in workflow.get("evidence_schema", [])}
    return {
        "workflow_id": route.get("workflow_id", "generic_workflow"),
        "evidence_schema": workflow.get("evidence_schema", []),
        "required_evidence_groups": workflow.get("evidence_schema", []),
        "selected_support_evidence_ids": valid_support,
        "evidence_bindings": bindings,
        "eligibility": workflow_eligibility(str(route.get("workflow_id")), evidence_store),
        "missing_evidence_groups": [group for group, ids in bindings.items() if not ids],
        "knowledge_strategy": workflow.get("knowledge_strategy"),
        "remediation_profile": workflow.get("remediation_profile"),
        "validation_profile": workflow.get("validation_profile"),
        "tools_selected": route.get("tool_plan", []),
    }
