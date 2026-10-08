from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from langchain_core.runnables import RunnableLambda

from .agent_tools import ToolExecutionError, redact, tool_registry
from .llm_reasoning import (
    REPORT_SECTIONS,
    Assessment,
    ReviewDecision,
    invoke_stage,
    validate_assessment,
)
from .memory import memory_store
from .model_client import ModelExecutionError, require_model
from .review import (
    build_review_failure,
    report_policy_check,
    select_review_failure,
    semantic_review,
    structured_state_review,
)

logger = logging.getLogger(__name__)

def _actionable_review_feedback(
    model_review: ReviewDecision,
    semantic: dict[str, Any],
    policy: dict[str, Any],
) -> tuple[list[str], list[dict[str, str]]]:
    """Keep only report-quality feedback that can change the current State.

    The independent model is a reviewer, not an owner of diagnostic metadata.
    In particular, it must not reject a report because it does not describe
    the internal model call chain, or because it disagrees with a deterministic
    check that already passed.  Such notes remain visible in the audit record.
    """
    raw_feedback = list(model_review.issues) + list(
        model_review.correction_instructions
    )
    if model_review.approved:
        return [], [
            {"feedback": str(item), "reason": "model_approved_note"}
            for item in raw_feedback
        ]

    semantic_checks = {
        str(item.get("check"))
        for item in semantic.get("failures", [])
        if isinstance(item, dict)
    }
    ignored: list[dict[str, str]] = []
    actionable: list[str] = []
    for item in raw_feedback:
        feedback = str(item).strip()
        if not feedback:
            continue
        reason = ""
        if any(
            token in feedback
            for token in (
                "外部模型链路",
                "模型调用",
                "模型链条",
                "调用验证",
                "验证说明",
                "llm_assessment 或证据中说明",
            )
        ):
            reason = "diagnostic_metadata_out_of_scope"
        elif policy.get("approved") and (
            "report_policy_check" in feedback
            or "小于最小要求" in feedback
            or "章节标题" in feedback
            or "IOC 语义" in feedback
        ):
            reason = "deterministic_policy_already_passed"
        elif (
            "security_claims_have_evidence" in feedback
            or "RULE_SECURITY_CLAIM_EVIDENCE" in feedback
        ) and "security_claims_have_evidence" not in semantic_checks:
            reason = "deterministic_security_rule_already_passed"
        if reason:
            ignored.append({"feedback": feedback, "reason": reason})
        else:
            actionable.append(feedback)
    return actionable, ignored


def _review_error_scope(
    model_review: ReviewDecision,
    feedback: list[str],
    failures: list[dict[str, Any]],
) -> str:
    """Resolve whether a failed review belongs to the State or the report.

    Deterministic failures own the routing decision.  The independent model
    may additionally mark a substantive assessment problem as analysis-level,
    but free-form wording alone cannot turn a diagnostic/meta note into a
    rollback request.
    """
    if any(
        str(item.get("rollback_target", ""))
        in {"normalization", "business_context", "security_classification", "scene_classification", "workflow_router", "workflow_evidence", "risk"}
        for item in failures
    ):
        return "analysis"
    if model_review.error_scope == "analysis" and feedback:
        return "analysis"
    return "report"


def _parse_alert(raw: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise TypeError("告警顶层必须是 JSON 对象")
    return parsed


def _query(alert: dict[str, Any]) -> str:
    fields = (
        "name",
        "description",
        "threatType",
        "protocol",
        "url",
        "requestHead",
        "requestBody",
        "responseBody",
    )
    return " ".join(str(alert.get(field, "")) for field in fields)[:4_000]


def _knowledge_query(
    alert: dict[str, Any],
    event_assessment: dict[str, Any],
    business_context: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
    requirement: str = "",
    router: dict[str, Any] | None = None,
    evidence_store: dict[str, Any] | None = None,
) -> str:
    """Build a scenario-first knowledge query without using rule metadata as fact.

    Knowledge retrieval is deliberately downstream of scenario identification.
    Only non-sensitive behavioral fields are included; credential-like values are
    represented by their field name so local retrieval cannot echo a secret.
    """
    classification = str(
        event_assessment.get("classification") or "主要场景待确认"
    ).strip()
    context = business_context or event_assessment.get("business_context") or {}
    selected = (
        event_assessment.get("selected_scene")
        or event_assessment.get("primary_scenario")
        or {}
    )
    candidates = event_assessment.get("candidate_scenarios") or []
    candidate_names = [
        str(item.get("name", ""))
        for item in candidates[:3]
        if isinstance(item, dict) and item.get("name")
    ]
    sensitive_terms = (
        "password",
        "passwd",
        "secret",
        "token",
        "cookie",
        "authorization",
        "credential",
        "密码",
        "密钥",
        "令牌",
    )
    behavior_fields = (
        "protocol",
        "method",
        "url",
        "requestHead",
        "requestBody",
        "responseHead",
        "responseBody",
        "processName",
        "commandLine",
        "fileName",
        "eventType",
    )
    behavior_terms: list[str] = []
    if evidence_store:
        # Knowledge is downstream of routing and receives a semantic, bounded
        # view of current evidence rather than the full raw alert payload.
        for item in evidence_store.get("items", [])[:16]:
            provenance = item.get("provenance", {})
            if not (
                item.get("applicable")
                and provenance.get("describes_current_event")
                and provenance.get("event_layer") == 0
            ):
                continue
            behavior_terms.append(
                f"{item.get('source_path', 'evidence')}[{item.get('semantic_type', 'fact')}]"
                f"={str(item.get('semantic_value', ''))[:120]}"
            )
    else:
        for field_name in behavior_fields:
            value = alert.get(field_name)
            if value in (None, "", [], {}, False, 0, 0.0, "0"):
                continue
            text = (
                json.dumps(value, ensure_ascii=False)
                if isinstance(value, (dict, list))
                else str(value)
            )
            if any(term in f"{field_name} {text}".lower() for term in sensitive_terms):
                behavior_terms.append(f"{field_name}(敏感字段已隐藏)")
            else:
                behavior_terms.append(f"{field_name}:{text[:160]}")
    query_parts = [
        f"业务动作：{context.get('business_action') or context.get('action') or 'unknown'}",
        f"业务对象：{context.get('business_object') or 'unknown'}",
        f"当前安全场景：{classification}",
        f"场景 ID：{selected.get('scene_id', event_assessment.get('scene_id', 'generic'))}",
    ]
    if router:
        query_parts.append(f"Workflow：{router.get('workflow_id', 'generic_workflow')}")
        query_parts.append(
            f"知识策略：{(router.get('workflow') or {}).get('knowledge_strategy', 'evidence_gap_first')}"
        )
    if context.get("expected_normal_behavior"):
        query_parts.append(
            f"正常预期：{str(context['expected_normal_behavior'])[:240]}"
        )
    if context.get("observed_behavior"):
        query_parts.append(f"观察行为：{str(context['observed_behavior'])[:240]}")
    if candidate_names:
        query_parts.append("候选场景：" + "、".join(candidate_names))
    if behavior_terms:
        query_parts.append("行为字段：" + "；".join(behavior_terms))
    confirmed = [
        str(item.get("source", ""))
        for item in event_assessment.get("facts", [])[:8]
        if isinstance(item, dict) and item.get("source")
    ]
    confirmed.extend(
        str(item.get("evidence_id") or item.get("reason") or "")
        if isinstance(item, dict)
        else str(item)
        for item in (selected.get("support") or [])[:5]
        if item
    )
    if evidence:
        confirmed.extend(
            str(row.get("label", ""))
            for row in evidence.get("rows", [])[:8]
            if row.get("status") == "✅ 已覆盖"
        )
    if confirmed:
        query_parts.append(
            "已观察/确认证据：" + "；".join(dict.fromkeys(confirmed))[:800]
        )
    query_parts.append(f"调查目标：{requirement or '核验场景成立条件与证据缺口'}")
    query_parts.append("处置与修复目标：最小化风险、补证、验证和关闭标准")
    return " ".join(query_parts)[:4_000]


def _md(value: Any, fallback: str = "未知") -> str:
    if value in (None, "", [], {}):
        return fallback
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value)
    return text.replace("|", "\\|").replace("\n", " ")[:500]


def _trace(
    traces: list[dict[str, Any]],
    call: dict[str, Any],
    stage: str,
    purpose: str,
    input_summary: str,
    output_summary: str,
    evidence: list[str],
) -> None:
    traces.append(
        {
            "step": len(traces) + 1,
            "stage": stage,
            "title": call["label"],
            "tool": call["tool"],
            "purpose": purpose,
            "input_summary": input_summary,
            "output_summary": output_summary,
            "evidence": evidence,
            "duration_ms": call["duration_ms"],
            "status": call["status"],
        }
    )


def _record_stage(
    state: AgentState,
    stage: str,
    status: str,
    output: dict[str, Any] | list[Any] | str | None = None,
    **metadata: Any,
) -> None:
    state.analysis_trace_events.append(
        {
            "stage": stage,
            "status": status,
            "output": output if output is not None else {},
            **metadata,
        }
    )


def _json_hash(value: Any) -> str:
    serialized = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _state_fingerprint(state: AgentState) -> str:
    """Hash only structured state; raw secrets and report text are excluded."""
    evidence_items = []
    for item in state.evidence_store.get("items", []):
        evidence_items.append(
            {
                "evidence_id": item.get("evidence_id"),
                "source_path": item.get("source_path"),
                "semantic_type": item.get("semantic_type"),
                "applicable": item.get("applicable"),
                "provenance": item.get("provenance", {}),
            }
        )
    payload = {
        "normalized_event": {
            key: value
            for key, value in state.normalized_event.items()
            if key not in {"behavior_text", "_alert_for_applicability"}
        },
        "business_context": state.business_context,
        "security_candidates": state.security_result.get("candidates", []),
        "router": state.router,
        "workflow": state.workflow_result,
        "selected_scene": state.event_assessment.get("selected_scene", {}),
        "evidence_items": evidence_items,
        "evidence": state.evidence,
        "risk": state.risk,
        "consistency": state.consistency,
        "citations": [item.get("id") for item in state.citations],
    }
    return _json_hash(payload)


def _report_fingerprint(report: str) -> str:
    return _json_hash({"report": str(report or "")})


def _refresh_fingerprints(state: AgentState) -> None:
    state.state_fingerprint = _state_fingerprint(state)
    state.report_fingerprint = _report_fingerprint(state.report)


def _analysis_trace(state: AgentState) -> dict[str, Any]:
    normalized = {
        key: value
        for key, value in state.normalized_event.items()
        if key not in {"behavior_text", "_alert_for_applicability"}
    }
    selected = state.event_assessment.get("selected_scene") or {}
    return {
        "schema_version": "analysis-trace-v1",
        "state_version": state.state_version,
        "state_fingerprint": state.state_fingerprint,
        "generated_from_state_version": state.generated_from_state_version,
        "report_fingerprint": state.report_fingerprint,
        "normalization": normalized,
        "business_context": state.business_context,
        "security_problem_candidates": state.security_result.get("candidates", []),
        "router": state.router,
        "workflow": state.workflow_result,
        "evidence_store": {
            key: value for key, value in state.evidence_store.items() if key != "by_id"
        },
        "current_evidence_ids": [
            item.get("evidence_id")
            for item in state.evidence_store.get("items", [])
            if item.get("applicable")
            and item.get("provenance", {}).get("event_layer") == 0
            and item.get("provenance", {}).get("describes_current_event")
        ],
        "available_knowledge_ids": [item.get("id") for item in state.citations],
        "scene_candidates": state.scene_result.get("candidates", []),
        "selected_scene": selected,
        "evidence_template": state.event_assessment.get("evidence_template", []),
        "evidence": state.evidence,
        "risk_profile": state.risk.get("risk_profile", {}),
        "risk": state.risk,
        "knowledge": {
            "query": state.knowledge_query,
            "citation_ids": [item.get("id") for item in state.citations],
            "result_count": len(state.citations),
        },
        "semantic_review": state.review,
        "structured_state_review": state.structured_review,
        "revision_feedback": state.revision_feedback,
        "review_iterations": state.review_history,
        "fallbacks": state.fallbacks,
        "model_calls": state.model_calls,
        "execution_events": state.analysis_trace_events,
    }


def _key_finding(
    alert: dict[str, Any], risk: dict[str, Any], event_assessment: dict[str, Any]
) -> str:
    name = _md(alert.get("name"), "未知安全告警")
    classification = _md(event_assessment.get("classification"), "待分类安全异常")
    layers = {item.get("id"): item for item in event_assessment.get("layers", [])}
    response = layers.get("server_processed", {})
    authorization = layers.get("authorization", {})
    exposure = layers.get("sensitive_exposure", {})
    conclusion = (
        "当前告警存在服务器响应和敏感数据线索，但授权状态仍需由认证、Session 和服务端权限日志验证。"
        if response.get("status") == "✅ 已覆盖"
        and exposure.get("status") != "❌ 缺失"
        and authorization.get("status") != "✅ 已覆盖"
        else response.get("conclusion") or "当前证据不足以确认服务器处理结果。"
    )
    return (
        f"{name} 当前归类为“{classification}”；观察风险为 {risk['level']}（{risk['score']}/100），"
        f"研判置信度为 {risk.get('confidence_level', '低')}（{risk.get('confidence_score', 0)}/100）。"
        f"{conclusion}"
    )


def _behavior_text(value: Any) -> str:
    excluded = {"name", "rulename", "alertname", "ruletitle", "threattype", "risklevel"}

    def walk(item: Any) -> list[str]:
        if isinstance(item, dict):
            return [
                part
                for key, child in item.items()
                if str(key).lower() not in excluded
                for part in walk(child)
            ]
        if isinstance(item, list):
            return [part for child in item for part in walk(child)]
        return [str(item)] if item not in (None, "", False, 0, 0.0, "0") else []

    return " ".join(walk(value)).lower()


SCENE_COMPAT_ALIASES = {
    "sql_injection": "injection",
    "command_injection": "command_execution",
    "rce": "command_execution",
    "xss": "xss",
    "sensitive_data_exposure": "data_exposure",
    "plaintext_credential": "data_exposure",
    "data_exfiltration": "data_exposure",
    "file_upload_abuse": "malware_file",
    "malware": "malware_file",
    "scan": "scanning",
    "normal_behavior": "credential_authentication",
    "weak_credential": "credential_authentication",
    "brute_force": "credential_authentication",
    "credential_stuffing": "credential_authentication",
    "unknown": "generic",
}


def _compat_scene_result(security_result: dict[str, Any]) -> dict[str, Any]:
    """Keep the old report schema while exposing the new classifier beside it."""
    candidates: list[dict[str, Any]] = []
    for original in security_result.get("candidates", []):
        item = dict(original)
        item["security_problem_id"] = original.get("scene_id")
        item["scene_id"] = SCENE_COMPAT_ALIASES.get(
            str(original.get("scene_id")), str(original.get("scene_id", "generic"))
        )
        item["support_evidence_ids"] = [
            support.get("evidence_id")
            for support in original.get("support", [])
            if isinstance(support, dict) and support.get("evidence_id")
        ]
        item["support"] = [
            f"{support.get('evidence_id')}: {support.get('reason', '当前事件证据')}"
            if isinstance(support, dict)
            else str(support)
            for support in original.get("support", [])
        ]
        candidates.append(item)
    return {
        "candidates": candidates,
        "inputs": {
            "normalized_event": True,
            "business_context_action": security_result.get("context_id", "unknown"),
            "direct_evidence_count": sum(
                len(item.get("support", [])) for item in candidates
            ),
            "negative_evidence_count": 0,
            "alert_metadata_used_as_fact": False,
            "source": "security_problem_classifier",
        },
    }


def _legacy_attack_profile(alert: dict[str, Any]) -> dict[str, str]:
    """Build a conservative, report-oriented hypothesis from observable signals."""
    text = _behavior_text(alert)
    profiles = (
        (
            ("union select", "sql 注入", "sql injection", "sql syntax"),
            {
                "name": "疑似 SQL 注入尝试",
                "hypothesis": "请求中出现 SQL 语义或数据库异常信号，需验证应用是否将外部输入拼接进查询语句。",
                "focus": "应用访问日志、数据库审计、慢查询/错误日志、受影响接口的参数处理逻辑",
                "containment": "经审批后在网关或 WAF 对已确认的恶意特征实施临时限制，并保留命中样本。",
                "remediation": "对受影响接口采用参数化查询、输入验证、最小数据库权限，并排查同类动态查询。",
                "validation": "在隔离或受控测试环境回放原始特征，确认危险语句不再进入数据库执行层。",
            },
        ),
        (
            ("rce", "命令执行", "cmd.exe", "powershell", "bash -c", ";cat "),
            {
                "name": "疑似命令执行尝试",
                "hypothesis": "请求或告警字段含有命令执行语义，需验证是否触发了应用子进程、脚本解释器或异常出站行为。",
                "focus": "Web/应用日志、进程树、EDR 告警、临时目录、DNS 与出站网络记录",
                "containment": "经审批后隔离受影响工作负载或限制可疑来源，并优先保全进程与网络证据。",
                "remediation": "移除危险的命令拼接与解释器调用，启用允许列表、最小运行权限和运行时监控。",
                "validation": "在受控环境验证外部输入不能生成子进程、命令行或异常网络连接。",
            },
        ),
        (
            ("xss", "<script", "javascript:", "onerror="),
            {
                "name": "疑似跨站脚本尝试",
                "hypothesis": "输入含有脚本执行语义，需确认该内容是否被持久化或以未编码形式回显给浏览器。",
                "focus": "请求/响应样本、页面渲染链路、存储记录、CSP 报告与受影响会话",
                "containment": "对已确认的恶意载荷做受控过滤，并评估受影响页面与会话令牌的暴露风险。",
                "remediation": "在所有输出上下文执行正确编码，实施内容安全策略并避免拼接 HTML/脚本。",
                "validation": "在测试环境确认同一载荷被安全编码且浏览器未发生脚本执行。",
            },
        ),
        (
            ("brute", "爆破", "password spray", "登录失败", "login failed"),
            {
                "name": "疑似凭据攻击或异常认证尝试",
                "hypothesis": "告警出现高频认证或凭据攻击信号，需判断是否为正常失败、密码喷洒或已成功登录后的横向活动。",
                "focus": "认证日志、账号失败/成功序列、来源 ASN/地理、MFA 记录和会话活动",
                "containment": "经审批后限制确认的高风险来源，并对可疑账号执行会话撤销、密码重置或加强验证。",
                "remediation": "启用 MFA、速率限制、异常登录检测和弱口令治理。",
                "validation": "核对封禁与会话处置后，异常失败率下降且不存在对应的可疑成功登录。",
            },
        ),
    )
    for signals, profile in profiles:
        if any(signal in text for signal in signals):
            return profile
    return {
        "name": "待分类安全异常",
        "hypothesis": "当前字段表明存在需要调查的安全异常，但不足以可靠归类具体攻击技术或确认攻击结果。",
        "focus": "原始告警、关联日志、受影响资产信息、请求/响应结果与时间范围",
        "containment": "在证据保全和业务影响评估完成后，经审批对已确认风险采取最小范围的受控限制。",
        "remediation": "根据根因验证结果修复暴露面，并为同类资产补充检测和变更验证。",
        "validation": "通过关联日志、受控复测和观察窗口验证风险已消除且正常业务未受影响。",
    }


def _attack_profile(
    alert: dict[str, Any],
    event_assessment: dict[str, Any] | None = None,
    business_context: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Render report guidance from the selected scene, never from keywords alone."""
    selected = (
        (event_assessment or {}).get("selected_scene")
        or (event_assessment or {}).get("primary_scenario")
        or {}
    )
    name = str(selected.get("name") or "主要场景待确认")
    context = business_context or (event_assessment or {}).get("business_context") or {}
    action = str(context.get("action") or "unknown")
    hypothesis = str(
        context.get("observed_behavior")
        or "当前缺少足够业务语义，需补充原始请求、响应和关联日志。"
    )
    deviations = context.get("deviation") or []
    if deviations:
        hypothesis = (
            hypothesis
            + " 观察到的偏差："
            + "；".join(str(item) for item in deviations[:3])
        )
    guidance = {
        "credential_authentication": {
            "focus": "认证日志、账号失败/成功序列、MFA、Session 和后续访问行为",
            "containment": "经审批后限制确认的高风险来源，并对可疑账号执行会话撤销、密码重置或加强验证。",
            "remediation": "启用 MFA、速率限制、异常登录检测和弱凭据治理，保留正常登录成功路径。",
            "validation": "用正常、失败和异常主体分别验证认证结果、Session 生命周期和后续访问行为。",
        },
        "data_exposure": {
            "focus": "请求主体、资源归属、服务端授权决策、敏感字段返回和数据访问/外传审计",
            "containment": "经审批后收紧受影响入口或会话，并保全响应、访问主体和数据审计证据。",
            "remediation": "补齐服务端身份认证、Session 与对象级/功能级授权；采用最小权限和最小化字段返回。",
            "validation": "用已授权、未授权和越权主体在受控环境验证资源、功能和敏感字段均按预期拒绝或脱敏。",
        },
        "injection": {
            "focus": "应用访问日志、数据库/解释器审计、错误日志、参数处理代码和受控复测",
            "containment": "经审批后在网关或 WAF 对已确认的恶意特征实施临时限制，并保留命中样本。",
            "remediation": "对受影响接口采用参数化查询或安全 API、输入验证和最小服务权限。",
            "validation": "在隔离环境回放原始特征与合理变体，确认危险语义不再进入执行层。",
        },
        "command_execution": {
            "focus": "Web/应用日志、进程树、EDR、临时目录、DNS 与出站网络记录",
            "containment": "经审批后隔离受影响工作负载或限制可疑来源，并优先保全进程与网络证据。",
            "remediation": "移除危险命令拼接，启用允许列表、最小运行权限和运行时监控。",
            "validation": "在受控环境确认外部输入不能生成任意子进程、命令行或异常网络连接。",
        },
        "xss": {
            "focus": "请求/响应样本、页面渲染链路、存储记录、CSP 报告与受影响会话",
            "containment": "对已确认的恶意载荷做受控过滤，并评估受影响页面与会话令牌的暴露风险。",
            "remediation": "在所有输出上下文执行正确编码，实施内容安全策略并避免拼接 HTML/脚本。",
            "validation": "在测试环境确认同一载荷被安全编码且浏览器未发生脚本执行。",
        },
        "malware_file": {
            "focus": "文件落盘、Hash、执行状态、进程树、EDR 和主机网络日志",
            "containment": "经审批后隔离受影响工作负载或样本，并保全文件与进程证据。",
            "remediation": "清理恶意文件和持久化入口，收紧执行权限并补充样本检测。",
            "validation": "在隔离环境验证样本不可执行、不可传播且资产完整性恢复。",
        },
        "scanning": {
            "focus": "扫描来源、目标范围、授权窗口、速率、WAF/API Gateway 和访问结果",
            "containment": "经审批后限制超出授权范围的扫描来源，避免影响正常业务。",
            "remediation": "完善扫描白名单、速率控制、暴露面治理和检测关联。",
            "validation": "核对授权扫描可识别、非授权探测被记录并不会绕过边界控制。",
        },
    }
    selected_guidance = guidance.get(
        action, guidance.get(str(selected.get("scene_id")), {})
    )
    return {
        "name": name,
        "hypothesis": hypothesis,
        "focus": str(
            selected_guidance.get("focus", "原始告警、关联日志、受影响资产和业务结果")
        ),
        "containment": str(
            selected_guidance.get(
                "containment",
                "在证据保全和业务影响评估完成后，经审批采取最小范围的受控限制。",
            )
        ),
        "remediation": str(
            selected_guidance.get(
                "remediation",
                "根据根因验证结果修复暴露面，并为同类资产补充检测和变更验证。",
            )
        ),
        "validation": str(
            selected_guidance.get(
                "validation",
                "通过关联日志、受控复测和观察窗口验证风险已消除且正常业务未受影响。",
            )
        ),
    }


def _confidence_label(evidence: dict[str, Any]) -> str:
    coverage = int(evidence.get("coverage", 0))
    if coverage >= 84:
        return "较高（关键证据组覆盖充分，仍需核验原始日志）"
    if coverage >= 50:
        return "中等（存在可用线索，但关键结论仍需补证）"
    return "较低（当前主要用于确定排查优先级，不足以确认攻击结果）"


def _fact_rows(alert: dict[str, Any], timeline: dict[str, Any]) -> str:
    fields = (
        ("name", "告警名称"),
        ("description", "告警描述"),
        ("srcIp", "来源地址"),
        ("sourceIp", "来源地址"),
        ("dstIp", "目标地址"),
        ("targetIp", "目标地址"),
        ("protocol", "协议"),
        ("url", "请求目标/载荷"),
        ("responseBody", "响应线索"),
        ("dbExecStatus", "执行状态线索"),
    )
    rows: list[str] = []
    seen: set[str] = set()
    for key, label in fields:
        value = alert.get(key)
        if key in seen or value in (None, "", [], {}):
            continue
        seen.add(key)
        rows.append(f"| {label} | {_md(value)} | `alert.{key}` |")
    if timeline.get("events"):
        rows.append(
            "| 可验证时间字段 | 已提取事件时间线，详见第 8 节 | `alert.*time*` |"
        )
    return (
        "\n".join(rows)
        or "| 暂无可直接复述的告警字段 | 需要补充原始告警和关联日志 | - |"
    )


def _gap_rows(evidence: dict[str, Any]) -> str:
    collection_plan = {
        "请求证据": (
            "完整请求头、参数、请求体与编码前样本",
            "确认请求是否发送、访问了哪个接口及其触发条件",
        ),
        "服务器响应": (
            "HTTP 状态、响应头/体、应用访问日志",
            "确认服务端是否处理并返回了有效响应",
        ),
        "服务器处理": (
            "HTTP 状态、应用访问日志与服务端错误日志",
            "确认服务器是否接收并成功处理请求",
        ),
        "有效业务响应": (
            "完整脱敏响应体、应用访问日志与接口返回码定义",
            "确认返回内容是否为有效业务结果",
        ),
        "认证信息观察": (
            "请求头、Cookie、Session、令牌及网关认证上下文",
            "确认是否观察到身份或会话上下文，而非推断其不存在",
        ),
        "认证与授权": (
            "认证日志、Session、Cookie、网关鉴权及服务端权限决策日志",
            "确认请求者身份和是否被合法授权",
        ),
        "敏感数据/执行结果": (
            "完整脱敏响应、数据访问审计、应用/数据库执行日志",
            "确认敏感数据、功能或危险操作是否实际暴露/执行",
        ),
        "漏洞成立条件": (
            "接口设计、授权策略、版本/配置、受控复测结果",
            "确认漏洞或配置缺陷是否成立",
        ),
        "后续利用与影响": (
            "WAF/API Gateway、账号行为、数据库审计、EDR/主机日志和调用链",
            "确认是否存在进一步利用、横向活动或范围扩展",
        ),
        "业务/资产影响": (
            "资产重要性、数据分级、业务监控、账号与数据变更审计",
            "确认业务、账号、数据或资产实际影响",
        ),
        "时间与关联": (
            "有效事件时间、应用访问日志、WAF/API Gateway 日志和上下游调用链",
            "建立可复核时间窗口并关联同源、同目标和同特征事件",
        ),
    }
    rows = []
    for item in evidence["rows"]:
        if item["status"] == "✅ 已覆盖":
            continue
        required, impact = collection_plan.get(
            item["label"], ("原始告警与关联日志", "核验当前结论")
        )
        rows.append(f"| {item['label']} | {required} | {impact} |")
    return (
        "\n".join(rows)
        or "| 无关键证据组缺失 | 继续抽样核验现有来源 | 保持结论可追溯 |"
    )


def _hunt_rows(
    alert: dict[str, Any], iocs: dict[str, Any], timeline: dict[str, Any]
) -> str:
    source = _md(alert.get("srcIp") or alert.get("sourceIp"), "当前未提供")
    target = _md(alert.get("dstIp") or alert.get("targetIp"), "当前未提供")
    url = _md(alert.get("url"), "当前未提供")
    rows = [
        f"| 来源关联 | 以 `{source}` 为线索检索相邻时间窗的认证、Web、WAF 与网络日志 | 判断是否存在同源探测、会话切换或横向行为 |",
        f"| 目标关联 | 围绕 `{target}` 的应用、主机、数据库或容器审计进行核验 | 判断是否产生真实执行、异常进程或数据访问 |",
        f"| 特征关联 | 搜索与 `{url}` 相同或相近的路径、参数和编码变体 | 识别攻击变种、重复命中与受影响接口范围 |",
    ]
    if iocs.get("total"):
        rows.append(
            "| IOC 关联 | 使用第 8 节 IOC 在 SIEM/EDR/WAF 中进行只读检索并保留命中上下文 | 扩展或排除相关事件范围 |"
        )
    if not timeline.get("events"):
        rows.append(
            "| 时间范围 | 先补充事件时间；在时间未知前避免对全量历史数据作无边界推断 | 建立可复核的调查窗口 |"
        )
    return "\n".join(rows)


def _strip_markdown_fence(report: str) -> str:
    text = report.strip()
    match = re.fullmatch(
        r"```(?:markdown|md)?\s*(.*?)\s*```", text, re.DOTALL | re.IGNORECASE
    )
    return match.group(1).strip() if match else text


def _ensure_chart_markers(report: str, charts: list[dict[str, Any]]) -> str:
    missing = [
        chart for chart in charts if f"<!-- chart:{chart['id']} -->" not in report
    ]
    if not missing:
        return report
    appendix = "\n\n## 数据图表\n\n" + "\n\n".join(
        f"<!-- chart:{chart['id']} -->" for chart in missing
    )
    return report.rstrip() + appendix


@dataclass
class AgentState:
    memory_id: str
    raw_alert: dict[str, Any] | str
    requirement: str
    use_model: bool
    alert: dict[str, Any] = field(default_factory=dict)
    normalized_event: dict[str, Any] = field(default_factory=dict)
    business_context: dict[str, Any] = field(default_factory=dict)
    evidence_store: dict[str, Any] = field(default_factory=dict)
    security_result: dict[str, Any] = field(default_factory=dict)
    router: dict[str, Any] = field(default_factory=dict)
    workflow_result: dict[str, Any] = field(default_factory=dict)
    scene_result: dict[str, Any] = field(default_factory=dict)
    query: str = ""
    iocs: dict[str, Any] = field(default_factory=dict)
    entities: dict[str, Any] = field(default_factory=dict)
    timeline: dict[str, Any] = field(default_factory=dict)
    event_assessment: dict[str, Any] = field(default_factory=dict)
    risk: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    consistency: dict[str, Any] = field(default_factory=dict)
    citations: list[dict[str, Any]] = field(default_factory=list)
    charts: list[dict[str, Any]] = field(default_factory=list)
    improvement_plan: dict[str, Any] = field(default_factory=dict)
    memory_insights: list[dict[str, Any]] = field(default_factory=list)
    reasoning_trace: list[dict[str, Any]] = field(default_factory=list)
    chain_trace: list[dict[str, Any]] = field(default_factory=list)
    report: str = ""
    engine: str = "langchain-llm"
    llm_assessment: dict[str, Any] = field(default_factory=dict)
    usage: dict[str, Any] = field(default_factory=dict)
    review: dict[str, Any] = field(default_factory=dict)
    knowledge_query: str = ""
    fallbacks: list[dict[str, Any]] = field(default_factory=list)
    model_calls: list[dict[str, Any]] = field(default_factory=list)
    analysis_trace_events: list[dict[str, Any]] = field(default_factory=list)
    review_history: list[dict[str, Any]] = field(default_factory=list)
    structured_review: dict[str, Any] = field(default_factory=dict)
    revision_feedback: dict[str, Any] = field(default_factory=dict)
    state_version: int = 1
    generated_from_state_version: int | None = None
    state_fingerprint: str = ""
    report_fingerprint: str = ""
    review_iteration: int = 0
    max_review_retries: int = 2


class ChainAgent:
    agent_id = "agent"
    label = "Agent"
    role = "执行安全研判节点"

    async def run(self, state: AgentState) -> None:
        raise NotImplementedError

    def record(
        self,
        state: AgentState,
        started: float,
        input_summary: str,
        output_summary: str,
        next_agent: str | None,
        tools: list[str] | None = None,
    ) -> None:
        state.chain_trace.append(
            {
                "step": len(state.chain_trace) + 1,
                "agent_id": self.agent_id,
                "label": self.label,
                "role": self.role,
                "status": "completed",
                "input_summary": input_summary,
                "output_summary": output_summary,
                "next_agent": next_agent,
                "tools": tools or [],
                "duration_ms": max(
                    0, round((time.perf_counter() - started) * 1_000, 2)
                ),
            }
        )


class PlanningAgent(ChainAgent):
    agent_id = "planner"
    label = "规划 Agent"
    role = "验证输入、界定安全边界并生成研判任务计划"

    async def run(self, state: AgentState) -> None:
        started = time.perf_counter()
        raw_alert = _parse_alert(state.raw_alert)
        if not isinstance(raw_alert, dict):
            raise TypeError("告警顶层必须是 JSON 对象")
        alert = redact(raw_alert)
        state.alert = alert
        state.query = _query(alert)
        normalization_call = tool_registry.execute(
            "normalize_alert", {"alert": raw_alert}
        )
        state.normalized_event = normalization_call["output"]
        _record_stage(
            state,
            "normalization",
            "completed",
            {
                "http": state.normalized_event.get("http", {}),
                "authorization": state.normalized_event.get("authorization", {}),
                "business_result": state.normalized_event.get("business_result", {}),
                "network": state.normalized_event.get("network", {}),
                "timestamps": state.normalized_event.get("timestamps", []),
            },
            tool="normalize_alert",
            duration_ms=normalization_call["duration_ms"],
        )
        self.record(
            state,
            started,
            f"接收 {len(alert)} 个顶层字段和 {len(state.requirement)} 字符的研判要求",
            "完成规范化并生成只读工具计划：业务上下文、场景、证据、风险、知识、报告与复核",
            "evidence",
        )


class MemoryAgent(ChainAgent):
    agent_id = "memory"
    label = "记忆 Agent"
    role = "在场景与 Workflow 选择后检索用户授权经验，并保持其与当前证据隔离"

    async def run(self, state: AgentState) -> None:
        started = time.perf_counter()
        if not state.router:
            raise RuntimeError(
                "Memory Agent 必须在 Security Problem 与 Workflow Router 之后运行"
            )
        state.memory_insights = memory_store.recall(state.alert)
        negative_count = sum(
            1
            for item in state.memory_insights
            if item.get("feedback_type") == "negative"
        )
        self.record(
            state,
            started,
            "当前脱敏告警与用户明确同意学习的历史经验",
            f"匹配 {len(state.memory_insights)} 条经验，其中 {negative_count} 条反面纠错样例；"
            "报告生成前需提取并避免相似错误，仅作为提示，不能替代当前证据",
            "risk",
            ["local_memory_recall"],
        )


class EvidenceAgent(ChainAgent):
    agent_id = "evidence"
    label = "证据 Agent"
    role = (
        "分离业务上下文与安全问题，建立统一证据溯源并执行 Router 选定的 Workflow 工具"
    )

    async def run(self, state: AgentState) -> None:
        started = time.perf_counter()
        field_count = len(state.alert)
        context_call = tool_registry.execute(
            "infer_business_context",
            {"alert": state.alert, "normalized_event": state.normalized_event},
        )
        state.business_context = context_call["output"]
        _record_stage(
            state,
            "business_context",
            "completed",
            state.business_context,
            tool="infer_business_context",
            duration_ms=context_call["duration_ms"],
        )
        evidence_store_call = tool_registry.execute(
            "build_evidence_store",
            {
                "alert": state.alert,
                "normalized_event": state.normalized_event,
                "business_context": state.business_context,
            },
        )
        state.evidence_store = evidence_store_call["output"]
        _record_stage(
            state,
            "evidence_store",
            "completed",
            {
                "evidence_count": state.evidence_store.get("evidence_count", 0),
                "current_evidence_count": state.evidence_store.get(
                    "current_evidence_count", 0
                ),
                "embedded_evidence_count": state.evidence_store.get(
                    "embedded_evidence_count", 0
                ),
            },
            tool="build_evidence_store",
            duration_ms=evidence_store_call["duration_ms"],
        )
        security_call = tool_registry.execute(
            "classify_security_problems",
            {
                "alert": state.alert,
                "normalized_event": state.normalized_event,
                "business_context": state.business_context,
                "evidence_store": state.evidence_store,
            },
        )
        state.security_result = security_call["output"]
        state.scene_result = _compat_scene_result(state.security_result)
        router_call = tool_registry.execute(
            "route_workflow",
            {
                "business_context": state.business_context,
                "security_result": state.security_result,
                "evidence_store": state.evidence_store,
            },
        )
        state.router = router_call["output"]
        workflow_evidence_call = tool_registry.execute(
            "build_workflow_evidence",
            {
                "router": state.router,
                "evidence_store": state.evidence_store,
                "security_result": state.security_result,
            },
        )
        state.workflow_result = workflow_evidence_call["output"]
        _record_stage(
            state,
            "security_classification",
            "completed",
            {
                "candidates": state.security_result.get("candidates", []),
                "context_id": state.business_context.get("context_id"),
                "confidence": state.business_context.get("confidence_score"),
            },
            tools=["build_evidence_store", "classify_security_problems"],
            duration_ms=round(
                evidence_store_call["duration_ms"] + security_call["duration_ms"], 2
            ),
        )
        # Compatibility stage name retained for existing API consumers; the
        # structured security_classification event is the authoritative one.
        _record_stage(
            state,
            "scene_classification",
            "completed",
            {
                "selected_security_problem": (
                    state.security_result.get("candidates") or [{}]
                )[0].get("scene_id", "unknown"),
                "compatibility_scene_id": (
                    state.scene_result.get("candidates") or [{}]
                )[0].get("scene_id", "generic"),
                "source": "security_classification",
            },
            compatibility_alias=True,
        )
        _record_stage(
            state,
            "workflow_router",
            "completed",
            {
                "primary_workflow": state.router.get("primary_workflow"),
                "secondary_workflows": state.router.get("secondary_workflows", []),
                "risk_profile_id": state.router.get("risk_profile_id"),
                "tool_plan": state.router.get("tool_plan", []),
                "reason": state.router.get("reason"),
            },
            tools=["route_workflow", "build_workflow_evidence"],
            duration_ms=round(
                router_call["duration_ms"] + workflow_evidence_call["duration_ms"], 2
            ),
        )
        assessment_call = tool_registry.execute(
            "assess_event_layers",
            {
                "alert": state.alert,
                "normalized_event": state.normalized_event,
                "business_context": state.business_context,
                "scene_result": state.scene_result,
            },
        )
        state.event_assessment = assessment_call["output"]
        state.scene_result["selected_scene"] = state.event_assessment.get(
            "selected_scene", {}
        )
        state.event_assessment["security_problem_candidates"] = (
            state.security_result.get("candidates", [])
        )
        state.event_assessment["router"] = state.router
        state.event_assessment["workflow"] = state.workflow_result
        _trace(
            state.reasoning_trace,
            assessment_call,
            "evidence",
            "按九层事件成立条件建立事实、推断与未知边界",
            f"{field_count} 个顶层字段",
            f"确认事实 {len(state.event_assessment.get('facts', []))} 项，合理推断 {len(state.event_assessment.get('inferences', []))} 项，待确认 {len(state.event_assessment.get('unknowns', []))} 项",
            [
                item.get("source", "alert.*")
                for item in state.event_assessment.get("facts", [])[:5]
            ],
        )
        state.iocs = {"indicators": [], "excluded": [], "counts": {}, "total": 0}
        state.entities = {"entities": [], "total": 0, "ioc_total": 0}
        state.timeline = {"events": [], "unrecorded": [], "total": 0}
        tool_plan = list(state.router.get("tool_plan", []))
        for tool_name in tool_plan:
            if tool_name == "assess_event_layers":
                continue
            call = tool_registry.execute(tool_name, {"alert": state.alert})
            if tool_name == "extract_iocs":
                state.iocs = call["output"]
                purpose = "按攻击关联价值识别可追踪安全指标并排除系统标识符"
                output = f"识别 {state.iocs['total']} 个 IOC，排除 {len(state.iocs.get('excluded', []))} 个非 IOC 候选"
                evidence = [
                    item.get("source", "alert.*")
                    for item in state.iocs.get("indicators", [])[:5]
                ]
            elif tool_name == "extract_security_entities":
                state.entities = call["output"]
                purpose = "将资产、应用、技术栈、敏感数据、身份、漏洞和 IOC 分开分类"
                output = f"识别 {state.entities['total']} 个安全实体，其中 {state.entities['ioc_total']} 个为具攻击关联价值的 IOC"
                evidence = [
                    item.get("source", "alert.*")
                    for item in state.entities.get("entities", [])[:5]
                ]
            elif tool_name == "build_timeline":
                state.timeline = call["output"]
                purpose = "重建可验证事件顺序"
                output = f"生成 {state.timeline['total']} 个有效时间节点；未记录 {len(state.timeline.get('unrecorded', []))} 项"
                evidence = [
                    item["source"] for item in state.timeline.get("events", [])[:5]
                ]
            else:
                continue
            _trace(
                state.reasoning_trace,
                call,
                "evidence",
                purpose,
                f"{field_count} 个顶层字段",
                output,
                evidence,
            )
        self.record(
            state,
            started,
            f"当前告警 {field_count} 个字段",
            f"context={state.business_context.get('context_id')}，问题候选 {len(state.security_result.get('candidates', []))} 个，路由 {state.router.get('primary_workflow')}；完成九层事件判断",
            "memory",
            [
                "infer_business_context",
                "build_evidence_store",
                "classify_security_problems",
                "route_workflow",
                "build_workflow_evidence",
            ]
            + tool_plan,
        )


class RiskAgent(ChainAgent):
    agent_id = "risk"
    label = "风险 Agent"
    role = "用工具整理证据，再由 LLM 独立判断场景、结论和置信度"

    async def run(self, state: AgentState) -> None:
        started = time.perf_counter()
        evidence_call = tool_registry.execute(
            "evidence_matrix",
            {
                "alert": state.alert,
                "event_assessment": state.event_assessment,
                "timeline": state.timeline,
                "evidence_store": state.evidence_store,
            },
        )
        state.evidence = evidence_call["output"]
        _trace(
            state.reasoning_trace,
            evidence_call,
            "analysis",
            "以已覆盖、部分覆盖、缺失、存在冲突四态量化有效证据",
            "九层事件判断、原始字段、语义冲突与有效时间线",
            f"完整覆盖 {state.evidence['covered']} 类、部分覆盖 {state.evidence.get('partial', 0)} 类、缺失 {state.evidence.get('missing', 0)} 类、冲突 {state.evidence.get('conflicts', 0)} 类（有效覆盖 {state.evidence['coverage']}%）",
            [
                row["source"]
                for row in state.evidence["rows"]
                if row["status"] == "✅ 已覆盖"
            ],
        )
        risk_call = tool_registry.execute(
            "calculate_risk",
            {
                "alert": state.alert,
                "event_assessment": state.event_assessment,
                "evidence": state.evidence,
                "router": state.router,
            },
        )
        state.risk = risk_call["output"]
        _trace(
            state.reasoning_trace,
            risk_call,
            "analysis",
            "按主场景选择风险维度并独立计算研判置信度",
            "场景化敏感性、成功度、授权/执行、资产影响、外传或后续行为和有效证据覆盖",
            f"观察风险 {state.risk['score']}/100（{state.risk['level']}），研判置信度 {state.risk.get('confidence_score', 0)}/100（{state.risk.get('confidence_level', '低')}）",
            [item.get("evidence", "-") for item in state.risk.get("dimensions", [])],
        )
        knowledge_query = _knowledge_query(
            state.alert,
            state.event_assessment,
            state.business_context,
            state.evidence,
            state.requirement,
            state.router,
            state.evidence_store,
        )
        state.knowledge_query = knowledge_query
        knowledge_call = tool_registry.execute(
            "search_knowledge",
            {
                "query": knowledge_query,
                "limit": 6,
                "min_relevance": 0.05,
                "scene_id": state.event_assessment.get("scene_id", "generic"),
                "workflow_id": state.router.get("workflow_id", "generic_workflow"),
                "risk_profile_id": state.router.get("risk_profile_id", "GENERIC_RISK"),
            },
        )
        knowledge = knowledge_call["output"]
        state.citations = knowledge["results"]
        _trace(
            state.reasoning_trace,
            knowledge_call,
            "knowledge",
            "检索本地知识并建立可追溯引用",
            f"按主场景检索：{knowledge['query'][:100]}",
            f"返回 {knowledge['total']} 个知识片段",
            [item["id"] for item in state.citations],
        )
        contradiction_call = tool_registry.execute(
            "detect_contradictions",
            {
                "event_assessment": state.event_assessment,
                "evidence": state.evidence,
                "timeline": state.timeline,
                "risk": state.risk,
                "alert": state.alert,
            },
        )
        state.consistency = contradiction_call["output"]
        _trace(
            state.reasoning_trace,
            contradiction_call,
            "review",
            "在报告前交叉检查 Agent 输出是否存在事实矛盾",
            "事件分层、证据矩阵、时间线与风险置信度",
            state.consistency.get("summary", "完成一致性检查"),
            [
                item.get("area", "结构化输出")
                for item in state.consistency.get("conflicts", [])
            ],
        )
        assessment = await invoke_stage(
            "evidence_reasoning",
            "独立分析证据并给出场景判断和结论。工具路由是候选，不得盲从。"
            "只能从 current_evidence_ids 中选择 confirmed_facts 的 Evidence ID，逐项引用当前 layer=0 且 applicable 的直接证据；"
            "不能用嵌入日志或历史记忆支持当前事实。"
            "字段名、规则命中和 HTTP 响应文本不能替代字段值、授权结果、数据库审计或后续行为；没有直接证据时必须放入 hypotheses/evidence_gaps，"
            "并在 confidence_factors 中说明证据覆盖、关键缺口和不确定性来源。"
            "不能可靠定性时用 insufficient_evidence，不强行判恶意；"
            "feedback_checks 必须与 memory_insights 的 lesson_id 集合完全相等：memory_insights 为空时必须返回空数组，"
            "有几条经验就逐条返回对应 lesson_id，且不得新增不存在的 lesson_id；每条都要说明适用或不适用的原因。"
            "如有 previous_review，必须据其纠正前次推理。",
            _llm_context(state),
            state.model_calls,
            Assessment,
        )
        validate_assessment(assessment, state.evidence_store, state.memory_insights)
        state.llm_assessment = assessment.model_dump()
        logger.info(
            "[Risk Agent] confirmed_facts=%d hypotheses=%d verdict=%s confidence=%s",
            len(state.llm_assessment.get("confirmed_facts", [])),
            len(state.llm_assessment.get("hypotheses", [])),
            state.llm_assessment.get("verdict"),
            state.llm_assessment.get("confidence"),
        )
        _record_stage(
            state,
            "risk",
            "completed",
            {
                "scene_id": state.risk.get("scene_id"),
                "workflow_id": state.risk.get("workflow_id"),
                "risk_profile_id": state.risk.get("risk_profile_id"),
                "risk_profile": state.risk.get("risk_profile", {}),
                "score": state.risk.get("score"),
                "confidence_score": state.risk.get("confidence_score"),
                "knowledge_query": state.knowledge_query,
                "citation_count": len(state.citations),
                "consistency": state.consistency.get("consistent"),
            },
            tools=[
                "evidence_matrix",
                "calculate_risk",
                "search_knowledge",
                "detect_contradictions",
            ],
        )
        self.record(
            state,
            started,
            "当前证据、IOC、事件时间线与内置知识库",
            f"风险 {state.risk['score']}/100，置信度 {state.risk.get('confidence_level', '低')}，证据覆盖 {state.evidence['coverage']}%，一致性：{state.consistency.get('summary', '待检查')}",
            "report",
            [
                "evidence_matrix",
                "calculate_risk",
                "search_knowledge",
                "detect_contradictions",
            ],
        )


class ReportAgent(ChainAgent):
    agent_id = "report"
    label = "报告 Agent"
    role = "整合证据、经验提示与模型能力，生成 Markdown 报告和图表"

    async def run(self, state: AgentState) -> None:
        started = time.perf_counter()
        improvement_call = tool_registry.execute(
            "build_improvement_plan",
            {
                "alert": state.alert,
                "risk": state.risk,
                "evidence": state.evidence,
                "event_assessment": state.event_assessment,
                "router": state.router,
                "workflow": state.workflow_result,
            },
        )
        state.improvement_plan = improvement_call["output"]
        _trace(
            state.reasoning_trace,
            improvement_call,
            "response",
            "将研判结果转化为待审批的响应、恢复、沟通与能力改进计划",
            "当前告警、风险评估与证据缺口",
            f"生成 {len(state.improvement_plan.get('response_actions', []))} 项响应和 {len(state.improvement_plan.get('improvements', []))} 项改进措施",
            ["response_actions", "improvements", "closure_criteria"],
        )
        chart_call = tool_registry.execute(
            "build_report_charts",
            {
                "risk": state.risk,
                "evidence": state.evidence,
                "iocs": state.iocs,
                "timeline": state.timeline,
                "improvement_plan": state.improvement_plan,
            },
        )
        state.charts = chart_call["output"]["charts"]
        _trace(
            state.reasoning_trace,
            chart_call,
            "presentation",
            "把分析结果转换为结构化可视化",
            "风险、证据、IOC 与时间线结果",
            f"生成 {len(state.charts)} 个图表",
            [chart["id"] for chart in state.charts],
        )
        state.report = str(
            redact(
                _strip_markdown_fence(
                    await invoke_stage(
                        "report_generation",
                        "根据当前 State 中的 llm_assessment、Evidence Store 和结构化工具结果，独立撰写完整中文 Markdown 调查报告；不是扩写模板。"
                        "报告的研判结论和置信度须与 llm_assessment 一致；在“研判结论”章节逐字保留 llm_assessment.conclusion，"
                        "verdict 和 confidence 也必须与 llm_assessment 完全一致。不得把 credential/password/token 字段的存在"
                        "升级为真实凭据、凭据有效或攻击成功，除非当前 Evidence Store 有直接验证证据。"
                        "规则风险评分只作为工具指标标明来源，"
                        "不得将其包装为模型置信度。引用当前事实的 Evidence ID、存在的 [K-01] 形式知识引用，"
                        "只能使用 context 中 current_evidence_ids 列出的 Evidence ID；必须保留 llm_assessment 的 confirmed_facts、"
                        "evidence_gaps 和 recommended_checks 的边界，不得引入不存在的字段或新的确定性结论。"
                        "知识引用只能使用 context 中 available_knowledge_ids 的精确 ID；不得猜测或补写其他 K-编号。"
                        "知识库引用中的示例、判定条件和处置标准必须作为引用或背景，不得改写成当前事件事实。"
                        "当前告警字段名、规则命中、知识库示例和工具候选只能作为背景或待核验线索；只有 Evidence Store 中当前事件 layer=0 且 applicable 的直接证据，"
                        "以及 llm_assessment 中逐项绑定的 Evidence ID，才能写入确认事实。字段名不等于字段值，HTTP 成功不等于利用成功。"
                        "工具风险分数和证据覆盖率是独立的确定性指标，不是 LLM 置信度；必须分别标注，不能互相替代。"
                        "保留 charts 给出的 <!-- chart:ID --> 标记。至少2400字，具体解释证据缺口和待验证假设。"
                        "为避免供应商输出截断，请将正文控制在约3000至4500个中文字符；每个章节写1至3句有事实依据的内容，"
                        "禁止重复同一结论或生成与本告警无关的长篇背景。"
                        "必须覆盖这些章节：" + "、".join(REPORT_SECTIONS) + "。"
                        "响应和恢复仅为待审批建议，不宣称已经执行。若 previous_review 有问题，逐项修正。",
                        _llm_context(state),
                        state.model_calls,
                    )
                )
            )
        )
        state.generated_from_state_version = state.state_version
        _refresh_fingerprints(state)
        last_call = state.model_calls[-1]
        state.engine = (
            f"langchain-llm/{last_call['model_provider']}/{last_call['model_name']}"
        )
        logger.info(
            "[Report Agent] report generated length=%d state_version=%d",
            len(state.report),
            state.state_version,
        )
        _record_stage(
            state,
            "report",
            "completed",
            {
                "engine": state.engine,
                "chart_ids": [chart["id"] for chart in state.charts],
                "report_length": len(state.report),
                "fallback_count": 0,
            },
            tools=["build_improvement_plan", "build_report_charts", "llm_report"],
        )
        self.record(
            state,
            started,
            "当前证据与 LLM 结构化研判",
            f"LLM 生成报告与 {len(state.charts)} 个工具图表，等待独立复核",
            "review",
            ["build_improvement_plan", "build_report_charts", "llm_report"],
        )


class StructuredStateReviewAgent(ChainAgent):
    agent_id = "structured_state_review"
    label = "结构化状态复核 Agent"
    role = "在报告生成前复核规范化、业务上下文、场景、路由、证据契约与风险 Profile"

    async def run(self, state: AgentState) -> None:
        started = time.perf_counter()
        result = structured_state_review(
            state.raw_alert,
            state.normalized_event,
            state.business_context,
            {
                **state.scene_result,
                "selected_scene": state.event_assessment.get("selected_scene", {}),
                "event_assessment": state.event_assessment,
            },
            state.evidence,
            state.risk,
            router=state.router,
            evidence_store=state.evidence_store,
            security_result=state.security_result,
            workflow_result=state.workflow_result,
        )
        _refresh_fingerprints(state)
        result.update(
            {
                "review_iteration": state.review_iteration,
                "state_version": state.state_version,
                "state_fingerprint": state.state_fingerprint,
            }
        )
        state.structured_review = result
        if not result["approved"]:
            state.review = result
        _record_stage(
            state,
            "structured_state_review",
            "completed" if result["approved"] else "failed",
            {
                "approved": result["approved"],
                "failure_rules": result.get("failure_rules", []),
                "error_category": result.get("error_category"),
                "failure_reason": result.get("failure_reason", ""),
                "rollback_target": result.get("rollback_target"),
            },
            state_version=state.state_version,
            state_fingerprint=state.state_fingerprint,
            review_iteration=state.review_iteration,
        )
        self.record(
            state,
            started,
            "规范化、业务上下文、场景、路由、证据契约与风险 Profile",
            "结构化状态通过，允许生成报告"
            if result["approved"]
            else f"结构化状态失败：{result.get('failure_reason', '上游状态不一致')}",
            "report" if result["approved"] else None,
            ["structured_state_review"],
        )


class ReviewAgent(ChainAgent):
    agent_id = "review"
    label = "复核 Agent"
    role = "检查报告事实、边界、章节、引用和图表标记，输出可交付结果"

    async def run(self, state: AgentState) -> None:
        started = time.perf_counter()
        state.report = _ensure_chart_markers(state.report, state.charts)
        semantic = semantic_review(
            state.raw_alert,
            state.normalized_event,
            state.business_context,
            {
                **state.scene_result,
                "selected_scene": state.event_assessment.get("selected_scene", {}),
                "event_assessment": state.event_assessment,
            },
            state.evidence,
            state.risk,
            state.report,
            router=state.router,
            evidence_store=state.evidence_store,
            security_result=state.security_result,
            workflow_result=state.workflow_result,
            include_report_checks=True,
            state_version=state.state_version,
            generated_from_state_version=state.generated_from_state_version,
        )
        policy = report_policy_check(
            state.report,
            required_sections=REPORT_SECTIONS,
            known_knowledge_ids={item["id"] for item in state.citations},
            known_evidence_ids={
                item["evidence_id"] for item in state.evidence_store.get("items", [])
            },
            chart_ids=[chart["id"] for chart in state.charts],
            state_version=state.state_version,
            generated_from_state_version=state.generated_from_state_version,
        )
        model_review = await invoke_stage(
            "report_review",
            "你是独立复核员。对照原始当前证据复核 llm_assessment 与 report：事实引用是否支持结论、"
            "场景是否被工具或规则名误导、历史反面经验是否逐项自检、报告是否有无依据的风险或执行成功断言。"
            "必须检查结论和置信度与 llm_assessment 一致，不能只查格式。只检查 llm_assessment 实际存在的字段："
            "conclusion、primary_scenario、verdict、confidence、confirmed_facts、hypotheses、evidence_gaps、"
            "recommended_checks、feedback_checks；不要要求不存在的 verified_conclusions 字段。"
            "Evidence ID 只能依据 current_evidence_ids 判断有效性，不得凭空声称已列出的 ID 不存在。"
            "仅在当前结构化 State 或 report_policy_check 能直接证明存在明确矛盾时拒绝；不要把否定、假设、待核验、"
            "处置建议、知识库引用或安全边界中的示例措辞当成已发生攻击，也不要仅因工具指标与 LLM 置信度并列而拒绝。"
            "模型供应商、模型调用链、验证脚本和诊断元数据不属于报告事实；不得因报告或 llm_assessment 未描述内部模型链路而拒绝。"
            "若 semantic_review 和 report_policy_check 的可执行结果均为 PASS，不得凭规则名称、检查说明或引用文本臆造 FAIL。"
            "若问题仅涉及报告措辞、章节、引用、知识背景或置信度说明，error_scope 必须为 report；"
            "只有能直接证明 llm_assessment 的 confirmed_facts、hypotheses、evidence_gaps 或结论状态与当前 Evidence Store 矛盾时，"
            "error_scope 才能为 analysis，并应优先回滚到 Risk Agent。approved=true 时 error_scope 必须为 none。"
            "failed_rules 只能填写当前可证明的问题规则，不要把诊断建议当作规则失败。"
            "任何问题均 approved=false 并给出具体修改要求。禁止照抄报告中的自称通过。"
            "只输出严格合法的 JSON 对象，不要 Markdown 代码围栏；issues 和 correction_instructions 各最多 8 条，"
            "每条尽量不超过 200 个字符，不要在 JSON 字符串中使用未转义换行。",
            {
                **_llm_context(state),
                "report": state.report,
                "rule_review": semantic,
                "report_policy_check": policy,
                "structured_state_review": state.structured_review,
            },
            state.model_calls,
            ReviewDecision,
            max_tokens=1_800,
        )
        model_feedback, ignored_model_feedback = _actionable_review_feedback(
            model_review, semantic, policy
        )
        deterministic_failures = list(semantic.get("failures", [])) + list(
            policy.get("failures", [])
        )
        error_scope = _review_error_scope(
            model_review, model_feedback, deterministic_failures
        )
        model_failures = (
            [
                build_review_failure(
                    "llm_analysis_review"
                    if error_scope == "analysis"
                    else "llm_report_review",
                    "; ".join(model_feedback)
                    or "独立模型复核未批准当前报告。",
                    "risk" if error_scope == "analysis" else "report",
                )
            ]
            if model_feedback
            else []
        )
        failures = (
            list(semantic.get("failures", []))
            + list(policy.get("failures", []))
            + model_failures
        )
        primary = select_review_failure(failures) if failures else None
        approved = bool(
            (model_review.approved or not model_feedback)
            and not model_feedback
            and semantic["approved"]
            and policy["approved"]
            and state.structured_review.get("approved", False)
            and state.consistency.get("consistent", False)
        )
        state.review = {
            "stage": "final_report_review",
            "llm_review": model_review.model_dump(),
            "semantic_review": semantic,
            "report_policy_check": policy,
            "structured_state_review": state.structured_review,
            "failures": failures,
            "failure_rules": [item["rule_id"] for item in failures],
            "issues": [item["reason"] for item in failures],
            "failure_details": [item["details"] for item in failures],
            "error_categories": list(
                dict.fromkeys(
                    item.get("error_category", "UNKNOWN_ERROR") for item in failures
                )
            ),
            "error_scope": "none" if approved else error_scope,
            "error_category": primary.get("error_category") if primary else None,
            "failure_type": primary.get("failure_type") if primary else None,
            "approved": approved,
            "status": "PASS" if approved else "FAIL",
            "missing_sections": policy.get("missing_sections", []),
            "reference_issues": policy.get("unknown_knowledge_ids", [])
            + policy.get("unknown_evidence_ids", []),
            "conflicts": state.consistency.get("conflicts", [])
            + semantic.get("conflicts", []),
            "boundary": (
                "历史经验未被当作当前事件证据；最终 Markdown 已与规范化事件、业务上下文、主场景、证据和风险 Profile 交叉复核；"
                "报告未声明任何系统动作已执行。"
            ),
            "report_characters": len(state.report),
            "review_iteration": state.review_iteration,
            "state_version": state.state_version,
            "generated_from_state_version": state.generated_from_state_version,
            "state_fingerprint": state.state_fingerprint,
            "report_fingerprint": state.report_fingerprint,
            "model_review_ignored_feedback": ignored_model_feedback,
        }
        if model_review.failed_rules:
            state.review["model_failed_rules"] = list(model_review.failed_rules)
        if not approved:
            state.review["rollback_target"] = (
                primary.get("rollback_target") if primary else "report"
            )
            state.review["revision_action"] = (
                primary.get("revision_action")
                if primary
                else "重新生成报告并复核。"
            )
            state.review["failure_reason"] = (
                "; ".join(item["reason"] for item in failures[:4])
                or "报告质量检查未通过"
            )
        else:
            state.review["rollback_target"] = None
            state.review["revision_action"] = "无需回退；允许交付。"
            state.review["failure_reason"] = ""
        logger.info(
            "[Review Agent] approved=%s error_scope=%s failed_rules=%s rollback=%s",
            state.review["approved"],
            state.review["error_scope"],
            state.review.get("failure_rules", []),
            state.review.get("rollback_target"),
        )
        _refresh_fingerprints(state)
        _record_stage(
            state,
            "semantic_review",
            "completed" if state.review["approved"] else "failed",
            {
                "status": state.review["status"],
                "failure_reason": state.review.get("failure_reason", ""),
                "rollback_target": state.review.get("rollback_target"),
                "checks": semantic.get("checks", []),
                "failure_rules": state.review.get("failure_rules", []),
                "error_category": state.review.get("error_category"),
            },
            reviewed_final_report=True,
            review_iteration=state.review_iteration,
            state_version=state.state_version,
            state_fingerprint=state.state_fingerprint,
            report_fingerprint=state.report_fingerprint,
        )
        _record_stage(
            state,
            "report_policy_check",
            "completed" if policy["approved"] else "failed",
            {
                "status": policy["status"],
                "missing_sections": policy.get("missing_sections", []),
                "failure_rules": policy.get("failure_rules", []),
                "error_category": policy.get("error_category"),
            },
            reviewed_final_report=True,
            review_iteration=state.review_iteration,
            state_version=state.state_version,
        )
        self.record(
            state,
            started,
            "结构化状态、草稿报告、图表标记、事实边界与独立模型复核",
            "REVIEW PASSED"
            if state.review["approved"]
            else f"REVIEW FAILED：{state.review.get('failure_reason', '语义矛盾')}",
            None,
            ["semantic_review", "llm_report_review", "report_policy_check"],
        )


AGENT_CHAIN: tuple[ChainAgent, ...] = (
    PlanningAgent(),
    EvidenceAgent(),
    MemoryAgent(),
    RiskAgent(),
    StructuredStateReviewAgent(),
    ReportAgent(),
    ReviewAgent(),
)

CHAIN_START_INDEX = {
    "normalization": 0,
    "business_context": 1,
    "security_classification": 1,
    "scene_classification": 1,
    "workflow_router": 1,
    "workflow_evidence": 1,
    "risk": 3,
    "report": 5,
}

MAX_REVIEW_ITERATIONS = 3


def _llm_context(state: AgentState) -> dict[str, Any]:
    return {
        "alert": state.alert,
        "requirement": state.requirement,
        "business_context": state.business_context,
        "evidence_store": {
            key: value for key, value in state.evidence_store.items() if key != "by_id"
        },
        "rule_router_candidate": state.router,
        "workflow": state.workflow_result,
        "rule_event_assessment": state.event_assessment,
        "rule_risk_metrics": state.risk,
        "evidence": state.evidence,
        "iocs": state.iocs,
        "entities": state.entities,
        "timeline": state.timeline,
        "consistency": state.consistency,
        "citations": state.citations,
        "memory_insights": state.memory_insights,
        "llm_assessment": state.llm_assessment,
        "improvement_plan": state.improvement_plan,
        "charts": state.charts,
        "previous_review": (
            state.revision_feedback.get("review", state.review)
            if state.review_iteration
            else {}
        ),
        "review_feedback": state.revision_feedback if state.review_iteration else {},
        "structured_state_review": state.structured_review,
        "state_version": state.state_version,
        "generated_from_state_version": state.generated_from_state_version,
    }


def _agent_runnable(agent: ChainAgent) -> RunnableLambda:
    async def run(state: AgentState) -> AgentState:
        await agent.run(state)
        return state

    return RunnableLambda(run, name=agent.agent_id)


async def _run_chain(state: AgentState, start_index: int = 0) -> None:
    # Keep each node a LangChain Runnable, while allowing the structured-state
    # gate to stop before report generation when an upstream contract is bad.
    for agent in AGENT_CHAIN[start_index:]:
        await _agent_runnable(agent).ainvoke(
            state, config={"run_name": "security_analysis_lcel"}
        )
        if (
            agent.agent_id == "structured_state_review"
            and not state.structured_review.get("approved", False)
        ):
            break


def chain_definition() -> list[dict[str, str]]:
    # Preserve the public legacy chain shape; the structured review gate is
    # exposed in execution_events/debug_trace and runs between risk and report.
    return [
        {"id": agent.agent_id, "label": agent.label, "role": agent.role}
        for agent in AGENT_CHAIN
        if agent.agent_id != "structured_state_review"
    ]


def _prepare_rollback(state: AgentState, target: str) -> None:
    """Invalidate downstream artifacts before rerunning the owning layer."""
    state.revision_feedback = {
        "failure_reason": state.review.get("failure_reason", "复核未通过"),
        "review": state.review,
        "failure_rules": state.review.get("failure_rules", []),
        "failure_details": state.review.get("failure_details", []),
        "error_category": state.review.get("error_category", "UNKNOWN_ERROR"),
        "rollback_target": target,
        "revision_action": state.review.get("revision_action", "重新执行对应上游节点。"),
    }
    state.state_version += 1
    state.report = ""
    state.generated_from_state_version = None
    state.review = {}
    if target != "report":
        state.structured_review = {}
    if target == "normalization":
        state.alert = {}
        state.query = ""
        state.normalized_event = {}
    if target in {"normalization", "business_context", "security_classification", "scene_classification", "workflow_router", "workflow_evidence"}:
        state.business_context = {}
        state.evidence_store = {}
        state.security_result = {}
        state.router = {}
        state.workflow_result = {}
        state.scene_result = {}
        state.event_assessment = {}
        state.iocs = {}
        state.entities = {}
        state.timeline = {}
    if target in {"normalization", "business_context", "security_classification", "scene_classification", "workflow_router", "workflow_evidence", "risk"}:
        state.risk = {}
        state.evidence = {}
        state.consistency = {}
        state.citations = []
        state.knowledge_query = ""
        state.improvement_plan = {}
        state.charts = []
        state.llm_assessment = {}
    _refresh_fingerprints(state)


async def analyze(
    raw_alert: dict[str, Any] | str,
    requirement: str,
    use_model: bool = True,
    memory_id: str = "",
) -> dict[str, Any]:
    require_model()
    if not use_model:
        raise ValueError("研判必须经过 LangChain LLM 推理链，不支持关闭大模型。")
    active_memory_id = memory_id or memory_store.create_input(raw_alert, requirement)
    state = AgentState(active_memory_id, raw_alert, requirement, use_model)
    try:
        await _run_chain(state)
        _refresh_fingerprints(state)
        state.review_history.append(
            {
                "review_iteration": state.review_iteration,
                "state_version": state.state_version,
                "state_fingerprint": state.state_fingerprint,
                "report_fingerprint": state.report_fingerprint,
                "failure_reason": state.review.get("failure_reason", ""),
                "failure_rules": state.review.get("failure_rules", []),
                "error_category": state.review.get("error_category"),
                "rollback_target": state.review.get("rollback_target"),
                "retry_result": "initial_pass"
                if state.review.get("approved")
                else "initial_fail",
            }
        )
        while (
            not state.review.get("approved", False)
            and state.review_iteration < MAX_REVIEW_ITERATIONS - 1
            and state.review.get("rollback_target") in CHAIN_START_INDEX
        ):
            target = str(state.review["rollback_target"])
            logger.info(
                "[Router] review -> %s; revision_iteration=%d/%d",
                target,
                state.review_iteration + 1,
                MAX_REVIEW_ITERATIONS,
            )
            previous_reason = str(state.review.get("failure_reason", "语义复核失败"))
            previous_state_fingerprint = state.state_fingerprint
            previous_report_fingerprint = state.report_fingerprint
            previous_review = dict(state.review)
            state.review_iteration += 1
            _prepare_rollback(state, target)
            history = {
                "review_iteration": state.review_iteration,
                "state_version": state.state_version,
                "failure_reason": previous_reason,
                "failure_rules": previous_review.get("failure_rules", []),
                "error_category": previous_review.get("error_category"),
                "rollback_target": target,
                "revision_action": previous_review.get("revision_action", ""),
                "previous_state_fingerprint": previous_state_fingerprint,
                "previous_report_fingerprint": previous_report_fingerprint,
                "retry_result": "started",
            }
            state.review_history.append(history)
            _record_stage(
                state,
                "review_rollback",
                "started",
                {
                    "review_iteration": state.review_iteration,
                    "failure_reason": previous_reason,
                    "rollback_target": target,
                },
            )
            await _run_chain(state, CHAIN_START_INDEX[target])
            _refresh_fingerprints(state)
            no_state_progress = state.state_fingerprint == previous_state_fingerprint
            no_report_progress = state.report_fingerprint == previous_report_fingerprint
            if (
                not state.review.get("approved", False)
                and ((target != "report" and no_state_progress) or (
                target == "report" and no_state_progress and no_report_progress
                ))
                and state.review_iteration >= state.max_review_retries
            ):
                loop_failure = build_review_failure(
                    "review_repair_loop",
                    "相同 State/报告哈希在回滚重试后未发生变化，检测到复核修复循环。",
                    target,
                )
                state.review = {
                    **state.review,
                    "approved": False,
                    "status": "FAIL",
                    "error_code": "REVIEW_REPAIR_LOOP_DETECTED",
                    "failures": list(state.review.get("failures", [])) + [loop_failure],
                    "failure_rules": list(state.review.get("failure_rules", []))
                    + [loop_failure["rule_id"]],
                    "error_category": "UNKNOWN_ERROR",
                    "failure_type": "UNKNOWN_ERROR",
                    "error_scope": "analysis" if target != "report" else "report",
                    "error_categories": list(
                        dict.fromkeys(
                            list(state.review.get("error_categories", []))
                            + ["UNKNOWN_ERROR"]
                        )
                    ),
                    "failure_reason": (
                        state.review.get("failure_reason", "")
                        + "; "
                        + loop_failure["reason"]
                    ).strip("; "),
                    "rollback_target": target,
                    "revision_action": loop_failure["revision_action"],
                    "state_fingerprint": state.state_fingerprint,
                    "report_fingerprint": state.report_fingerprint,
                }
                history["loop_detected"] = True
            history["retry_result"] = (
                "passed" if state.review.get("approved") else "failed"
            )
            history["retry_failure_reason"] = state.review.get("failure_reason", "")
            history["state_fingerprint"] = state.state_fingerprint
            history["report_fingerprint"] = state.report_fingerprint
            history["retry_failure_rules"] = state.review.get("failure_rules", [])
            _record_stage(
                state,
                "review_rollback",
                "completed",
                {
                    "review_iteration": state.review_iteration,
                    "failure_reason": history["retry_failure_reason"],
                    "rollback_target": target,
                    "retry_result": history["retry_result"],
                    "loop_detected": history.get("loop_detected", False),
                    "state_fingerprint": state.state_fingerprint,
                    "report_fingerprint": state.report_fingerprint,
                },
                state_version=state.state_version,
            )
            if history.get("loop_detected"):
                break
        state.review["review_iterations"] = state.review_history
        state.review["max_review_retries"] = state.max_review_retries
        state.review["max_review_iterations"] = MAX_REVIEW_ITERATIONS
        review_passed = bool(state.review.get("approved"))
        required_stages = {"evidence_reasoning", "report_generation", "report_review"}
        if review_passed and not required_stages <= {
            call["stage"] for call in state.model_calls if call["success"]
        }:
            raise ModelExecutionError(
                "pipeline",
                "INCOMPLETE_LLM_CHAIN",
                "LLM 推理链不完整，已拒绝结果。",
                {
                    "review": state.review,
                "review_history": state.review_history,
                "state_version": state.state_version,
            },
        )
        state.review["review_status"] = "passed" if review_passed else "failed"
        state.review["run_status"] = "completed"
        state.review["report_available"] = bool(state.report.strip())
        state.usage = {}
        for call in state.model_calls:
            for key, value in call.get("usage", {}).items():
                if isinstance(value, (int, float)):
                    state.usage[key] = state.usage.get(key, 0) + value
        assessment = state.llm_assessment or {}
        risk = state.risk or {}
        evidence = state.evidence or {}
        iocs = state.iocs or {}
        confidence = int(assessment.get("confidence", risk.get("confidence_score", 0)) or 0)
        finding = str(
            assessment.get("conclusion")
            or state.review.get("failure_reason")
            or "复核未通过，当前未形成可交付报告草稿。"
        )
        analysis_id = f"AGENT-{uuid4().hex[:10].upper()}"
        summary = {
            "title": str(state.alert.get("name") or "未知安全告警"),
            "risk_score": risk.get("score", 0),
            "risk_level": risk.get("level", "未知"),
            "confidence_score": confidence,
            "confidence_level": "高"
            if confidence >= 75
            else "中"
            if confidence >= 45
            else "低",
            "primary_scenario": assessment.get("primary_scenario", "待确认"),
            "risk_source": "deterministic_tool",
            "context_id": state.business_context.get("context_id", "unknown"),
            "security_problem_id": state.router.get("selected_scene_id", "unknown"),
            "primary_workflow": state.router.get(
                "primary_workflow", "generic_workflow"
            ),
            "risk_profile_id": state.router.get("risk_profile_id", "GENERIC_RISK"),
            "classification_confidence": state.event_assessment.get(
                "classification_confidence", "低"
            ),
            "evidence_coverage": evidence.get("coverage", 0),
            "ioc_count": iocs.get("total", 0),
            "key_finding": finding,
            "run_status": "completed",
            "review_status": "passed" if review_passed else "failed",
        }
        memory_store.record_result(
            active_memory_id,
            analysis_id,
            summary,
            {
                "llm_assessment": state.llm_assessment,
                "report": state.report,
                "review": state.review,
            },
        )
        successful_calls = [call for call in state.model_calls if call.get("success")]
        provider = (
            successful_calls[-1].get("model_provider", "")
            if successful_calls
            else ""
        )
        result = {
            "analysis_id": analysis_id,
            "memory_id": active_memory_id,
            "state_version": state.state_version,
            "generated_at": datetime.now(tz=UTC).isoformat(),
            "engine": state.engine,
            "provider": provider,
            "framework": "langchain",
            "run_status": "completed",
            "review_status": "passed" if review_passed else "failed",
            "report_available": bool(state.report.strip()),
            "model_calls": state.model_calls,
            "llm_assessment": state.llm_assessment,
            "summary": summary,
            "report_markdown": state.report,
            "charts": state.charts,
            "reasoning_trace": state.reasoning_trace,
            "agent_chain": [
                item
                for item in state.chain_trace
                if item.get("agent_id") != "structured_state_review"
            ],
            "review_nodes": [
                item
                for item in state.chain_trace
                if item.get("agent_id") == "structured_state_review"
            ],
            "memory_insights": state.memory_insights,
            "review": state.review,
            "business_context": state.business_context,
            "security_problem_candidates": state.security_result.get("candidates", []),
            "router": state.router,
            "workflow": state.workflow_result,
            "evidence_store": {
                key: value
                for key, value in state.evidence_store.items()
                if key != "by_id"
            },
            "citations": state.citations,
            "usage": state.usage,
            "database_used": False,
        }
        if os.getenv("ANALYSIS_DEBUG", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            result["debug_trace"] = _analysis_trace(state)
        return result
    except Exception as error:
        error_type = getattr(error, "error_type", type(error).__name__)
        message = str(redact(getattr(error, "message", str(error))))[:500]
        error_code = getattr(error, "code", "PIPELINE_FAILED")
        failed_tool = getattr(error, "tool", None)
        tool_stage = {
            "normalize_alert": "normalization",
            "infer_business_context": "business_context",
            "build_evidence_store": "security_classification",
            "classify_security_problems": "security_classification",
            "route_workflow": "workflow_router",
            "build_workflow_evidence": "workflow_router",
            "generate_scene_candidates": "scene_classification",
            "select_primary_scene": "scene_classification",
            "assess_event_layers": "scene_classification",
            "evidence_matrix": "risk",
            "calculate_risk": "risk",
            "search_knowledge": "risk",
            "detect_contradictions": "risk",
            "build_improvement_plan": "report",
            "build_report_charts": "report",
        }
        failed_stage = getattr(error, "stage", None) or tool_stage.get(
            str(failed_tool), "analysis_pipeline"
        )
        failed_agent = {
            "normalization": "planner",
            "business_context": "evidence",
            "security_classification": "evidence",
            "scene_classification": "evidence",
            "workflow_router": "evidence",
            "risk": "risk",
            "report": "report",
        }.get(failed_stage, "pipeline")
        state.fallbacks.append(
            {
                "stage": failed_stage,
                "agent": failed_agent,
                "tool": failed_tool,
                "reason": "pipeline_error",
                "error_type": error_type,
                "error_code": error_code,
                "message": message,
                "fallback_used": False,
            }
        )
        _record_stage(
            state,
            "tool_failure"
            if isinstance(error, ToolExecutionError)
            else "analysis_failure",
            "failed",
            {
                "agent": failed_agent,
                "tool": failed_tool,
                "error_type": error_type,
                "error_code": error_code,
                "message": message,
                "fallback_used": False,
            },
        )
        logger.exception(
            "analysis pipeline failed at agent=%s stage=%s tool=%s",
            failed_agent,
            failed_stage,
            failed_tool or "unknown",
        )
        if isinstance(error, ModelExecutionError) and not error.diagnostic:
            error.diagnostic = {
                "error_code": error_code,
                "error_stage": failed_stage,
                "error_type": error_type,
                "state_version": state.state_version,
                "state_fingerprint": state.state_fingerprint,
                "report_fingerprint": state.report_fingerprint,
                "model_calls": state.model_calls,
                "review": state.review,
                "review_history": state.review_history,
            }
        memory_store.record_failure(
            active_memory_id,
            f"stage={failed_stage} code={error_code} error_type={error_type} message={message}",
            {
                "error_code": error_code,
                "error_stage": failed_stage,
                "error_type": error_type,
                "review": state.review,
                "structured_state_review": state.structured_review,
                "review_history": state.review_history,
                "state_version": state.state_version,
                "state_fingerprint": state.state_fingerprint,
                "report_fingerprint": state.report_fingerprint,
                "fallbacks": state.fallbacks,
                "execution_events": state.analysis_trace_events,
            },
        )
        raise
