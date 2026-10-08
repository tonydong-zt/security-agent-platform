"""Business-aware scene hypothesis generation and primary scene selection."""

from __future__ import annotations

import json
from typing import Any

SCENE_TEMPLATES: dict[str, list[str]] = {
    "credential_authentication": [
        "credential_present",
        "credential_strength",
        "auth_request",
        "auth_result",
        "session_or_token",
        "account_context",
        "post_auth_behavior",
    ],
    "data_exposure": [
        "sensitive_data_present",
        "requester_identity",
        "resource_ownership",
        "server_authorization_decision",
        "response_scope",
        "external_transfer",
        "business_impact",
    ],
    "injection": [
        "injection_payload",
        "input_sink",
        "server_processing",
        "database_or_command_result",
        "controlled_reproduction",
        "impact",
    ],
    "command_execution": [
        "command_semantics",
        "interpreter_or_process",
        "execution_result",
        "post_execution_behavior",
        "impact",
    ],
    "xss": [
        "script_payload",
        "reflection_or_persistence",
        "browser_execution",
        "session_impact",
        "controlled_reproduction",
    ],
    "malware_file": [
        "file_or_sample_identity",
        "delivery_or_storage",
        "execution_state",
        "host_behavior",
        "network_or_propagation",
    ],
    "scanning": [
        "scanner_or_source",
        "target_scope",
        "authorization_window",
        "rate_and_pattern",
        "resulting_access",
    ],
    "generic": [
        "request_or_event",
        "server_processing",
        "business_result",
        "identity_and_authorization",
        "impact",
    ],
}


def _contains(text: str, values: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(value.lower() in lowered for value in values)


def _behavior_text(normalized: dict[str, Any], alert_metadata: dict[str, Any] | None) -> str:
    text = str(normalized.get("behavior_text") or "")
    if not isinstance(alert_metadata, dict):
        return text.lower()
    rows: list[str] = []
    for key, value in alert_metadata.items():
        if str(key).lower() in {"name", "rulename", "alertname", "ruletitle", "threattype", "risklevel"}:
            continue
        rows.append(json.dumps({key: value}, ensure_ascii=False))
    return f"{text} {' '.join(rows)}".lower()


def _confidence(score: float) -> str:
    return "高" if score >= 0.78 else "中" if score >= 0.5 else "低"


def _make_candidate(
    scene_id: str,
    name: str,
    support: list[str],
    contradictions: list[str],
    missing: list[str],
    business_fit: float,
    evidence_strength: float,
) -> dict[str, Any]:
    support = list(dict.fromkeys(support))
    contradictions = list(dict.fromkeys(contradictions))
    missing = list(dict.fromkeys(missing))
    score = max(0.0, min(1.0, 0.65 * evidence_strength + 0.35 * business_fit - 0.08 * len(contradictions)))
    return {
        "scene_id": scene_id,
        "scene": name,
        "name": name,
        "support": support[:12],
        "contradictions": contradictions[:12],
        "contrary": contradictions[:12],
        "missing": missing[:12],
        "business_fit": round(business_fit, 3),
        "evidence_strength": round(evidence_strength, 3),
        "score": round(score, 3),
        "confidence": _confidence(score),
        "evidence_template": SCENE_TEMPLATES.get(scene_id, SCENE_TEMPLATES["generic"]),
    }


def generate_scene_candidates(
    normalized_event: dict[str, Any],
    business_context: dict[str, Any],
    direct_evidence: list[str] | None = None,
    negative_evidence: list[str] | None = None,
    alert_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate hypotheses from normalized facts and business semantics.

    Rule names and threat labels are intentionally accepted only as metadata;
    they are excluded from the text used for support signals.
    """
    behavior = _behavior_text(normalized_event, alert_metadata)
    action = str(business_context.get("action") or "unknown")
    direct = list(direct_evidence or business_context.get("direct_evidence", []))
    negative = list(negative_evidence or business_context.get("negative_evidence", []))
    response = normalized_event.get("http", {}).get("response_body_parse_result", {})
    response_keys = [str(item).lower() for item in response.get("keys", [])]
    sensitive_keys = list(business_context.get("sensitive_response_fields", []))
    success = normalized_event.get("business_result", {}).get("success")
    status = normalized_event.get("http", {}).get("status_code")
    candidates: list[dict[str, Any]] = []

    auth_signal = action == "authentication" or _contains(
        behavior, ("login failed", "password spray", "brute", "爆破", "登录失败", "凭据攻击")
    )
    if auth_signal:
        support = [item for item in direct if any(token in item for token in ("method", "path", "business_result", "authorization"))]
        if not support:
            support = ["business_context.action=authentication"]
        contradictions: list[str] = []
        if action != "authentication":
            contradictions.append("认证信号不是当前业务动作的主语义")
        missing = ["认证日志/失败成功序列", "账号主体与 MFA/Session 记录", "后续访问行为"]
        if success is True and business_context.get("normal_behavior_assessment") == "normal_business_consistent":
            missing.append("无需将正常 Token 返回直接解释为泄露；仅在出现异常接收方/外传证据时升级")
        candidates.append(
            _make_candidate(
                "credential_authentication",
                "身份认证/登录业务" if success is True and not business_context.get("deviation") else "疑似身份认证异常或凭据攻击",
                support,
                contradictions,
                missing,
                1.0 if action == "authentication" else 0.5,
                min(1.0, 0.45 + 0.12 * len(support) + (0.15 if success is not None else 0)),
            )
        )

    injection_signal = _contains(
        behavior, ("union select", "sql injection", "sql 注入", "sql syntax", "select ", "${", "../")
    )
    if injection_signal:
        support = ["normalized.request_or_event contains SQL/path-manipulation semantics"]
        if "union select" in behavior or "sql" in behavior:
            support.append("payload/query contains database query manipulation signal")
        contradictions = []
        if action == "authentication":
            contradictions.append("当前业务上下文是身份认证；SQL 字符串可能只是认证参数中的异常输入，尚需验证真实查询执行")
        candidates.append(
            _make_candidate(
                "injection",
                "疑似 SQL 注入或数据库查询操纵",
                support,
                contradictions,
                ["输入是否进入查询/解释器", "数据库审计或应用错误日志", "受控复测结果"],
                0.55 if action == "authentication" else 0.9 if action == "database_query" else 0.75,
                0.55 + (0.2 if status is not None else 0),
            )
        )

    command_signal = _contains(behavior, ("command", "cmd.exe", "powershell", "bash -c", "命令执行", "rce", "shell", "whoami"))
    if command_signal:
        candidates.append(
            _make_candidate(
                "command_execution",
                "疑似命令执行或危险解释器调用",
                ["normalized event contains command/interpreter semantics"],
                ["只有请求载荷，没有子进程/执行结果证据"] if not normalized_event.get("business_result", {}).get("success") else [],
                ["进程树/子进程", "EDR 或系统调用日志", "异常出站连接"],
                0.9 if action == "command_execution" else 0.65,
                0.6 + (0.15 if status is not None else 0),
            )
        )

    xss_signal = _contains(behavior, ("<script", "javascript:", "onerror=", "xss", "跨站"))
    if xss_signal:
        candidates.append(
            _make_candidate(
                "xss",
                "疑似跨站脚本或不安全内容渲染",
                ["normalized event contains script-rendering semantics"],
                [],
                ["反射/持久化位置", "浏览器执行或 CSP 报告", "受控回放"],
                0.9 if action == "content_rendering" else 0.7,
                0.62,
            )
        )

    file_signal = _contains(behavior, ("filename", "file", "sample", "malware", "sha256", "恶意文件"))
    if file_signal and action in {"file_upload", "unknown"}:
        candidates.append(
            _make_candidate(
                "malware_file",
                "疑似恶意文件或主机异常行为",
                ["normalized event contains file/sample semantics"],
                [],
                ["文件落盘与来源", "执行状态/进程树", "EDR 与主机网络日志"],
                0.9 if action == "file_upload" else 0.6,
                0.55,
            )
        )

    if action == "scanning" or _contains(behavior, ("port scan", "scanner", "scanner", "扫描", "探测")):
        candidates.append(
            _make_candidate(
                "scanning",
                "疑似扫描或服务探测",
                ["business_context.action=scanning"],
                [],
                ["授权扫描窗口", "目标范围", "扫描来源与速率"],
                0.95 if action == "scanning" else 0.65,
                0.58,
            )
        )

    exposure_signal = bool(sensitive_keys)
    token_only_normal = (
        action == "authentication"
        and business_context.get("normal_behavior_assessment") == "normal_business_consistent"
        and business_context.get("token_leak_signal") is False
        and set(response_keys) <= {"token", "access_token", "accesstoken", "id_token", "session", "session_id", "expires_in", "meta", "message", "code", "status_code", "success"}
    )
    if exposure_signal and not token_only_normal or business_context.get("token_leak_signal"):
        support = [f"normalized.response_body contains sensitive field key: {item}" for item in sensitive_keys]
        if business_context.get("token_leak_signal"):
            support.append("observed token/session leak or external-transfer signal")
        contradictions = []
        if action == "authentication" and not business_context.get("deviation"):
            contradictions.append("认证成功返回 Session/Token 可能符合正常业务，缺少异常接收方或外传证据")
        candidates.append(
            _make_candidate(
                "data_exposure",
                "疑似敏感信息泄露或访问控制缺陷",
                support,
                contradictions,
                ["请求主体与资源归属", "服务端权限决策", "数据访问/外传审计"],
                0.85 if action in {"resource_access", "configuration_retrieval"} else 0.45 if action == "authentication" else 0.7,
                min(1.0, 0.58 + 0.1 * len(support)),
            )
        )

    if not candidates:
        candidates.append(
            _make_candidate(
                "generic",
                "主要场景待确认",
                direct[:4] or ["当前事件存在可分析字段，但没有具体攻击语义"],
                [],
                ["完整请求/响应", "业务主体与授权上下文", "关联日志和受控验证"],
                0.7 if action != "unknown" else 0.35,
                0.32 if direct else 0.2,
            )
        )
    candidates.sort(key=lambda item: (-item["score"], -item["evidence_strength"], item["scene_id"]))
    return {
        "candidates": candidates[:5],
        "inputs": {
            "normalized_event": True,
            "business_context_action": action,
            "direct_evidence_count": len(direct),
            "negative_evidence_count": len(negative),
            "alert_metadata_used_as_fact": False,
        },
    }


def select_primary_scene(scene_result: dict[str, Any]) -> dict[str, Any]:
    candidates = [item for item in scene_result.get("candidates", []) if isinstance(item, dict)]
    if not candidates:
        return _make_candidate(
            "generic", "主要场景待确认", [], [], ["补充业务与证据"], 0.0, 0.0
        )
    selected = dict(candidates[0])
    selected["selected"] = True
    return selected
