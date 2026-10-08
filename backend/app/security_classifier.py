"""Open-world security-problem classification over current-event evidence.

This classifier is deliberately separate from business context.  It never
promotes a rule title, a nested log, or a historical reference into the main
event scene.  Candidate support is always a list of Evidence Store IDs.
"""

from __future__ import annotations

from typing import Any

SCENE_NAMES = {
    "weak_credential": "弱凭据",
    "brute_force": "暴力破解/高频认证失败",
    "credential_stuffing": "凭据填充",
    "unauthorized_access": "未授权访问",
    "privilege_escalation": "权限提升",
    "sensitive_data_exposure": "疑似敏感信息泄露或访问控制缺陷",
    "plaintext_credential": "疑似敏感信息泄露或访问控制缺陷",
    "sql_injection": "疑似 SQL 注入或数据库查询操纵",
    "command_injection": "疑似命令执行或危险解释器调用",
    "rce": "疑似命令执行或危险解释器调用",
    "xss": "疑似跨站脚本或不安全内容渲染",
    "ssrf": "服务端请求伪造",
    "path_traversal": "路径穿越",
    "arbitrary_file_read": "任意文件读取",
    "file_upload_abuse": "文件上传滥用",
    "webshell": "WebShell",
    "malware": "恶意软件/样本",
    "scan": "扫描/探测",
    "lateral_movement": "横向移动",
    "persistence": "持久化",
    "data_exfiltration": "数据外传",
    "misconfiguration": "安全配置错误",
    "suspicious_behavior": "可疑行为",
    "normal_behavior": "正常业务行为",
    "unknown": "安全问题待确认",
}


def _text(store: dict[str, Any], current_only: bool = True) -> str:
    values = []
    for item in store.get("items", []):
        provenance = item.get("provenance", {})
        if current_only and not (
            item.get("applicable")
            and provenance.get("describes_current_event")
            and provenance.get("event_layer") == 0
        ):
            continue
        values.append(str(item.get("semantic_value", "")))
        values.append(str(item.get("raw_value", "")))
    return " ".join(values).lower()


def _items(store: dict[str, Any], types: tuple[str, ...]) -> list[dict[str, Any]]:
    return [
        item
        for item in store.get("items", [])
        if item.get("semantic_type") in types
        and item.get("applicable")
        and item.get("provenance", {}).get("describes_current_event")
        and item.get("provenance", {}).get("event_layer") == 0
    ]


def _support(items: list[dict[str, Any]], reason: str) -> list[dict[str, str]]:
    return [
        {"evidence_id": str(item["evidence_id"]), "reason": reason}
        for item in items[:8]
    ]


def _candidate(
    scene_id: str,
    support: list[dict[str, str]],
    missing: list[str],
    confidence: float,
    business_fit: float,
    contradictions: list[str] | None = None,
) -> dict[str, Any]:
    contradictions = contradictions or []
    confidence = max(0.0, min(1.0, confidence))
    return {
        "scene_id": scene_id,
        "scene": SCENE_NAMES.get(scene_id, scene_id),
        "name": SCENE_NAMES.get(scene_id, scene_id),
        "support": support,
        "contradictions": contradictions[:8],
        "contrary": contradictions[:8],
        "missing": missing[:10],
        "business_fit": round(max(0.0, min(1.0, business_fit)), 3),
        "evidence_strength": round(min(1.0, len(support) / 4), 3),
        "score": round(confidence, 3),
        "confidence_score": round(confidence, 3),
        "confidence": "高" if confidence >= 0.78 else "中" if confidence >= 0.5 else "低",
        "open_world": scene_id in {"unknown", "suspicious_behavior"},
        "evidence_template": [
            "当前事件直接证据",
            "业务主体与授权结果",
            "服务端处理/执行结果",
            "关联日志或受控复测",
        ],
    }


def classify_security_problems(
    normalized_event: dict[str, Any],
    business_context: dict[str, Any],
    evidence_store: dict[str, Any],
    alert: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return open-world candidates with Evidence Store references."""
    del normalized_event
    alert = alert if isinstance(alert, dict) else {}
    context_id = str(business_context.get("context_id") or business_context.get("action") or "unknown")
    current_text = _text(evidence_store)
    request_items = _items(evidence_store, ("current_request_signal", "request_target"))
    response_items = _items(evidence_store, ("current_response_field", "business_result"))
    auth_items = _items(evidence_store, ("authentication_observation",))
    execution_items = _items(evidence_store, ("execution_observation",))
    file_items = _items(evidence_store, ("file_metadata", "file_upload_observation"))
    candidates: list[dict[str, Any]] = []

    def add_signal(scene_id: str, needles: tuple[str, ...], missing: list[str], fit: float, base: float) -> None:
        matched = [item for item in request_items if any(needle in str(item.get("raw_value", "")).lower() for needle in needles)]
        if matched:
            candidates.append(_candidate(scene_id, _support(matched, "当前请求/目标包含该安全语义"), missing, base + min(0.15, len(matched) * 0.04), fit))

    if context_id in {"authentication", "logout", "password_change"}:
        auth_support = _support(auth_items, "当前请求观察到认证上下文")
        success = business_context.get("business_result", {}).get("success")
        if business_context.get("normal_behavior_assessment") == "normal_business_consistent":
            candidates.append(_candidate("normal_behavior", auth_support, ["认证日志与后续访问关联"], 0.86, 0.95))
            candidates.append(_candidate("normal_behavior", [], ["若判断异常，需失败序列、来源和账号上下文"], 0.32, 0.72, ["当前业务语义与正常认证流程一致"]))
        elif success is False:
            text = str(alert).lower()
            scene_id = "credential_stuffing" if "stuff" in text or "凭据填充" in text else "brute_force" if any(word in text for word in ("brute", "spray", "爆破", "高频")) else "weak_credential"
            candidates.append(_candidate(scene_id, auth_support, ["失败序列、来源分布、账号主体、MFA 与速率"], 0.61, 0.88))
        else:
            candidates.append(_candidate("suspicious_behavior", auth_support, ["认证结果、主体、MFA、后续访问"], 0.43, 0.76))

    sensitive = [
        item
        for item in response_items
        if any(
            word in str(item.get("semantic_value", "")).lower()
            for word in ("password", "secret", "credential", "apikey", "private")
        )
    ]
    if sensitive and not (context_id == "authentication" and business_context.get("normal_behavior_assessment") == "normal_business_consistent"):
        candidates.append(_candidate("plaintext_credential", _support(sensitive, "当前响应出现敏感凭据字段键"), ["调用主体、对象归属、授权决策、数据审计"], 0.82, 0.9))
        candidates.append(_candidate("sensitive_data_exposure", _support(sensitive, "当前响应出现敏感数据字段键"), ["授权结果、返回范围、外传审计"], 0.78, 0.86))

    add_signal("sql_injection", ("union select", "sql injection", "sql 注入", "sql syntax"), ["数据库审计、应用错误、参数化查询验证"], 0.88, 0.67)
    add_signal("path_traversal", ("../", "..\\", "path traversal", "路径穿越"), ["文件访问结果、规范化路径、受控复测"], 0.86, 0.67)
    add_signal("command_injection", ("cmd.exe", "powershell", "bash -c", "command injection", "命令注入"), ["解释器调用、子进程、执行结果"], 0.75, 0.62)
    add_signal("rce", ("rce", "remote code execution", "远程代码执行"), ["进程树、系统调用、执行结果"], 0.64, 0.6)
    add_signal("xss", ("<script", "javascript:", "onerror=", "xss", "跨站"), ["反射/持久化位置、浏览器执行、CSP"], 0.79, 0.72)
    add_signal("ssrf", ("ssrf", "server-side request", "服务端请求伪造"), ["服务端出站连接、目标响应、网络日志"], 0.71, 0.65)
    add_signal("unauthorized_access", ("unauthorized", "未授权", "auth bypass", "bypass", "越权"), ["调用主体、资源归属、服务端权限决策"], 0.78, 0.68)
    add_signal("privilege_escalation", ("privilege escalation", "权限提升", "提权", "role escalation", "sudo"), ["角色变更、权限策略、管理员审计"], 0.74, 0.62)
    add_signal("data_exfiltration", ("exfil", "外传", "data export", "数据外传", "third party"), ["外传目标、出口流量、数据访问审计"], 0.7, 0.62)
    add_signal("persistence", ("persistence", "持久化", "startup", "scheduled task", "计划任务"), ["启动项/计划任务、主机变更和回滚记录"], 0.68, 0.58)
    add_signal("lateral_movement", ("lateral movement", "横向", "remote service", "远程服务"), ["同源资产序列、认证跳转和网络连接"], 0.65, 0.58)
    add_signal("misconfiguration", ("misconfiguration", "错误配置", "暴露配置", "公开存储桶", "public bucket"), ["配置基线、变更记录、资产暴露面"], 0.64, 0.6)
    if any(word in current_text for word in ("webshell", "web shell")):
        candidates.append(_candidate("webshell", _support(request_items, "当前请求包含 WebShell 语义"), ["落盘文件、Hash、执行进程、持久化"], 0.7, 0.82))
    if context_id == "file_download" and request_items:
        candidates.append(_candidate("arbitrary_file_read", _support(request_items, "当前文件下载/导出请求需要校验对象边界"), ["对象归属、路径规范化、授权决策和返回内容"], 0.52, 0.74))
    if context_id == "file_upload" and file_items:
        upload_support = _support(file_items, "当前事件存在文件上传或文件元数据")
        candidates.append(_candidate("file_upload_abuse", upload_support, ["落盘位置、类型校验、执行状态、EDR"], 0.7 if upload_support else 0.4, 0.92))
        if any(word in current_text for word in ("malware", "恶意", "webshell", "shell")):
            candidates.append(_candidate("malware", _support(file_items, "当前文件字段包含样本/恶意语义"), ["Hash、落盘、执行和传播证据"], 0.64, 0.9))
    if context_id in {"network_connection", "scanning"} or any(word in current_text for word in ("scanner", "port scan", "扫描", "探测")):
        candidates.append(_candidate("scan", _support(request_items, "当前事件包含扫描/探测语义"), ["授权窗口、目标范围、速率和访问结果"], 0.72, 0.9))
    if execution_items:
        candidates.append(_candidate("suspicious_behavior", _support(execution_items, "当前事件提供主机/执行观测"), ["完整进程链、执行成功结果和影响"], 0.7, 0.62))

    # No response sensitive field is allowed to turn a normal login token into
    # a leak.  Missing Authorization is also deliberately not an authz claim.
    if not candidates:
        candidates.append(_candidate("unknown", [], ["完整请求/响应、主体、授权决策、服务端日志和受控验证"], 0.28, 0.35))
    unique: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        existing = unique.get(candidate["scene_id"])
        if existing is None or candidate["score"] > existing["score"]:
            unique[candidate["scene_id"]] = candidate
    ordered = sorted(unique.values(), key=lambda item: (-item["score"], item["scene_id"]))[:8]
    return {
        "schema_version": "security-problem-classification-v1",
        "candidate_taxonomy": sorted(set(SCENE_NAMES) | {"OTHER"}),
        "candidates": ordered,
        "context_id": context_id,
        "open_world": True,
        "rule_metadata_used_as_fact": False,
        "direct_support_rule": "support[] 只能引用 Unified Evidence Store evidence_id；嵌入/历史证据不能直接支持主场景。",
    }


def select_security_problem(result: dict[str, Any]) -> dict[str, Any]:
    candidates = [item for item in result.get("candidates", []) if isinstance(item, dict)]
    if not candidates:
        return _candidate("unknown", [], ["补充当前事件证据"], 0.2, 0.2)
    selected = dict(candidates[0])
    selected["selected"] = True
    return selected
