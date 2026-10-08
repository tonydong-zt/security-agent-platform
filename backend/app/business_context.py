"""Business-semantic interpretation of a normalized alert.

The result describes what the application appears to be doing and what normal
behaviour would look like.  It intentionally does not decide that an attack is
successful; that is the job of scenario and evidence evaluation.
"""

from __future__ import annotations

from typing import Any

from .normalization import apply_field_applicability


def _contains(text: str, values: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(value.lower() in lowered for value in values)


def _keys(normalized: dict[str, Any], response: bool = False) -> list[str]:
    key_name = "response_body_parse_result" if response else "body_parse_result"
    return [str(item).lower() for item in normalized.get("http", {}).get(key_name, {}).get("keys", [])]


def _sensitive_response_keys(keys: list[str]) -> list[str]:
    tokens = ("password", "passwd", "secret", "credential", "private", "api_key", "apikey", "ssn")
    return [key for key in keys if any(token in key for token in tokens)
            and not any(part in key.split(".") for part in ("log", "logs", "history", "trace", "artifact"))]


def infer_business_context(
    normalized_event: dict[str, Any], alert: dict[str, Any] | None = None
) -> dict[str, Any]:
    http = normalized_event.get("http", {})
    method = str(http.get("method") or "").upper()
    path = str(http.get("path") or http.get("target") or "")
    behavior = str(normalized_event.get("behavior_text") or "").lower()
    request_keys = _keys(normalized_event)
    response_keys = _keys(normalized_event, response=True)
    response_sensitive_keys = _sensitive_response_keys(response_keys)
    body_status = normalized_event.get("business_result", {})
    # Response contents describe returned data, not the current request action.
    combined = f"{path} {' '.join(request_keys)} {behavior}".lower()

    request_semantics = f"{path} {http.get('target') or ''} {' '.join(request_keys)}".lower()
    if _contains(request_semantics, ("logout", "signout", "sign-out", "退出登录")):
        action = "logout"
        business_object = path or "authentication/logout"
        expected = "撤销或结束当前主体会话；服务端不应继续接受已注销的 Session/Token。"
    elif _contains(request_semantics, ("password/change", "password_change", "change-password", "reset-password", "修改密码", "重置密码")):
        action = "password_change"
        business_object = path or "authentication/password_change"
        expected = "仅允许已认证主体在满足旧凭据/MFA/策略后修改密码，并记录审计结果。"
    elif _contains(request_semantics, ("login", "signin", "sign-in", "logon", "authenticate", "authentication", "认证", "登录")) or (
        _contains(" ".join(request_keys), ("password", "passwd", "username", "credential", "凭据"))
        and method in {"POST", "PUT", "PATCH", ""}
    ):
        action = "authentication"
        business_object = path or "authentication/login"
        expected = (
            "提交身份凭据 → 服务端验证身份与策略 → 成功返回当前主体的 Session/Token；"
            "失败返回拒绝或错误，不应创建成功会话。"
        )
    elif method in {"POST", "PUT", "PATCH", ""} and _contains(
        request_semantics + " " + str(http.get("headers", {}).get("Content-Type", "")),
        ("upload", "multipart", "filename", "fileupload", "文件上传"),
    ):
        action = "file_upload"
        business_object = path or "file upload"
        expected = "接收受控文件 → 校验类型、大小与内容 → 隔离/存储并返回处理结果；不应直接执行上传内容。"
    elif _contains(request_semantics, ("download", "export", "下载", "导出")):
        action = "file_download"
        business_object = path or "file download"
        expected = "仅返回当前主体有权访问的文件或导出结果，并记录对象范围与下载审计。"
    elif _contains(request_semantics, ("log", "audit", "日志", "审计")):
        action = "log_access"
        business_object = path or "audit log"
        expected = "仅向有权限主体返回最小必要审计数据，不暴露凭据、令牌或其他租户日志。"
    elif _contains(combined, ("command", "exec", "shell", "powershell", "cmd.exe", "命令执行")):
        action = "command_execution"
        business_object = path or "command execution"
        expected = "业务接口只执行允许列表中的固定动作；外部输入不应生成任意命令、子进程或出站连接。"
    elif _contains(combined, ("config", "configuration", "settings", "配置")) and method in {"GET", ""}:
        action = "configuration_retrieval"
        business_object = path or "configuration"
        expected = "按调用主体的权限返回最小必要配置；敏感密钥、内部连接信息和凭据不应返回。"
    elif _contains(combined, ("query", "sql", "database", "mysql", "postgres", "数据库", "union select")):
        action = "database_query"
        business_object = path or "database query"
        expected = "服务端使用参数化查询和最小数据库权限返回业务所需结果；外部输入不应改变查询结构。"
    elif _contains(combined, ("<script", "javascript:", "onerror", "xss", "跨站")):
        action = "content_rendering"
        business_object = path or "web content rendering"
        expected = "用户内容按输出上下文正确编码并受 CSP 约束；浏览器不应执行未经信任的脚本。"
    elif _contains(combined, ("scan", "scanner", "probe", "port scan", "扫描", "探测")):
        action = "scanning"
        business_object = path or "service discovery"
        expected = "扫描活动应来自授权来源、处于批准窗口，并限制速率与目标范围。"
    elif method in {"GET", "POST", "PUT", "PATCH", "DELETE"} or path:
        action = "resource_access"
        business_object = path or "application resource"
        expected = "服务端根据认证主体、对象归属和功能权限返回最小必要资源或明确拒绝。"
    else:
        action = "unknown"
        business_object = "unknown"
        expected = "需要补充协议、接口、主体、业务结果和关联日志，才能建立正常业务预期。"

    apply_field_applicability(normalized_event, action, alert)
    auth = normalized_event.get("authorization", {})
    http_status = http.get("status_code")
    success = body_status.get("success")
    response_keys_lower = set(response_keys)
    token_returned = bool(response_keys_lower & {"token", "access_token", "accesstoken", "id_token", "session", "session_id"})
    leak_signal = _contains(
        behavior,
        ("token in url", "token leaked", "token leak", "third party", "external", "exfil", "泄露", "外传", "日志"),
    )

    direct_evidence: list[str] = []
    negative_evidence: list[str] = []
    if method:
        direct_evidence.append(f"normalized.http.method={method}")
    if path:
        direct_evidence.append(f"normalized.http.path={path}")
    if http_status is not None:
        direct_evidence.append(f"normalized.http.status_code={http_status}")
    if success is not None:
        direct_evidence.append(f"normalized.business_result.success={str(success).lower()}")
    if body_status.get("code") is not None:
        direct_evidence.append(f"normalized.business_result.code={body_status['code']}")
    if auth.get("present"):
        direct_evidence.append(
            f"normalized.authorization.present=true/state={auth.get('value_state')}"
        )
    else:
        negative_evidence.append("未观察到认证上下文；这不是未授权结论")
    if success is False:
        negative_evidence.append("业务结果明确失败，不视为业务成功")
    if http_status is not None and not (200 <= int(http_status) < 300):
        negative_evidence.append(f"HTTP 状态为 {http_status}，不是 2xx 成功状态")
    if auth.get("value_state") == "null_or_invalid":
        negative_evidence.append("Authorization 字段存在但值为 null/无效语义，认证有效性未确认")
    if normalized_event.get("field_applicability", {}).get("not_applicable_fields"):
        negative_evidence.append("存在与当前业务协议/场景不适用的字段，不作为反证")

    deviations: list[str] = []
    normal_assessment = "unknown"
    if action == "authentication" and success is True and token_returned and not leak_signal:
        normal_assessment = "normal_business_consistent"
        direct_evidence.append("登录成功后返回 Session/Token，符合认证业务预期")
    elif action == "authentication" and success is False:
        normal_assessment = "normal_failure_or_attack_requires_correlation"
        deviations.append("认证失败本身可能是正常输错，也可能是凭据攻击；需要失败序列、来源和账号上下文")
    elif action == "authentication" and token_returned and leak_signal:
        normal_assessment = "deviation_observed"
        deviations.append("检测到 Token/Session 可能进入 URL、日志、第三方或外传路径")
    elif response_sensitive_keys:
        normal_assessment = "deviation_or_authorization_gap_requires_verification"
        deviations.append("响应包含敏感字段，需要核对调用主体、资源归属和服务端授权决策")
    elif success is not None or http_status is not None:
        normal_assessment = "partially_observed"

    confidence = "高" if action != "unknown" and (path or method or success is not None) else "中" if action != "unknown" else "低"
    confidence_score = 0.90 if confidence == "高" else 0.62 if confidence == "中" else 0.25
    # Keep the previous action names as compatibility aliases while exposing
    # the open business-context taxonomy required by the routed pipeline.
    context_id = {
        "authentication": "authentication",
        "file_upload": "file_upload",
        "command_execution": "process_execution",
        "configuration_retrieval": "configuration_access",
        "database_query": "database_query",
        "content_rendering": "resource_read",
        "scanning": "network_connection",
        "resource_access": "resource_write" if method in {"POST", "PUT", "PATCH", "DELETE"} else "resource_read",
        "logout": "logout",
        "password_change": "password_change",
        "file_download": "file_download",
        "log_access": "log_access",
        "unknown": "unknown",
    }.get(action, "unknown")
    observed = (
        f"{action} 业务收到 {method or '未知方法'} {path or '未知入口'}；"
        f"HTTP={http_status if http_status is not None else '未知'}，"
        f"business_success={success if success is not None else '未知'}。"
    )
    if token_returned:
        observed += "响应出现 Session/Token 结构字段。"
    if response_sensitive_keys:
        observed += f"响应出现敏感字段键：{', '.join(response_sensitive_keys[:8])}。"

    return {
        "action": action,
        "business_action": action,
        "context_id": context_id,
        "business_object": business_object,
        "expected_normal_behavior": expected,
        "observed_behavior": observed,
        "deviation": deviations,
        "normal_behavior_assessment": normal_assessment,
        "confidence": confidence,
        "confidence_score": confidence_score,
        "confidence_evidence": [
            item for item in ("normalized.http.method", "normalized.http.path", "normalized.business_result")
            if (item == "normalized.http.method" and method)
            or (item == "normalized.http.path" and path)
            or (item == "normalized.business_result" and success is not None)
        ],
        "direct_evidence": direct_evidence[:20],
        "negative_evidence": negative_evidence[:20],
        "business_result": body_status,
        "authorization": {
            "present": bool(auth.get("present")),
            "state": auth.get("value_state", "not_observed"),
            "validity": auth.get("authentication_validity", "not_confirmed"),
        },
        "field_applicability": normalized_event.get("field_applicability", {}),
        "token_returned": token_returned,
        "token_leak_signal": leak_signal,
        "sensitive_response_fields": response_sensitive_keys,
        "source_fields": {
            "method": "normalized.http.method",
            "path": "normalized.http.path",
            "status": "normalized.http.status_code",
            "business_result": "normalized.business_result",
        },
    }
