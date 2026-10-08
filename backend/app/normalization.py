"""Deterministic alert normalization used by the real analysis pipeline.

This module deliberately returns engineering facts, not a security verdict.  It
is safe to expose in a debug trace because secret-bearing headers and bodies are
represented by metadata (presence, scheme, keys and parse status), never values.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

HTTP_REQUEST_LINE = re.compile(
    r"^(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/(?P<version>\d(?:\.\d)?)$",
    re.IGNORECASE,
)
HTTP_STATUS_LINE = re.compile(r"HTTP/\d(?:\.\d)?\s+(\d{3})", re.IGNORECASE)
IP_PATTERN = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
BEARER_PATTERN = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_-]*)\s*(?:\s+(.*))?$")
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
}
SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "authorization",
    "credential",
    "privatekey",
    "apikey",
)
RULE_METADATA_KEYS = {
    "name",
    "rulename",
    "alertname",
    "ruletitle",
    "threattype",
    "risklevel",
}


def _as_dict(raw: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise TypeError("告警顶层必须是 JSON 对象")
    return parsed


def _safe_text(value: Any, limit: int = 240) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = re.sub(r"(?i)(bearer\s+)[^\s,;]+", r"\1[令牌已隐藏]", text)
    text = re.sub(r"(?i)(password|passwd|secret|token|apikey)\s*[:=]\s*[^,;\s}]+", r"\1=[值已隐藏]", text)
    return text.replace("\n", " ")[:limit]


def _flatten(value: Any, path: str = "alert") -> list[tuple[str, Any]]:
    if isinstance(value, dict):
        return [item for key, child in value.items() for item in _flatten(child, f"{path}.{key}")]
    if isinstance(value, list):
        return [item for index, child in enumerate(value) for item in _flatten(child, f"{path}[{index}]")]
    return [(path, value)]


def _key(path: str) -> str:
    return re.sub(r"\[\d+\]", "", path.rsplit(".", 1)[-1]).lower()


def _first(alert: dict[str, Any], names: tuple[str, ...]) -> tuple[Any, str | None]:
    lowered = {str(key).lower(): key for key in alert}
    for name in names:
        key = lowered.get(name.lower())
        if key is not None and alert[key] not in (None, "", [], {}):
            return alert[key], str(key)
    return None, None


def _parse_json_value(value: Any) -> tuple[Any | None, dict[str, Any]]:
    if value in (None, "", [], {}):
        return None, {"status": "missing", "type": "none", "keys": []}
    candidate = value
    if isinstance(value, str):
        try:
            candidate = json.loads(value)
        except json.JSONDecodeError:
            return None, {
                "status": "not_json",
                "type": "string",
                "keys": [],
                "preview": _safe_text(value, 160),
            }
    if isinstance(candidate, dict):
        # Retain nested field paths, not values. Embedded logs remain contextual.
        keys = list(dict.fromkeys(
            [str(key) for key in candidate]
            + [path.removeprefix("body.") for path, _ in _flatten(candidate, "body")]
        ))[:160]
        return candidate, {"status": "parsed", "type": "object", "keys": keys}
    if isinstance(candidate, list):
        return candidate, {"status": "parsed", "type": "array", "keys": []}
    return candidate, {"status": "parsed", "type": type(candidate).__name__, "keys": []}


def _headers(value: Any) -> tuple[dict[str, str], dict[str, Any]]:
    if value in (None, "", [], {}):
        return {}, {}
    if isinstance(value, dict):
        # Keep the internal value for semantic parsing; the public normalized
        # record applies _safe_headers before it is returned in any trace.
        return {str(key): str(item) for key, item in value.items()}, {}
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            return _headers(parsed)
        rows = value.replace("\r\n", "\n").split("\n")
        metadata: dict[str, Any] = {}
        result: dict[str, str] = {}
        for index, row in enumerate(rows):
            if index == 0:
                match = HTTP_REQUEST_LINE.match(row.strip())
                if match:
                    metadata["request_line"] = {
                        "method": match.group("method").upper(),
                        "target": match.group("target"),
                        "version": match.group("version"),
                    }
                    continue
                status = HTTP_STATUS_LINE.search(row)
                if status:
                    metadata["status_code"] = int(status.group(1))
                    continue
            if ":" not in row:
                continue
            name, item = row.split(":", 1)
            if name.strip():
                result[name.strip()] = item.strip()[:400]
        return result, metadata
    return {}, {}


def _header(headers: dict[str, str], name: str) -> tuple[str | None, str | None]:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value, key
    return None, None


def _status(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 100 <= value <= 599 else None
    if isinstance(value, str):
        match = HTTP_STATUS_LINE.search(value)
        if match:
            return int(match.group(1))
        if value.strip().isdigit() and 100 <= int(value.strip()) <= 599:
            return int(value.strip())
    return None


def _request(alert: dict[str, Any]) -> dict[str, Any]:
    head, _ = _first(alert, ("requestHead", "requestHeaders", "request_header"))
    metadata: dict[str, Any] = {}
    headers, parsed_metadata = _headers(head)
    metadata = {**metadata, **parsed_metadata}
    method_value, _ = _first(alert, ("method", "httpMethod"))
    path_value, _ = _first(alert, ("path", "requestPath", "url", "uri"))
    request_line = metadata.get("request_line", {})
    method = str(method_value or request_line.get("method") or "").upper()
    target = str(path_value or request_line.get("target") or "")
    version = str(request_line.get("version") or "")
    if not version:
        version_value, _ = _first(alert, ("httpVersion", "version"))
        version = str(version_value or "")
    parsed_url = urlparse(target if "://" in target else f"//{target}")
    path = parsed_url.path or (target if target.startswith("/") else "")
    host, _ = _header(headers, "Host")
    host = host or parsed_url.netloc or ""
    body, body_source = _first(alert, ("requestBody", "request_body", "payload"))
    body_value, body_info = _parse_json_value(body)
    return {
        "method": method or None,
        "path": path or None,
        "target": target or None,
        "host": host or None,
        "version": version or None,
        "headers": headers,
        "body": body_info,
        "body_source": f"alert.{body_source}" if body_source else None,
        "body_value": body_value,
    }


def _response(alert: dict[str, Any]) -> dict[str, Any]:
    head, _ = _first(alert, ("responseHead", "responseHeaders", "response_header"))
    headers, metadata = _headers(head)
    status_value, status_source = _first(
        alert, ("httpStatus", "statusCode", "responseStatus", "response_code")
    )
    status_code = _status(status_value) or _status(metadata.get("status_code"))
    if status_code is None:
        for key, value in headers.items():
            if key.lower() in {"status", ":status"}:
                status_code = _status(value)
                if status_code is not None:
                    break
    body, body_source = _first(alert, ("responseBody", "response_body", "responseData"))
    body_value, body_info = _parse_json_value(body)
    return {
        "status_code": status_code,
        "status_source": f"alert.{status_source}" if status_source else None,
        "headers": headers,
        "body": body_info,
        "body_source": f"alert.{body_source}" if body_source else None,
        "body_value": body_value,
    }


def parse_http_request(raw: dict[str, Any] | str) -> dict[str, Any]:
    """Public, redacted request parser for tool callers and audit tests.

    The pipeline uses the private representation internally so that business
    extraction can inspect parsed values.  This public helper deliberately
    removes those values and returns only safe request metadata.
    """
    alert = _as_dict(raw) if isinstance(raw, (dict, str)) else {}
    parsed = _request(alert)
    return {
        key: _safe_headers(value) if key == "headers" else value
        for key, value in parsed.items()
        if key != "body_value"
    }


def parse_http_response(raw: dict[str, Any] | str) -> dict[str, Any]:
    """Public, redacted response parser for tool callers and audit tests."""
    alert = _as_dict(raw) if isinstance(raw, (dict, str)) else {}
    parsed = _response(alert)
    return {
        key: _safe_headers(value) if key == "headers" else value
        for key, value in parsed.items()
        if key != "body_value"
    }


def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: "[敏感头已隐藏]" if key.lower() in SENSITIVE_HEADER_NAMES else value
        for key, value in headers.items()
    }


def _ip(value: Any) -> str | None:
    text = str(value).strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        match = IP_PATTERN.search(text)
        if not match:
            return None
        try:
            return str(ipaddress.ip_address(match.group(0)))
        except ValueError:
            return None


def _pick_ip(alert: dict[str, Any], names: tuple[str, ...]) -> tuple[str | None, str | None]:
    value, source = _first(alert, names)
    if isinstance(value, list):
        value = next((item for item in value if _ip(item)), None)
    parsed = _ip(value) if value is not None else None
    return parsed, f"alert.{source}" if source and parsed else None


def _auth(request: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
    value, source_key = _header(request["headers"], "Authorization")
    if source_key:
        source_key = f"request.headers.{source_key}"
    if value is None:
        value, source = _first(alert, ("authorization", "authHeader", "authentication"))
        source_key = f"alert.{source}" if source else None
    cookie, cookie_key = _header(request["headers"], "Cookie")
    if cookie_key:
        cookie_key = f"request.headers.{cookie_key}"
    if cookie is None:
        cookie, source = _first(alert, ("cookie", "session", "sessionId"))
        cookie_key = f"alert.{source}" if source else None
    if value is not None:
        match = BEARER_PATTERN.match(str(value))
        scheme = match.group(1) if match else "unknown"
        credential = match.group(2) if match else str(value)
        lowered = str(credential or "").strip().lower()
        value_state = (
            "null_or_invalid"
            if not credential or lowered in {"null", "undefined", "none", "invalid", "expired"}
            else "present_unvalidated"
        )
        if value_state == "present_unvalidated" and scheme.lower() in {"bearer", "basic", "digest"}:
            value_state = "token_or_credential"
        return {
            "present": True,
            "scheme": scheme,
            "value_state": value_state,
            "authentication_validity": "not_confirmed",
            "source": source_key,
            "cookie_present": cookie is not None,
            "cookie_source": cookie_key,
        }
    if cookie is not None:
        return {
            "present": True,
            "scheme": "Cookie/Session",
            "value_state": "session_present_unvalidated",
            "authentication_validity": "not_confirmed",
            "source": cookie_key,
            "cookie_present": True,
            "cookie_source": cookie_key,
        }
    return {
        "present": False,
        "scheme": None,
        "value_state": "not_observed",
        "authentication_validity": "not_confirmed",
        "source": None,
        "cookie_present": False,
        "cookie_source": None,
    }


def _find_key(value: Any, names: tuple[str, ...], path: str = "responseBody") -> tuple[Any, str | None]:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in {name.lower() for name in names}:
                return child, f"{path}.{key}"
            found, found_path = _find_key(child, names, f"{path}.{key}")
            if found_path:
                return found, found_path
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found, found_path = _find_key(child, names, f"{path}[{index}]")
            if found_path:
                return found, found_path
    return None, None


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "success", "succeeded", "ok", "成功"}:
            return True
        if lowered in {"false", "failed", "failure", "error", "失败", "拒绝"}:
            return False
    return None


def extract_business_result(response_body: Any, http_status: int | None = None) -> dict[str, Any]:
    """Extract application result without conflating it with HTTP status."""
    success_value, success_source = _find_key(response_body, ("success", "succeeded", "ok", "ret"))
    code_value, code_source = _find_key(
        response_body, ("status_code", "statusCode", "businessCode", "business_status", "code")
    )
    message_value, message_source = _find_key(response_body, ("message", "msg", "error"))
    success = _bool(success_value)
    code: int | str | None = code_value if isinstance(code_value, (int, str)) else None
    if isinstance(code, str) and code.strip().isdigit():
        code = int(code.strip())
    if success is None and isinstance(code, int):
        success = 200 <= code < 300
    elif success is None and isinstance(code, str):
        success = _bool(code)
    status = "success" if success is True else "failure" if success is False else "unknown"
    return {
        "success": success,
        "code": code,
        "message": _safe_text(message_value, 240) if message_value is not None else None,
        "status": status,
        "source": success_source or code_source or message_source,
        "http_status": http_status,
        "http_and_business_are_separate": True,
    }


def _timestamp(value: Any) -> tuple[str | None, str]:
    if value in (None, "", 0, 0.0, "0"):
        return None, "未记录"
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if number > 10_000_000_000:
            number /= 1_000
        if not 946_684_800 <= number <= 4_102_444_800:
            return None, "无效时间戳"
        return datetime.fromtimestamp(number, tz=UTC).isoformat(), "有效"
    if not isinstance(value, str):
        return None, "无效时间格式"
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value.strip())
        except (TypeError, ValueError, IndexError):
            return None, "无效时间格式"
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    if not 2000 <= parsed.year <= 2100:
        return None, "无效时间范围"
    return parsed.isoformat(), "有效"


def _timestamp_results(alert: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for path, value in _flatten(alert):
        key = _key(path)
        if key not in {
            "time",
            "date",
            "datetime",
            "timestamp",
            "eventtime",
            "event_time",
            "firstseen",
            "lastseen",
            "createdat",
            "updatedat",
            "occurtimestamp",
            "发生时间",
            "时间戳",
        }:
            continue
        parsed, status = _timestamp(value)
        results.append(
            {
                "source": path,
                "status": status,
                "value": parsed or _safe_text(value, 80),
            }
        )
    return results


def _behavior_text(alert: dict[str, Any]) -> str:
    rows = [
        f"{path} {_safe_text(value)}"
        for path, value in _flatten(alert)
        if _key(path) not in RULE_METADATA_KEYS
        and not re.search(r"time|timestamp|date|duration|count|length|size", _key(path), re.I)
        and not any(part in path.lower() for part in ("response", "uebaproof", "history", "logtrace"))
        and value not in (None, "", [], {}, False, 0, 0.0, "0")
    ]
    return " ".join(rows).lower()


def apply_field_applicability(
    normalized: dict[str, Any], action: str, alert: dict[str, Any] | None = None
) -> dict[str, Any]:
    alert = alert if isinstance(alert, dict) else normalized.get("_alert_for_applicability", {})
    not_applicable: list[dict[str, str]] = []
    protocol = str(normalized.get("http", {}).get("protocol") or "").lower()
    non_http_families = ("mysql", "vpn", "ldap", "smb", "rdp")
    for path, _ in _flatten(alert):
        key = _key(path)
        family = next((item for item in non_http_families if key.startswith(item)), None)
        if family and (protocol == "http" or action in {"authentication", "resource_access", "file_upload"}):
            not_applicable.append(
                {
                    "field": path,
                    "status": "not_applicable",
                    "reason": f"当前业务上下文为 HTTP/{action}，{family.upper()} 字段不参与本次业务结果判断。",
                }
            )
    normalized["field_applicability"] = {
        "not_applicable": not_applicable,
        "not_applicable_fields": [item["field"] for item in not_applicable],
        "rule": "字段不适用时不作为反证、负证据或攻击成功证据；0/false 只在字段适用且语义明确时解释。",
    }
    normalized.pop("_alert_for_applicability", None)
    return normalized


def normalize_alert(raw: dict[str, Any] | str) -> dict[str, Any]:
    alert = _as_dict(raw)
    request = _request(alert)
    response = _response(alert)
    normalized: dict[str, Any] = {
        "schema_version": "analysis-normalized-event-v1",
        "source_field_count": len(alert),
        "http": {
            "method": request["method"],
            "path": request["path"],
            "target": request["target"],
            "host": request["host"],
            "version": request["version"],
            "headers": _safe_headers(request["headers"]),
            "body_parse_result": request["body"],
            "status_code": response["status_code"],
            "response_headers": _safe_headers(response["headers"]),
            "response_body_parse_result": response["body"],
            "protocol": str(_first(alert, ("protocol", "transport"))[0] or "HTTP").upper(),
        },
        "authorization": _auth(request, alert),
        "network": {
            "source_ip": _pick_ip(alert, ("srcIp", "sourceIp", "src_ip", "clientIp"))[0],
            "destination_ip": _pick_ip(alert, ("dstIp", "targetIp", "destinationIp", "dst_ip"))[0],
        },
        "timestamps": _timestamp_results(alert),
        "business_result": extract_business_result(response["body_value"], response["status_code"]),
        "source_semantics": {
            "request_body": request["body_source"],
            "response_body": response["body_source"],
            "http_status": response["status_source"],
        },
        "behavior_text": _behavior_text(alert),
        "_alert_for_applicability": alert,
    }
    normalized["request"] = {
        "method": request["method"],
        "path": request["path"],
        "host": request["host"],
        "headers": normalized["http"]["headers"],
        "body_parse_result": normalized["http"]["body_parse_result"],
    }
    normalized["response"] = {
        "status_code": response["status_code"],
        "headers": normalized["http"]["response_headers"],
        "body_parse_result": normalized["http"]["response_body_parse_result"],
    }
    return apply_field_applicability(normalized, "unknown", alert)
