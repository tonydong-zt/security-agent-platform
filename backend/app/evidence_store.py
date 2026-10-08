"""Unified, provenance-aware evidence for routed alert analysis.

The store is intentionally conservative: it contains semantic facts and safe
previews, never secret-bearing raw values.  Evidence from an embedded log or
historical reference is retained for context, but cannot directly support the
main event scene.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .normalization import _parse_json_value


SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "authorization",
    "credential",
    "apikey",
    "api_key",
    "privatekey",
)
RULE_KEYS = {"name", "rulename", "alertname", "ruletitle", "threattype", "risklevel"}
EMBEDDED_KEYS = {
    "log",
    "logs",
    "history",
    "historical",
    "reference",
    "trace",
    "stack",
    "stacktrace",
    "stdout",
    "stderr",
    "command",
    "process",
    "event",
    "request",
    "response",
    "http",
    "artifact",
    "content",
    "email",
}


def _key(path: str) -> str:
    return re.sub(r"\[\d+\]", "", path.rsplit(".", 1)[-1]).lower()


def _flatten(value: Any, path: str = "alert") -> list[tuple[str, Any]]:
    if isinstance(value, str) and path.lower().endswith((".responsebody", ".requestbody")):
        parsed, _ = _parse_json_value(value)
        if isinstance(parsed, (dict, list)):
            value = parsed
    if isinstance(value, dict):
        return [row for key, child in value.items() for row in _flatten(child, f"{path}.{key}")]
    if isinstance(value, list):
        return [row for index, child in enumerate(value) for row in _flatten(child, f"{path}[{index}]")]
    return [(path, value)]


def _safe_preview(value: Any, key: str = "", limit: int = 180) -> Any:
    lowered = key.lower()
    if isinstance(value, dict) and isinstance(value.get("keys"), list):
        return {"keys": [str(item) for item in value["keys"]][:40]}
    if any(part in lowered for part in SENSITIVE_KEY_PARTS) and isinstance(value, dict):
        # Preserve the existence and names of semantic fields while dropping
        # their values (for example responseBody.password -> {keys:[...]}).
        return {"keys": [str(item) for item in value.keys()][:40]}
    if any(part in lowered for part in SENSITIVE_KEY_PARTS):
        return "[敏感值已隐藏]"
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value)
    text = re.sub(r"(?i)(bearer\s+)[^\s,;]+", r"\1[令牌已隐藏]", text)
    text = re.sub(
        r"(?i)(password|passwd|secret|token|apikey|authorization)\s*[:=]\s*[^,;\s}]+",
        r"\1=[值已隐藏]",
        text,
    )
    return text.replace("\n", " ")[:limit]


def _is_present(value: Any) -> bool:
    return value not in (None, "", [], {}, False)


def _semantic_type(path: str, value: Any) -> str:
    key = _key(path)
    lowered = path.lower()
    if key in {"method", "httpmethod"}:
        return "http_method"
    if key in {"path", "url", "target", "requesturi"}:
        return "request_target"
    if "status" in key and isinstance(value, (int, float, str)):
        return "http_or_business_status"
    if "authorization" in key or key in {"cookie", "session", "sessionid", "token"}:
        return "authentication_observation"
    if "response" in lowered:
        return "current_response_field"
    if "request" in lowered or key in {"query", "body", "payload", "parameter", "params"}:
        return "current_request_field"
    if any(part in key for part in ("file", "filename", "hash", "sha256", "md5")):
        return "file_metadata"
    if any(part in key for part in ("exec", "process", "command", "shell")):
        return "execution_observation"
    if "time" in key or "date" in key or "timestamp" in key:
        return "event_time"
    return "alert_field"


def _source_role(path: str, layer: int) -> str:
    lowered = path.lower()
    if layer == 1:
        return "embedded_artifact"
    if layer == 2:
        return "historical_reference"
    if "response" in lowered:
        return "current_response"
    if "request" in lowered or any(token in lowered for token in ("url", "query", "payload")):
        return "current_request"
    if any(token in lowered for token in ("rule", "threattype", "risklevel", "alertname")):
        return "rule_metadata"
    return "normalized_fact"


def _looks_like_embedded(path: str, parent_path: str = "") -> bool:
    keys = {_key(path), _key(parent_path)}
    lowered = path.lower()
    # The top-level request/response containers are current-event material;
    # nested ``responseBody.log`` / ``responseBody.history`` is an artifact.
    top_level = lowered.endswith((".requesthead", ".requestbody", ".responsehead", ".responsebody"))
    nested_parts = lowered.split(".")[2:]
    return (bool(keys & EMBEDDED_KEYS) or bool(set(nested_parts) & EMBEDDED_KEYS)) and not top_level


def _polarity(path: str, value: Any, action: str) -> str:
    text = f"{path} {value}".lower()
    if any(token in text for token in ("failed", "failure", "denied", "拒绝", "失败", "invalid", "无效")):
        return "negative"
    if any(token in text for token in ("success", "succeeded", "ok", "成功", "allowed", "已授权")):
        return "positive"
    if action == "authentication" and "token" in text:
        return "positive"
    return "unknown"


def parse_embedded_content(alert: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract embedded artifacts as contextual evidence with layers > 0."""
    results: list[dict[str, Any]] = []
    for path, value in _flatten(alert):
        if not _is_present(value) or not _looks_like_embedded(path):
            continue
        lower = str(value).lower()
        if isinstance(value, (dict, list)):
            semantic_type = "embedded_structured_artifact"
        elif any(token in lower for token in ("powershell", "cmd.exe", "bash", "sh -c", "whoami")):
            semantic_type = "embedded_command_reference"
        elif any(token in lower for token in ("http/", "get /", "post /", "authorization:")):
            semantic_type = "embedded_http_reference"
        else:
            semantic_type = "embedded_log_or_reference"
        results.append(
            {
                "source_path": path,
                "raw_value": _safe_preview(value, _key(path)),
                "semantic_value": f"嵌入内容：{_safe_preview(value, _key(path), 120)}",
                "semantic_type": semantic_type,
                "polarity": "unknown",
                "applicable": True,
                "confidence": 0.55,
                "provenance": {
                    "source_role": "embedded_artifact",
                    "describes_current_event": False,
                    "event_layer": 1,
                    "direct": False,
                },
            }
        )
    return results[:40]


def build_evidence_store(
    normalized_event: dict[str, Any],
    alert: dict[str, Any] | None = None,
    business_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a stable evidence store with IDs suitable for candidate support."""
    alert = alert if isinstance(alert, dict) else {}
    context = business_context if isinstance(business_context, dict) else {}
    action = str(context.get("context_id") or context.get("action") or "unknown")
    items: list[dict[str, Any]] = []

    def add(
        source_path: str,
        semantic_value: Any,
        semantic_type: str,
        polarity: str = "unknown",
        applicable: bool = True,
        confidence: float = 0.85,
        source_role: str = "normalized_fact",
        describes_current_event: bool = True,
        event_layer: int = 0,
        raw_value: Any = None,
    ) -> None:
        if semantic_value in (None, "", [], {}, False) and raw_value in (None, "", [], {}, False):
            return
        items.append(
            {
                "evidence_id": f"E{len(items) + 1:03d}",
                "source_path": source_path,
                "raw_value": _safe_preview(raw_value if raw_value is not None else semantic_value, source_path),
                "semantic_value": _safe_preview(semantic_value, source_path),
                "semantic_type": semantic_type,
                "polarity": polarity,
                "applicable": bool(applicable),
                "confidence": round(max(0.0, min(1.0, float(confidence))), 3),
                "provenance": {
                    "source_role": source_role,
                    "describes_current_event": bool(describes_current_event),
                    "event_layer": int(event_layer),
                    "direct": bool(describes_current_event and event_layer == 0),
                },
            }
        )

    http = normalized_event.get("http", {})
    method = http.get("method")
    path = http.get("path") or http.get("target")
    status = http.get("status_code")
    if method:
        add("normalized.http.method", method, "http_method", "positive", confidence=0.98)
    if path:
        add("normalized.http.path", path, "request_target", "positive", confidence=0.95)
    if status is not None:
        add(
            "normalized.http.status_code",
            status,
            "http_status",
            "positive" if isinstance(status, int) and 200 <= status < 300 else "negative",
            confidence=0.98,
        )
    request_keys = normalized_event.get("http", {}).get("body_parse_result", {}).get("keys", [])
    request_text = str(path or "").lower() + " " + " ".join(request_keys).lower()
    headers = http.get("headers", {})
    content_type = next((str(v).lower() for k, v in headers.items() if k.lower() == "content-type"), "")
    if method in (None, "", "POST", "PUT", "PATCH") and (
        "multipart/form-data" in content_type
        or any(term in request_text for term in ("upload", "filename", "fileupload"))
    ):
        add("normalized.request.file_delivery", "file upload request observed; storage/execution unknown",
            "file_upload_observation", "positive", source_role="current_request")
    business = normalized_event.get("business_result", {})
    if business.get("success") is not None or business.get("status") not in (None, "unknown"):
        add(
            "normalized.business_result",
            {"success": business.get("success"), "status": business.get("status"), "code": business.get("code")},
            "business_result",
            "positive" if business.get("success") is True else "negative" if business.get("success") is False else "unknown",
            confidence=0.9,
        )
    auth = normalized_event.get("authorization", {})
    if auth.get("present"):
        add(
            "normalized.authorization",
            {"present": True, "scheme": auth.get("scheme"), "value_state": auth.get("value_state")},
            "authentication_observation",
            "positive",
            confidence=0.92,
            source_role="current_request",
        )
    else:
        add(
            "normalized.authorization",
            {"present": False, "value_state": "not_observed"},
            "authentication_observation",
            "unknown",
            confidence=0.88,
            source_role="current_request",
        )

    applicability = normalized_event.get("field_applicability", {})
    not_applicable = set(applicability.get("not_applicable_fields", []))
    for source_path, value in _flatten(alert):
        key = _key(source_path)
        if key in RULE_KEYS or not _is_present(value):
            continue
        lower_path = source_path.lower()
        if any(token in lower_path for token in ("requesthead", "requestbody", "query", "payload", "parameter", "url")):
            text = _safe_preview(value, key, 220)
            add(
                source_path,
                text,
                "current_request_signal",
                _polarity(source_path, value, action),
                source_path not in not_applicable,
                confidence=0.76,
                source_role="current_request",
                raw_value=value,
            )
        elif any(token in lower_path for token in ("responsehead", "responsebody")):
            if _looks_like_embedded(source_path):
                # Keep nested response logs/traces as layer-1 artifacts.  Do
                # not duplicate them as current-response facts.
                continue
            if isinstance(value, dict):
                keys = list(value.keys())[:40]
            else:
                keys = [key]
            add(
                source_path,
                {"keys": keys},
                "current_response_field",
                "positive",
                source_path not in not_applicable,
                confidence=0.8,
                source_role="current_response",
                raw_value=value,
            )
        elif any(token in key for token in ("filename", "filehash", "sha256", "md5", "sample")):
            add(
                source_path,
                "file metadata observed",
                "file_metadata",
                "positive",
                source_path not in not_applicable,
                confidence=0.8,
                source_role="current_request" if "request" in lower_path else "normalized_fact",
                raw_value=value,
            )
        elif any(token in key for token in ("execstatus", "processname", "commandline", "execution", "childprocess")):
            add(
                source_path,
                "execution status/host process field observed",
                "execution_observation",
                _polarity(source_path, value, action),
                source_path not in not_applicable,
                confidence=0.84,
                source_role="current_response" if "response" in lower_path else "normalized_fact",
                raw_value=value,
            )

    for item in parse_embedded_content(alert):
        item["evidence_id"] = f"E{len(items) + 1:03d}"
        items.append(item)

    applicable_current = [
        item
        for item in items
        if item["applicable"]
        and item["provenance"]["describes_current_event"]
        and item["provenance"]["event_layer"] == 0
    ]
    embedded = [item for item in items if item["provenance"]["event_layer"] == 1]
    return {
        "schema_version": "unified-evidence-store-v1",
        "items": items,
        "evidence_count": len(items),
        "current_evidence_count": len(applicable_current),
        "embedded_evidence_count": len(embedded),
        "current_event_rule": "只有 provenance.describes_current_event=true 且 event_layer=0 的证据可以直接支持主场景；嵌入/历史内容只能作为上下文。",
        "by_id": {item["evidence_id"]: item for item in items},
    }


def evidence_ids_for(
    store: dict[str, Any],
    semantic_types: tuple[str, ...] = (),
    current_only: bool = True,
) -> list[str]:
    ids: list[str] = []
    for item in store.get("items", []):
        if semantic_types and item.get("semantic_type") not in semantic_types:
            continue
        provenance = item.get("provenance", {})
        if current_only and not (
            item.get("applicable")
            and provenance.get("describes_current_event")
            and provenance.get("event_layer") == 0
        ):
            continue
        ids.append(str(item.get("evidence_id")))
    return ids
