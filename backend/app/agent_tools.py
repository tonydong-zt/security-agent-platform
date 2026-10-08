from __future__ import annotations

import ipaddress
import json
import re
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

from .business_context import infer_business_context
from .evidence_store import build_evidence_store
from .knowledge import get_knowledge_service
from .normalization import normalize_alert
from .privacy import redact_secrets
from .risk import quantize_score, risk_level, risk_profile_for_scene, risk_profile_for_workflow
from .scenarios import generate_scene_candidates, select_primary_scene
from .security_classifier import classify_security_problems
from .workflows import route_workflow, workflow_evidence_result

ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


class ToolExecutionError(RuntimeError):
    """A tool failure that keeps the failing tool and original error type."""

    def __init__(self, tool: str, error_type: str, message: str) -> None:
        self.tool = tool
        self.error_type = error_type
        self.message = message
        super().__init__(f"tool={tool} error_type={error_type} message={message}")

IP_PATTERN = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
DOMAIN_PATTERN = re.compile(
    r"(?<![@\w-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![\w-])"
)
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
HTTP_STATUS_PATTERN = re.compile(r"HTTP/\d(?:\.\d)?\s+(\d{3})", re.IGNORECASE)
HASH_PATTERN = re.compile(r"\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b")
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
TIME_KEY_PATTERN = re.compile(
    r"(?:time|date|timestamp|firstseen|lastseen|发生|时间)", re.IGNORECASE
)
SENSITIVE_PATTERNS = (
    (re.compile(r"\b1[3-9]\d{9}\b"), "[手机号已脱敏]"),
    (re.compile(r"\b\d{17}[0-9Xx]\b"), "[身份证已脱敏]"),
    (re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"), "[邮箱已脱敏]"),
    (
        re.compile(r"\b(?:sk-|Bearer\s+)[A-Za-z0-9._-]{8,}\b", re.IGNORECASE),
        "[令牌已脱敏]",
    ),
)
PRIVATE_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    label: str
    description: str
    category: str
    input_schema: dict[str, Any]
    sample_input: dict[str, Any]
    handler: ToolHandler

    def public(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label,
            "description": self.description,
            "category": self.category,
            "safety": "只读",
            "input_schema": self.input_schema,
            "sample_input": self.sample_input,
        }


def redact(value: Any) -> Any:
    value = redact_secrets(value)
    if isinstance(value, dict):
        return {str(key): redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if not isinstance(value, str):
        return value
    result = value
    for pattern, replacement in SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def _flatten(value: Any, path: str = "alert") -> list[tuple[str, Any]]:
    rows: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            rows.extend(_flatten(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            rows.extend(_flatten(item, f"{path}[{index}]"))
    else:
        rows.append((path, value))
    return rows


def _alert(arguments: dict[str, Any]) -> dict[str, Any]:
    alert = arguments.get("alert", arguments)
    if not isinstance(alert, dict):
        raise TypeError("工具参数 alert 必须是 JSON 对象")
    return redact(alert)


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _contains_any(text: str, words: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(word in lowered for word in words)


def _behavior_serialized(alert: dict[str, Any]) -> str:
    """Serialize behavioral fields while excluding rule metadata from detection."""
    excluded = {"name", "rulename", "alertname", "ruletitle", "threattype", "risklevel"}
    return " ".join(
        f"{path} {_short(value)}"
        for path, value in _flatten(alert)
        if _path_key(path) not in excluded and _has_value(value)
    ).lower()


def _path_key(path: str) -> str:
    key = path.rsplit(".", 1)[-1]
    return re.sub(r"\[\d+\]", "", key).lower()


def _has_value(value: Any) -> bool:
    # False/0/"0" are normally negative or absent signals.  Dedicated parsers
    # still retain them as unrecorded/invalid values when the field is semantic.
    return value not in (None, "", [], {}, False, 0, 0.0, "0")


def _short(value: Any, limit: int = 180) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value)
    return text.replace("\n", " ")[:limit]


TIME_FIELD_NAMES = frozenset(
    {
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
        "logtime",
        "accesstime",
        "occurtimestamp",
        "firsttimestamp",
        "lasttimestamp",
        "uploadtimestamp",
        "startcloudts",
        "endcloudts",
        "filecreatetime",
        "filemodifytime",
        "scanstarttime",
        "scanendtime",
        "发生时间",
        "时间戳",
    }
)
TIME_FIELD_EXCLUSIONS = (
    "timeregion",
    "duration",
    "timeout",
    "tcpelapsedtime",
    "logintimeout",
    "locktime",
    "bfduration",
    "pfduration",
    "count",
    "port",
)
ID_PATH_TOKENS = ("apiid", "appid", "requestid", "traceid", "spanid", "uuid", "guid")
TECHNOLOGY_LABELS = (
    "asp.net",
    "microsoft-iis",
    "microsoft.com",
    "nginx",
    "apache",
    "tomcat",
    "kestrel",
)
SENSITIVE_TERMS = (
    "password",
    "passwd",
    "credential",
    "secret",
    "token",
    "apikey",
    "api_key",
    "privatekey",
    "身份证",
    "手机号",
    "邮箱",
    "bank",
    "card",
    "ssn",
    "hash",
)


def _is_time_semantic(path: str) -> bool:
    key = _path_key(path)
    if any(token in key for token in TIME_FIELD_EXCLUSIONS):
        return False
    if key in TIME_FIELD_NAMES:
        return True
    return key.endswith("time") and any(
        prefix in key
        for prefix in ("event", "create", "update", "log", "access", "first", "last")
    )


def _parse_time(value: Any) -> tuple[str | None, str]:
    if value in (None, "", 0, 0.0, "0"):
        return None, "未记录"
    if isinstance(value, str) and value.strip().isdigit():
        try:
            value = int(value.strip())
        except ValueError:
            return None, "无效时间格式"
    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp <= 0:
            return None, "未记录"
        if timestamp > 10_000_000_000:
            timestamp /= 1_000
        if not 946_684_800 <= timestamp <= 4_102_444_800:
            return None, "无效时间戳"
        try:
            return datetime.fromtimestamp(timestamp, tz=UTC).isoformat(), "有效"
        except (OverflowError, OSError, ValueError):
            return None, "无效时间戳"
    if not isinstance(value, str) or not value.strip():
        return None, "未记录"
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


def build_timeline(arguments: dict[str, Any]) -> dict[str, Any]:
    """Only accepts fields whose names clearly carry time semantics."""
    alert = _alert(arguments)
    events: list[dict[str, Any]] = []
    unrecorded: list[dict[str, str]] = []
    ignored_fields: list[dict[str, str]] = []
    for path, raw in _flatten(alert):
        key = _path_key(path)
        if any(token in key for token in TIME_FIELD_EXCLUSIONS):
            ignored_fields.append(
                {"source": path, "reason": "字段名不表示事件发生时间"}
            )
            continue
        if not _is_time_semantic(path):
            continue
        parsed, status = _parse_time(raw)
        if not parsed:
            unrecorded.append({"source": path, "value": _short(raw), "reason": status})
            continue
        events.append(
            {
                "time": parsed,
                "label": key,
                "source": path,
                "description": f"原始告警时间字段 {path}",
            }
        )
    # Multiple products often repeat one timestamp in fields such as
    # eventTime/occurTimestamp. They are one occurrence, not several events.
    deduplicated: dict[str, dict[str, Any]] = {}
    for event in events:
        existing = deduplicated.get(event["time"])
        if not existing:
            event["sources"] = [event["source"]]
            deduplicated[event["time"]] = event
            continue
        existing["sources"].append(event["source"])
        existing["source"] = ", ".join(existing["sources"])
        existing["label"] = " / ".join(
            [part for part in (existing["label"], event["label"]) if part]
        )
        existing["description"] = (
            "多个语义明确的原始时间字段记录同一时刻：" + existing["source"]
        )
    events = sorted(deduplicated.values(), key=lambda item: item["time"])
    return {
        "events": events[:50],
        "total": len(events),
        "raw_total": sum(len(item.get("sources", [])) for item in events),
        "unrecorded": unrecorded[:30],
        "ignored_fields": ignored_fields[:30],
    }


def _ip_scope(value: str) -> str:
    address = ipaddress.ip_address(value)
    if address.is_loopback:
        return "本机"
    if address.version == 4 and any(
        address in network for network in PRIVATE_IPV4_NETWORKS
    ):
        return "私网/内部资产"
    if address.is_global:
        return "公网"
    return "保留/特殊用途"


def _ioc_meaning(
    kind: str, candidate: str, path: str, text: str
) -> dict[str, Any] | None:
    """Accept indicators only where path and surrounding semantics justify them."""
    key = _path_key(path)
    lower_path = path.lower()
    lower_candidate = candidate.lower()
    if kind == "hash":
        if any(token in key for token in ID_PATH_TOKENS) or "id" == key:
            return None
        if not any(
            token in lower_path
            for token in ("hash", "sha", "md5", "file", "sample", "artifact", "malware")
        ):
            return None
        return {
            "reason": "文件、样本或制品字段中出现的哈希，可用于跨日志关联",
            "confidence": 0.9,
            "scope": "待确认",
        }
    if kind == "ip":
        normalized = _valid_ip(candidate)
        if not normalized:
            return None
        scope = _ip_scope(normalized)
        if any(
            token in lower_path
            for token in ("src", "source", "client", "remote", "xff", "origin")
        ):
            return {
                "reason": "告警来源网络字段，可用于关联同源请求和会话行为",
                "confidence": 0.85 if scope == "公网" else 0.65,
                "scope": scope,
                "value": normalized,
            }
        if any(token in lower_path for token in ("ioc", "indicator", "c2", "malware")):
            return {
                "reason": "告警明确标记为威胁或关联指标",
                "confidence": 0.9,
                "scope": scope,
                "value": normalized,
            }
        return None
    if kind == "domain":
        if lower_candidate in TECHNOLOGY_LABELS or any(
            token in lower_path
            for token in ("server", "technology", "framework", "product")
        ):
            return None
        if any(
            token in lower_path
            for token in ("ioc", "indicator", "c2", "malware", "phishing")
        ):
            return {
                "reason": "告警明确标记为威胁、恶意软件、钓鱼或 C2 关联的域名",
                "confidence": 0.85,
                "scope": "外部/待确认",
            }
        return None
    if kind == "url":
        suspicious = _contains_any(
            candidate,
            ("union select", "../", "<script", "cmd=", "exec", "token=", "password="),
        )
        if suspicious or any(
            token in lower_path for token in ("ioc", "indicator", "redirect", "referer")
        ):
            return {
                "reason": "请求或重定向中具有攻击关联语义的完整 URL",
                "confidence": 0.78 if suspicious else 0.65,
                "scope": "外部/待确认",
            }
        return None
    if kind == "cve":
        return {
            "reason": "告警中直接引用的漏洞编号，可用于核验受影响版本与补丁状态",
            "confidence": 0.8,
            "scope": "漏洞参考",
        }
    return None


def extract_iocs(arguments: dict[str, Any]) -> dict[str, Any]:
    alert = _alert(arguments)
    indicators: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for path, raw in _flatten(alert):
        if not isinstance(raw, (str, int, float)):
            continue
        text = str(raw)
        candidates: list[tuple[str, str]] = []
        candidates.extend(
            ("url", match.group(0)) for match in URL_PATTERN.finditer(text)
        )
        candidates.extend(("ip", match.group(0)) for match in IP_PATTERN.finditer(text))
        candidates.extend(
            ("hash", match.group(0).lower()) for match in HASH_PATTERN.finditer(text)
        )
        candidates.extend(
            ("cve", match.group(0).upper()) for match in CVE_PATTERN.finditer(text)
        )
        candidates.extend(
            ("domain", match.group(0).lower())
            for match in DOMAIN_PATTERN.finditer(text)
        )
        for kind, candidate in candidates:
            meaning = _ioc_meaning(kind, candidate, path, text)
            normalized = meaning.pop("value", candidate) if meaning else candidate
            key = (kind, normalized)
            if key in seen:
                continue
            seen.add(key)
            if not meaning:
                excluded.append(
                    {
                        "value": candidate,
                        "source": path,
                        "reason": "字段语义不足以证明其具有攻击关联价值；未作为 IOC",
                    }
                )
                continue
            indicators.append(
                {
                    "type": kind,
                    "value": normalized,
                    "source": path,
                    "scope": meaning["scope"],
                    "reason": meaning["reason"],
                    "confidence": meaning["confidence"],
                }
            )
            if len(indicators) >= 100:
                break
    return {
        "indicators": indicators,
        "excluded": excluded[:50],
        "counts": dict(Counter(item["type"] for item in indicators)),
        "total": len(indicators),
    }


def _add_entity(
    entities: list[dict[str, str]],
    seen: set[tuple[str, str, str]],
    category: str,
    value: str,
    source: str,
    role: str,
    confidence: str = "字段直接出现",
) -> None:
    normalized = (category, value, source)
    if normalized in seen:
        return
    seen.add(normalized)
    entities.append(
        {
            "category": category,
            "value": value,
            "source": source,
            "role": role,
            "confidence": confidence,
        }
    )


def extract_security_entities(arguments: dict[str, Any]) -> dict[str, Any]:
    """Classify security-relevant entities before deciding which are IOCs.

    Entity extraction deliberately keeps an internal asset, API identifier, password
    hash, framework name, and network IOC in different classes.  Only the IOC class
    is suitable for threat-hunting indicator queries.
    """
    alert = _alert(arguments)
    iocs = extract_iocs({"alert": alert})
    entities: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    ioc_keys = {
        (item["type"], item["value"], item["source"]) for item in iocs["indicators"]
    }

    for item in iocs["indicators"]:
        _add_entity(
            entities,
            seen,
            "网络 IOC" if item["type"] in {"ip", "domain", "url"} else "威胁指标",
            str(item["value"]),
            str(item["source"]),
            item["reason"],
            f"IOC 可信度 {item['confidence']}",
        )

    for path, raw in _flatten(alert):
        if not _has_value(raw):
            continue
        key = _path_key(path)
        lower_path = path.lower()
        text = _short(raw)
        for candidate in IP_PATTERN.findall(text):
            value = _valid_ip(candidate)
            if not value:
                continue
            if any(
                token in lower_path
                for token in ("dst", "target", "destination", "host")
            ):
                _add_entity(
                    entities,
                    seen,
                    "资产",
                    value,
                    path,
                    "目标网络地址；内部地址表示资产角色，不自动等同于恶意 IOC",
                    _ip_scope(value),
                )
            elif ("ip", value, path) not in ioc_keys:
                _add_entity(
                    entities,
                    seen,
                    "网络地址",
                    value,
                    path,
                    "网络上下文字段；需结合字段语义确认是否具有攻击关联",
                    _ip_scope(value),
                )
        if any(token in key for token in ID_PATH_TOKENS) or key in {
            "assetid",
            "ruleid",
            "tenantid",
            "xappid",
        }:
            _add_entity(
                entities,
                seen,
                "应用/系统标识符",
                text,
                path,
                "应用、租户、规则或链路标识符；不作为文件 Hash IOC",
            )
        if any(
            token in lower_path for token in ("url", "uri", "endpoint", "api", "path")
        ):
            _add_entity(
                entities,
                seen,
                "应用/API",
                text,
                path,
                "应用入口或接口上下文",
            )
        if _contains_any(f"{path} {text}", SENSITIVE_TERMS) and (
            "response" in lower_path or "data" in lower_path
        ):
            _add_entity(
                entities,
                seen,
                "敏感数据",
                key,
                path,
                "响应或数据字段具有凭据、密码摘要、令牌或个人信息语义；按字段名展示，避免重复暴露值",
            )
        if any(
            token in lower_path
            for token in (
                "user",
                "account",
                "principal",
                "identity",
                "subject",
                "session",
                "cookie",
            )
        ):
            _add_entity(
                entities,
                seen,
                "身份/会话",
                key
                if any(token in lower_path for token in ("session", "cookie", "token"))
                else text,
                path,
                "身份、账号或会话上下文；其存在不等同于授权有效",
            )
        if any(token in lower_path for token in ("hash", "sha", "md5")) and not any(
            token in lower_path for token in ("password", "credential", "secret")
        ):
            for candidate in HASH_PATTERN.findall(text):
                _add_entity(
                    entities,
                    seen,
                    "文件/样本",
                    candidate.lower(),
                    path,
                    "文件、样本或制品哈希；可用于文件/样本关联",
                )
        for cve in CVE_PATTERN.findall(text):
            _add_entity(
                entities,
                seen,
                "漏洞参考",
                cve.upper(),
                path,
                "告警直接引用的漏洞编号；需核验受影响版本与利用关系",
            )
        if any(label in text.lower() for label in TECHNOLOGY_LABELS):
            _add_entity(
                entities,
                seen,
                "技术栈",
                text,
                path,
                "服务端技术或产品指纹；不是攻击域名 IOC",
            )

    entities.sort(key=lambda item: (item["category"], item["source"], item["value"]))
    return {
        "entities": entities[:100],
        "counts": dict(Counter(item["category"] for item in entities)),
        "total": len(entities),
        "ioc_total": iocs["total"],
    }


def _paths_matching(
    alert: dict[str, Any], tokens: tuple[str, ...]
) -> list[tuple[str, Any]]:
    return [
        (path, value)
        for path, value in _flatten(alert)
        if _has_value(value) and any(token in path.lower() for token in tokens)
    ]


def _is_applicable_path(path: str, normalized_event: dict[str, Any]) -> bool:
    excluded = set(
        normalized_event.get("field_applicability", {}).get("not_applicable_fields", [])
    )
    return path not in excluded


def _layer(
    layer_id: str,
    question: str,
    status: str,
    conclusion: str,
    evidence: list[str],
) -> dict[str, Any]:
    return {
        "id": layer_id,
        "question": question,
        "status": status,
        "conclusion": conclusion,
        "evidence": evidence[:8],
    }


def _is_successful_status(value: Any) -> bool:
    if isinstance(value, int):
        return 200 <= value < 300
    return (
        isinstance(value, str) and value.strip().isdigit() and 200 <= int(value) < 300
    )


def _host_ip(value: Any) -> str | None:
    text = str(value).strip()
    if not text:
        return None
    parsed = urlparse(text if "://" in text else f"//{text}")
    if parsed.hostname:
        normalized = _valid_ip(parsed.hostname)
        if normalized:
            return normalized
    match = IP_PATTERN.search(text)
    return _valid_ip(match.group(0)) if match else None


def _semantic_conflicts(
    alert: dict[str, Any], sensitive_response: list[tuple[str, Any]]
) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []
    destination = _paths_matching(alert, ("dstip", "targetip", "destinationip"))
    hosts = [
        (path, value)
        for path, value in _flatten(alert)
        if _has_value(value)
        and _path_key(path) in {"host", "authority"}
        and any(token in path.lower() for token in ("request", "http", "header"))
    ]
    for dst_path, dst_value in destination:
        dst_ip = _host_ip(dst_value)
        if not dst_ip:
            continue
        for host_path, host_value in hosts:
            host_ip = _host_ip(host_value)
            if host_ip and host_ip != dst_ip:
                conflicts.append(
                    {
                        "area": "目标地址与 HTTP Host",
                        "detail": f"{dst_path}={dst_ip} 与 {host_path}={host_ip} 不一致。",
                        "resolution": "核对代理、负载均衡、NAT、虚拟主机映射和原始连接目标；不能把两者直接视为同一资产。",
                        "sources": [dst_path, host_path],
                    }
                )
    label_fields = [
        (path, str(value))
        for path, value in _flatten(alert)
        if _has_value(value)
        and _path_key(path) in {"name", "rulename", "alertname", "ruletitle"}
    ]
    if sensitive_response and any(
        _contains_any(
            value, ("non-sensitive", "non sensitive", "nonsensitive", "非敏感")
        )
        for _, value in label_fields
    ):
        conflicts.append(
            {
                "area": "告警规则语义与响应内容",
                "detail": "告警规则名称表示非敏感内容，但响应字段直接出现敏感数据语义。",
                "resolution": "以原始响应字段为准，复核规则命名、分类逻辑和数据分级，避免用规则标题覆盖原始证据。",
                "sources": [path for path, _ in label_fields]
                + [path for path, _ in sensitive_response],
            }
        )
    event_times: list[tuple[str, str]] = []
    http_dates: list[tuple[str, str]] = []
    http_codes: list[tuple[str, int]] = []
    business_codes: list[tuple[str, int | bool]] = []
    for path, value in _flatten(alert):
        key = _path_key(path)
        if isinstance(value, str):
            status_match = HTTP_STATUS_PATTERN.search(value)
            if status_match:
                http_codes.append((path, int(status_match.group(1))))
        if (
            key in {"status", "statuscode", "httpstatus", "responsecode"}
            and "response" in path.lower()
            and (
                _is_successful_status(value)
                or isinstance(value, int)
                and 100 <= value <= 599
            )
        ):
            http_codes.append((path, int(value)))
        if key in {
            "businessstatus",
            "businesscode",
            "status_code",
            "loginstatus",
            "success",
        } and (
            isinstance(value, bool) or isinstance(value, int) and 100 <= value <= 599
        ):
            business_codes.append((path, value))
        parsed, status = _parse_time(value)
        if status != "有效" or not parsed:
            continue
        if key in {"eventtime", "event_time", "occurtimestamp", "发生时间", "时间戳"}:
            event_times.append((path, parsed))
        if key == "date" and "response" in path.lower():
            http_dates.append((path, parsed))
    for event_path, event_time in event_times:
        parsed_event = datetime.fromisoformat(event_time)
        for date_path, http_date in http_dates:
            delta = abs(
                (parsed_event - datetime.fromisoformat(http_date)).total_seconds()
            )
            if delta > 3_600:
                if any(item["area"] == "告警时间与 HTTP Date" for item in conflicts):
                    continue
                conflicts.append(
                    {
                        "area": "告警时间与 HTTP Date",
                        "detail": f"{event_path} 与 {date_path} 相差约 {round(delta / 3600, 1)} 小时。",
                        "resolution": "核对时区、采集延迟、代理缓存和字段含义；不在未核验前把两者拼成单一时间线。",
                        "sources": [event_path, date_path],
                    }
                )
    http_success = any(200 <= code < 300 for _, code in http_codes)
    business_failure = any(
        value is False
        or (
            isinstance(value, int)
            and not isinstance(value, bool)
            and not 200 <= value < 300
        )
        for _, value in business_codes
    )
    business_success = any(
        value is True
        or (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 200 <= value < 300
        )
        for _, value in business_codes
    )
    if (
        http_codes
        and business_codes
        and (
            (http_success and business_failure)
            or (not http_success and business_success)
        )
    ):
        conflicts.append(
            {
                "area": "HTTP 状态与业务状态",
                "detail": "协议层 HTTP 状态与业务层 status/success 结果表达不一致。",
                "resolution": "同时核对 HTTP 状态行、业务状态码/成功标志和响应体；协议成功不等于业务操作成功。",
                "sources": [path for path, _ in http_codes[:4]]
                + [path for path, _ in business_codes[:4]],
            }
        )
    return conflicts


def _legacy_candidate_scenarios(
    alert: dict[str, Any],
    request_fields: list[tuple[str, Any]],
    response_fields: list[tuple[str, Any]],
    auth_fields: list[tuple[str, Any]],
    sensitive_response: list[tuple[str, Any]],
    execution_fields: list[tuple[str, Any]],
    successful_response: bool,
    normalized_event: dict[str, Any] | None = None,
    business_context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Compatibility wrapper for the business-aware scene generator.

    The old keyword-only implementation is retained below only as a source
    compatibility reference for older callers; the production analysis path
    always supplies normalized event and business context and returns here.
    """
    if normalized_event is not None and business_context is not None:
        return generate_scene_candidates(
            normalized_event,
            business_context,
            business_context.get("direct_evidence", []),
            business_context.get("negative_evidence", []),
            alert,
        )["candidates"]
    """Generate a small, evidence-backed candidate set before choosing a primary."""
    behavior_rows = [
        (path, value)
        for path, value in _flatten(alert)
        if _path_key(path)
        not in {"name", "rulename", "alertname", "ruletitle", "threattype", "risklevel"}
        and _has_value(value)
    ]
    behavior_text = " ".join(
        f"{path} {_short(value)}" for path, value in behavior_rows
    ).lower()
    candidates: list[dict[str, Any]] = []

    def add(
        name: str,
        support: list[str],
        contrary: list[str],
        missing: list[str],
        confidence: str,
    ) -> None:
        if not support:
            return
        candidates.append(
            {
                "name": name,
                "support": support[:8],
                "contrary": contrary[:8],
                "missing": missing[:8],
                "confidence": confidence,
            }
        )

    sql_signals = ("union select", "sql 注入", "sql injection", "sql syntax", "select ")
    sql_support = [
        path
        for path, value in behavior_rows
        if _contains_any(f"{path} {_short(value)}", sql_signals)
    ]
    if sql_support:
        add(
            "疑似 SQL 注入或数据库查询操纵",
            sql_support,
            [
                path
                for path, value in response_fields
                if _contains_any(_short(value), ("invalid", "错误", "失败"))
            ],
            ["数据库审计/查询日志", "受控复测结果", "接口参数处理代码"],
            "中",
        )

    command_signals = ("cmd.exe", "powershell", "bash -c", "命令执行", "rce", "shell")
    command_support = [
        path
        for path, value in behavior_rows
        if _contains_any(f"{path} {_short(value)}", command_signals)
    ]
    if command_support:
        add(
            "疑似命令执行或危险解释器调用",
            command_support,
            [],
            ["进程树/子进程", "EDR 或系统调用日志", "异常出站连接"],
            "中",
        )

    xss_signals = ("<script", "javascript:", "onerror=", "xss")
    xss_support = [
        path
        for path, value in behavior_rows
        if _contains_any(f"{path} {_short(value)}", xss_signals)
    ]
    if xss_support:
        add(
            "疑似跨站脚本或不安全内容渲染",
            xss_support,
            [],
            ["浏览器渲染/CSP", "持久化存储记录", "受控回放"],
            "中",
        )

    auth_support = [path for path, _ in auth_fields]
    if auth_support or _contains_any(
        behavior_text, ("login", "登录", "password spray", "爆破", "认证")
    ):
        add(
            "疑似身份认证异常或凭据攻击",
            auth_support or [path for path, _ in request_fields],
            [
                path
                for path, value in response_fields
                if _contains_any(
                    _short(value), ("invalid password", "登录失败", "unauthorized")
                )
            ],
            ["认证成功/失败日志", "MFA 与 Session 记录", "账号后续行为"],
            "中" if auth_support else "低",
        )

    if sensitive_response and successful_response:
        add(
            "疑似敏感信息泄露或访问控制缺陷",
            [path for path, _ in sensitive_response]
            + [path for path, _ in response_fields],
            [],
            ["身份主体与资源归属", "服务端权限决策", "数据访问/外传审计"],
            "中",
        )

    file_support = [
        path
        for path, value in behavior_rows
        if _contains_any(
            path, ("file", "sample", "process", "hash", "sha256", "malware")
        )
        and _has_value(value)
    ]
    if file_support:
        add(
            "疑似恶意文件或主机异常行为",
            file_support,
            [],
            ["文件落盘与来源", "执行状态/进程树", "EDR 与主机网络日志"],
            "中",
        )

    if not candidates:
        fallback_support = [
            path for path, _ in request_fields + response_fields + execution_fields
        ]
        add(
            "主要场景待确认",
            fallback_support,
            [],
            ["完整请求/响应", "认证与资产上下文", "关联日志和受控验证"],
            "低",
        )
    # Prefer concrete exploit semantics over generic auth/data context, then
    # preserve evidence density. This is ranking, not a conclusion from a rule name.
    priority = {
        "疑似 SQL 注入或数据库查询操纵": 5,
        "疑似命令执行或危险解释器调用": 5,
        "疑似跨站脚本或不安全内容渲染": 5,
        "疑似敏感信息泄露或访问控制缺陷": 4,
        "疑似身份认证异常或凭据攻击": 3,
        "疑似恶意文件或主机异常行为": 3,
    }
    candidates.sort(
        key=lambda item: (-priority.get(item["name"], 1), -len(item["support"]))
    )
    return candidates[:3]


def _candidate_scenarios(
    alert: dict[str, Any],
    request_fields: list[tuple[str, Any]],
    response_fields: list[tuple[str, Any]],
    auth_fields: list[tuple[str, Any]],
    sensitive_response: list[tuple[str, Any]],
    execution_fields: list[tuple[str, Any]],
    successful_response: bool,
    normalized_event: dict[str, Any] | None = None,
    business_context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Generate candidates from normalized facts and business context.

    The positional arguments are retained for callers compiled against the old
    helper; they are intentionally not used to classify the event.
    """
    del request_fields, response_fields, auth_fields, sensitive_response, execution_fields, successful_response
    normalized = normalized_event or normalize_alert(alert)
    context = business_context or infer_business_context(normalized, alert)
    return generate_scene_candidates(
        normalized,
        context,
        context.get("direct_evidence", []),
        context.get("negative_evidence", []),
        alert,
    )["candidates"]


def _dynamic_core_chain(
    classification: str, layers: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_id = {item["id"]: item for item in layers}

    def node(stage: str, layer_ids: tuple[str, ...]) -> dict[str, Any]:
        selected = [by_id[layer_id] for layer_id in layer_ids if layer_id in by_id]
        statuses = [item.get("status", "❌ 缺失") for item in selected]
        status = (
            "✅ 已覆盖"
            if selected and all(item == "✅ 已覆盖" for item in statuses)
            else "⚡ 存在冲突"
            if any(item == "⚡ 存在冲突" for item in statuses)
            else "⚠️ 部分覆盖"
            if any(item != "❌ 缺失" for item in statuses)
            else "❌ 缺失"
        )
        return {
            "stage": stage,
            "status": status,
            "evidence": [
                source for item in selected for source in item.get("evidence", [])
            ][:8],
        }

    if "认证" in classification or "凭据" in classification:
        stages = (
            ("认证请求", ("request_sent",)),
            ("凭据/认证信息", ("auth_observed",)),
            ("认证结果", ("valid_business_response", "server_processed")),
            ("Token/Session", ("auth_observed",)),
            ("后续访问", ("further_exploitation", "business_impact")),
        )
    elif "文件" in classification or "主机" in classification:
        stages = (
            ("文件进入/落盘", ("request_sent",)),
            ("Hash/样本身份", ("sensitive_exposure",)),
            ("执行状态", ("server_processed", "valid_business_response")),
            ("进程与主机行为", ("further_exploitation",)),
            ("网络连接/传播", ("further_exploitation", "business_impact")),
        )
    elif "命令执行" in classification:
        stages = (
            ("输入与命令语义", ("request_sent",)),
            ("解释器调用", ("server_processed",)),
            ("子进程/执行结果", ("valid_business_response", "vulnerability")),
            ("后续行为", ("further_exploitation",)),
        )
    elif "敏感信息" in classification or "数据" in classification:
        stages = (
            ("敏感数据", ("sensitive_exposure",)),
            ("读取/访问主体", ("auth_observed", "authorization")),
            ("传输/返回", ("valid_business_response",)),
            ("外传目标", ("further_exploitation",)),
            ("影响范围", ("business_impact",)),
        )
    else:
        stages = (
            ("来源与目标", ("request_sent",)),
            ("请求/输入", ("request_sent",)),
            ("服务器处理", ("server_processed",)),
            ("响应与结果", ("valid_business_response", "sensitive_exposure")),
            ("后续行为与影响", ("further_exploitation", "business_impact")),
        )
    return [node(stage, ids) for stage, ids in stages]


def assess_event_layers(arguments: dict[str, Any]) -> dict[str, Any]:
    """Separate direct facts, reasonable inferences, and nine event proof layers."""
    alert = _alert(arguments)
    normalized_event = arguments.get("normalized_event")
    if not isinstance(normalized_event, dict):
        normalized_event = normalize_alert(alert)
    business_context = arguments.get("business_context")
    if not isinstance(business_context, dict):
        business_context = infer_business_context(normalized_event, alert)
    scene_result = arguments.get("scene_result")
    if not isinstance(scene_result, dict):
        scene_result = generate_scene_candidates(
            normalized_event,
            business_context,
            business_context.get("direct_evidence", []),
            business_context.get("negative_evidence", []),
            alert,
        )
    selected_scene = select_primary_scene(scene_result)
    facts: list[dict[str, str]] = []
    factual_tokens = (
        "url",
        "method",
        "requesthead",
        "requestbody",
        "responsehead",
        "responsebody",
        "status",
        "srcip",
        "sourceip",
        "dstip",
        "targetip",
        "authorization",
        "authentication",
        "cookie",
        "session",
        "dbexecstatus",
        "dbaffectrows",
    )
    for path, value in _flatten(alert):
        key = _path_key(path)
        if _has_value(value) and any(token in key for token in factual_tokens):
            display = (
                "[敏感语义值不在报告重复呈现]"
                if _contains_any(f"{path} {_short(value)}", SENSITIVE_TERMS)
                else _short(value)
            )
            facts.append(
                {
                    "category": "原始字段事实",
                    "statement": f"告警字段包含 {key}：{display}",
                    "source": path,
                }
            )
    request_fields = _paths_matching(
        alert, ("url", "requesthead", "requestbody", "method", "query", "path")
    )
    response_fields = _paths_matching(
        alert, ("responsehead", "responsebody", "status", "statuscode", "httpstatus")
    )
    response_body_fields = _paths_matching(
        alert, ("responsebody", "response_data", "responsecontent")
    )
    auth_fields = _paths_matching(
        alert,
        ("authorization", "authentication", "cookie", "session", "token", "authstatus"),
    )
    normalized_auth = normalized_event.get("authorization", {})
    if not auth_fields and normalized_auth.get("present"):
        # A complete requestHead is often stored as one raw HTTP string, so
        # the Authorization header is not present in the flattened raw path.
        # Preserve the normalized fact in the legacy nine-layer assessment to
        # prevent a report from saying both "observed" and "missing".
        auth_fields = [("normalized.authorization", normalized_auth)]
    execution_fields = _paths_matching(
        alert, ("execstatus", "affectrows", "action", "result", "success")
    )
    execution_fields = [
        item for item in execution_fields if _is_applicable_path(item[0], normalized_event)
    ]
    sensitive_response = [
        (path, value)
        for path, value in _flatten(alert)
        if _has_value(value)
        and "response" in path.lower()
        and _contains_any(f"{path} {_short(value)}", SENSITIVE_TERMS)
    ]
    # A token/session returned by a successful login is a normal business
    # result, not data-exposure evidence.  It becomes exposure evidence only
    # when the business-context stage found an abnormal recipient/transport.
    if (
        business_context.get("action") == "authentication"
        and business_context.get("normal_behavior_assessment") == "normal_business_consistent"
        and not business_context.get("token_leak_signal")
    ):
        sensitive_response = [
            (path, value)
            for path, value in sensitive_response
            if not any(
                token in _path_key(path)
                for token in ("token", "session", "access", "id_token")
            )
        ]
    status_values = [
        (path, value)
        for path, value in response_fields
        if any(
            _path_key(path).endswith(token)
            for token in ("status", "statuscode", "httpstatus", "responsecode")
        )
    ]
    # Parse the protocol status line when the source did not normalize it into a
    # separate status field.
    for path, value in response_fields:
        if isinstance(value, str):
            match = HTTP_STATUS_PATTERN.search(value)
            if match:
                status_values.append(
                    (f"{path} [HTTP status line]", int(match.group(1)))
                )
    successful_response = any(
        _is_successful_status(value) for _, value in status_values
    )
    response_indicates_error = any(
        _contains_any(
            _short(value),
            (
                "error",
                "failed",
                "failure",
                "exception",
                "invalid",
                "错误",
                "失败",
                "异常",
                "拒绝",
                "denied",
            ),
        )
        for _, value in response_body_fields
    )
    # An authentication failure message such as ``invalid password`` is not
    # evidence that a password was returned. Keep sensitive response evidence
    # only when the response field itself is sensitive (for example
    # ``responseBody.passwordHash``), or when there is no explicit error
    # signal. This prevents candidate ranking from turning a failed login into
    # a data-exposure incident merely because the word "password" appears in
    # the error text.
    if response_indicates_error:
        sensitive_response = [
            (path, value)
            for path, value in sensitive_response
            if any(
                token in _path_key(path)
                for token in (
                    "password",
                    "passwd",
                    "secret",
                    "token",
                    "credential",
                    "privatekey",
                    "hash",
                )
            )
        ]
    business_status_fields = [
        (path, value)
        for path, value in _flatten(alert)
        if _is_applicable_path(path, normalized_event)
        if any(
            token in _path_key(path)
            for token in (
                "businessstatus",
                "businesscode",
                "status_code",
                "loginstatus",
                "success",
            )
        )
    ]
    business_success = any(
        _is_successful_status(value)
        or str(value).strip().lower() in {"true", "success", "succeeded", "成功"}
        for _, value in business_status_fields
    )
    invalid_auth_fields = [
        (path, value)
        for path, value in auth_fields
        if _contains_any(
            str(value),
            ("bearer null", "bearer undefined", "expired", "invalid", "过期", "无效"),
        )
    ]
    explicit_bypass = [
        (path, value)
        for path, value in _paths_matching(
            alert, ("authbypass", "authorizationbypass", "unauthorizedaccess")
        )
        if str(value).strip().lower() in {"true", "1", "yes", "bypassed", "confirmed"}
    ]
    explicit_denial = [
        (path, value)
        for path, value in auth_fields + status_values
        if _contains_any(
            str(value),
            ("unauthorized", "forbidden", "未授权", "权限不足", "401", "403"),
        )
    ]
    exploitation_fields = _paths_matching(
        alert,
        ("exfil", "lateral", "persistence", "postexploit", "commandexec", "download"),
    )
    impact_fields = _paths_matching(
        alert,
        (
            "businessimpact",
            "affected",
            "dataleak",
            "exfil",
            "compromise",
            "impact",
            "accountchange",
            "datamodif",
        ),
    )
    semantic_conflicts = _semantic_conflicts(alert, sensitive_response)
    candidates = _candidate_scenarios(
        alert,
        request_fields,
        response_fields,
        auth_fields,
        sensitive_response,
        execution_fields,
        successful_response,
        normalized_event=normalized_event,
        business_context=business_context,
    )

    layers = [
        _layer(
            "request_sent",
            "请求是否成功发送？",
            "✅ 已覆盖"
            if successful_response
            else "⚠️ 部分覆盖"
            if request_fields
            else "❌ 缺失",
            "服务端返回有效 2xx 响应，可确认记录中的请求已送达服务器；不证明请求者授权或漏洞成立。"
            if successful_response
            else "告警仅含请求表征，仍需访问或网关日志确认请求是否送达。"
            if request_fields
            else "未提供请求地址、方法、头或载荷，无法确认请求是否发送。",
            [path for path, _ in request_fields + status_values],
        ),
        _layer(
            "server_processed",
            "服务器是否成功处理？",
            "✅ 已覆盖"
            if successful_response
            else "⚠️ 部分覆盖"
            if response_fields
            else "❌ 缺失",
            "响应状态为 2xx，可确认服务器返回成功状态；业务处理语义仍需结合响应体和应用日志。"
            if successful_response
            else "存在响应字段，但没有有效 2xx 状态可确认成功处理。"
            if response_fields
            else "未提供响应状态、响应头或响应体。",
            [path for path, _ in status_values or response_fields],
        ),
        _layer(
            "valid_business_response",
            "服务器是否返回有效业务响应？",
            "✅ 已覆盖"
            if successful_response
            and response_body_fields
            and (business_success or not business_status_fields)
            and not response_indicates_error
            else "⚠️ 部分覆盖"
            if successful_response or response_body_fields
            else "❌ 缺失",
            "2xx 响应并包含响应体，可确认服务端返回了可见业务结果；不据此判断其内容是否按权限应当返回。"
            if successful_response
            and response_body_fields
            and (business_success or not business_status_fields)
            and not response_indicates_error
            else "响应体含有错误、失败或异常语义；即使 HTTP 为 2xx，也不能据此确认有效业务处理。"
            if successful_response and response_body_fields and response_indicates_error
            else "仅见成功状态或响应体之一，需以完整响应、应用访问日志确认业务返回语义。"
            if successful_response or response_body_fields
            else "缺少可判断业务返回的状态和响应体证据。",
            [path for path, _ in status_values + response_body_fields],
        ),
        _layer(
            "sensitive_exposure",
            "敏感信息、数据或功能是否实际暴露？",
            "✅ 已覆盖"
            if sensitive_response
            else "⚠️ 部分覆盖"
            if response_fields
            else "❌ 缺失",
            "响应字段直接出现敏感数据语义，可确认服务器返回了该类敏感内容；这不能单独证明请求者未授权或数据已被外传。"
            if sensitive_response
            else "存在响应证据，但未见可直接确认的敏感数据、敏感功能结果或数据量。"
            if response_fields
            else "缺少响应和数据结果证据。",
            [path for path, _ in sensitive_response]
            or [path for path, _ in response_fields],
        ),
        _layer(
            "auth_observed",
            "请求中是否观察到认证或会话信息？",
            "✅ 已覆盖" if auth_fields else "❌ 缺失",
            "原始请求/告警字段包含认证、Cookie、Session 或令牌上下文；字段形式存在不等同于认证成功，当前值还需校验有效期与服务端验证结果。"
            if auth_fields and not invalid_auth_fields
            else "观察到认证字段形式，但其中包含 null、过期或无效语义；不能据此确认认证成功。"
            if invalid_auth_fields
            else "未观察到认证、Cookie、Session 或令牌字段；缺失字段不能证明请求者未认证。",
            [path for path, _ in auth_fields],
        ),
        _layer(
            "authorization",
            "是否能够确认请求者缺少合法授权？",
            "✅ 已覆盖"
            if explicit_bypass
            else "⚠️ 部分覆盖"
            if explicit_denial or auth_fields
            else "❌ 缺失",
            "存在明确的授权绕过或未授权访问结果字段，仍应结合服务端会话和权限决策日志复核。"
            if explicit_bypass
            else "存在认证/授权字段或拒绝结果，但不能据此确认成功访问请求者缺少合法授权。"
            if explicit_denial or auth_fields
            else "未提供认证、Session、网关鉴权或服务端权限决策证据；缺失 Authorization 不能证明未认证。",
            [path for path, _ in explicit_bypass or explicit_denial or auth_fields],
        ),
        _layer(
            "vulnerability",
            "是否能够确认漏洞成立？",
            "✅ 已覆盖"
            if explicit_bypass and (sensitive_response or execution_fields)
            else "⚠️ 部分覆盖"
            if successful_response and (sensitive_response or execution_fields)
            else "❌ 缺失",
            "明确绕过字段与可见敏感/执行结果同时存在，形成较强漏洞成立线索；仍应通过受控复测、授权模型和资源归属确认。"
            if explicit_bypass and (sensitive_response or execution_fields)
            else "成功响应与敏感/执行线索只能构成疑似漏洞证据，不能替代授权判断或受控复测。"
            if successful_response and (sensitive_response or execution_fields)
            else "当前字段不足以确认漏洞成因或可重复利用条件。",
            [
                path
                for path, _ in explicit_bypass
                + sensitive_response
                + execution_fields
                + status_values
            ],
        ),
        _layer(
            "further_exploitation",
            "是否发现攻击者进一步利用漏洞？",
            "✅ 已覆盖" if exploitation_fields else "❌ 缺失",
            "告警存在外传、横向、持久化、后续命令或下载字段，需按时间线和资产日志核验其真实性与范围。"
            if exploitation_fields
            else "未提供横向移动、持久化、外传、后续命令或关联账号行为证据。",
            [path for path, _ in exploitation_fields],
        ),
        _layer(
            "business_impact",
            "是否已经造成业务、账号、数据或资产影响？",
            "✅ 已覆盖"
            if impact_fields and (sensitive_response or exploitation_fields)
            else "⚠️ 部分覆盖"
            if impact_fields or sensitive_response
            else "❌ 缺失",
            "当前字段同时存在影响线索和敏感返回/后续利用线索，仍需业务、账号和数据审计形成影响闭环。"
            if impact_fields and (sensitive_response or exploitation_fields)
            else "存在数据或影响线索，但没有足以确认实际业务、账号或资产影响的闭环证据。"
            if impact_fields or sensitive_response
            else "未提供业务、账号、数据或资产影响证据。",
            [
                path
                for path, _ in impact_fields + sensitive_response + exploitation_fields
            ],
        ),
    ]
    inferences = [
        {"statement": layer["conclusion"], "sources": layer["evidence"]}
        for layer in layers
        if layer["status"] != "❌ 缺失"
    ]
    unknowns = [
        {"question": layer["question"], "reason": layer["conclusion"]}
        for layer in layers
        if layer["status"] != "✅ 已覆盖"
    ]
    candidates = scene_result.get("candidates", candidates)
    primary_candidate = selected_scene or (
        candidates[0]
        if candidates
        else {
            "name": "主要场景待确认",
            "scene_id": "generic",
            "confidence": "低",
            "support": [],
            "contradictions": [],
            "contrary": [],
            "missing": [],
        }
    )
    classification = primary_candidate["name"]
    core_chain = _dynamic_core_chain(classification, layers)
    return {
        "classification": classification,
        "classification_confidence": primary_candidate.get("confidence", "低"),
        "primary_scenario": primary_candidate,
        "candidate_scenarios": candidates,
        "selected_scene": primary_candidate,
        "scene_id": primary_candidate.get("scene_id", "generic"),
        "normalized_event": normalized_event,
        "business_context": business_context,
        "evidence_template": primary_candidate.get("evidence_template", []),
        "facts": facts[:24],
        "layers": layers,
        "inferences": inferences,
        "unknowns": unknowns,
        "semantic_conflicts": semantic_conflicts,
        "core_chain": core_chain,
    }


def _layer_by_id(assessment: dict[str, Any], layer_id: str) -> dict[str, Any]:
    return next(
        (item for item in assessment.get("layers", []) if item.get("id") == layer_id),
        {"status": "❌ 缺失", "evidence": [], "conclusion": "未生成该层级证据"},
    )


def evidence_matrix(arguments: dict[str, Any]) -> dict[str, Any]:
    alert = _alert(arguments)
    assessment = arguments.get("event_assessment")
    if not isinstance(assessment, dict):
        assessment = assess_event_layers({"alert": alert})
    timeline = arguments.get("timeline")
    if not isinstance(timeline, dict):
        timeline = build_timeline({"alert": alert})
    evidence_store = arguments.get("evidence_store")
    evidence_items = evidence_store.get("items", []) if isinstance(evidence_store, dict) else []

    def evidence_ids(sources: list[str]) -> list[str]:
        ids: list[str] = []
        for item in evidence_items:
            source_path = str(item.get("source_path", ""))
            if any(source_path == source or source.endswith(source_path) or source_path.endswith(source) for source in sources):
                ids.append(str(item.get("evidence_id")))
        return list(dict.fromkeys(ids))
    mapping = (
        ("请求证据", "request_sent"),
        ("服务器处理", "server_processed"),
        ("有效业务响应", "valid_business_response"),
        ("认证信息观察", "auth_observed"),
        ("认证与授权", "authorization"),
        ("敏感数据/执行结果", "sensitive_exposure"),
        ("漏洞成立条件", "vulnerability"),
        ("后续利用与影响", "further_exploitation"),
        ("业务/资产影响", "business_impact"),
    )
    rows = []
    for label, layer_id in mapping:
        layer = _layer_by_id(assessment, layer_id)
        rows.append(
            {
                "label": label,
                "status": layer["status"],
                "fields": [
                    source.removeprefix("alert.") for source in layer["evidence"]
                ],
                "source": ", ".join(layer["evidence"]) or "-",
                "evidence_ids": evidence_ids(layer["evidence"]),
                "meaning": layer["conclusion"],
            }
        )
    rows.append(
        {
            "label": "时间与关联",
            "status": "✅ 已覆盖"
            if timeline.get("total", 0)
            else "⚠️ 部分覆盖"
            if timeline.get("unrecorded")
            else "❌ 缺失",
            "fields": [item["source"] for item in timeline.get("events", [])]
            or [item["source"] for item in timeline.get("unrecorded", [])],
            "source": ", ".join(item["source"] for item in timeline.get("events", []))
            or ", ".join(item["source"] for item in timeline.get("unrecorded", []))
            or "-",
            "meaning": "仅纳入字段语义明确且值有效的时间；0、空值或无效时间戳标记为未记录。",
            "evidence_ids": evidence_ids(
                [item["source"] for item in timeline.get("events", [])]
                + [item["source"] for item in timeline.get("unrecorded", [])]
            ),
        }
    )
    for conflict in assessment.get("semantic_conflicts", []):
        sources = conflict.get("sources", [])
        rows.append(
            {
                "label": f"字段语义冲突：{conflict.get('area', '待核验')}",
                "status": "⚡ 存在冲突",
                "fields": sources,
                "source": ", ".join(sources) or "-",
                "evidence_ids": evidence_ids(sources),
                "meaning": conflict.get("detail", "原始字段语义存在待核验矛盾"),
            }
        )
    covered = sum(1 for row in rows if row["status"] == "✅ 已覆盖")
    partial = sum(1 for row in rows if row["status"] == "⚠️ 部分覆盖")
    conflicts = sum(1 for row in rows if row["status"] == "⚡ 存在冲突")
    missing = len(rows) - covered - partial - conflicts
    coverage = round((covered + partial * 0.5) / len(rows) * 100)
    return {
        "rows": rows,
        "coverage": coverage,
        "covered": covered,
        "partial": partial,
        "missing": missing,
        "conflicts": conflicts,
        "field_applicability": assessment.get(
            "business_context", {}
        ).get("field_applicability") or assessment.get("normalized_event", {}).get(
            "field_applicability", {}
        ),
        "evidence_store_bound": bool(evidence_items),
    }


def _legacy_calculate_risk(arguments: dict[str, Any]) -> dict[str, Any]:
    """Return a reproducible observed-risk score and independent evidence confidence."""
    alert = _alert(arguments)
    assessment = arguments.get("event_assessment")
    if not isinstance(assessment, dict):
        assessment = assess_event_layers({"alert": alert})
    evidence = arguments.get("evidence")
    if not isinstance(evidence, dict):
        evidence = evidence_matrix({"alert": alert, "event_assessment": assessment})
    serialized = json.dumps(alert, ensure_ascii=False).lower()
    response_layer = _layer_by_id(assessment, "server_processed")
    sensitive_layer = _layer_by_id(assessment, "sensitive_exposure")
    authorization_layer = _layer_by_id(assessment, "authorization")
    impact_layer = _layer_by_id(assessment, "business_impact")
    exploit_layer = _layer_by_id(assessment, "further_exploitation")
    public_sources = [
        item
        for item in extract_iocs({"alert": alert})["indicators"]
        if item["type"] == "ip" and item["scope"] == "公网"
    ]

    def layer_score(layer: dict[str, Any]) -> int:
        return {
            "✅ 已覆盖": 100,
            "⚠️ 部分覆盖": 50,
            "⚡ 存在冲突": 0,
            "❌ 缺失": 0,
        }.get(layer.get("status", "❌ 缺失"), 0)

    sensitivity = layer_score(sensitive_layer)
    processing = (
        75
        if response_layer.get("status") == "✅ 已覆盖"
        else 50
        if response_layer.get("status") == "⚠️ 部分覆盖"
        else 0
    )
    business_response = layer_score(_layer_by_id(assessment, "valid_business_response"))
    auth_observed = layer_score(_layer_by_id(assessment, "auth_observed"))
    authorization = layer_score(authorization_layer)
    asset_impact = layer_score(impact_layer)
    exploitation = layer_score(exploit_layer)
    exposure = (
        75
        if public_sources
        else 50
        if _contains_any(
            serialized,
            ("union select", "sql injection", "未授权", "unauthorized", "rce", "xss"),
        )
        else 25
    )
    classification = str(assessment.get("classification", ""))
    primary_support = assessment.get("primary_scenario", {}).get("support", [])
    positive_execution = any(
        _has_value(value)
        and _contains_any(path, ("execstatus", "commandexec", "process", "action"))
        for path, value in _flatten(alert)
    )
    if any(
        token in classification for token in ("SQL", "注入", "命令执行", "跨站脚本")
    ):
        components = (
            ("敏感性", 0.30, sensitivity, sensitive_layer),
            ("请求/处理成功度", 0.25, processing, response_layer),
            ("未授权可信度", 0.20, authorization, authorization_layer),
            ("资产与业务影响", 0.15, asset_impact, impact_layer),
            ("威胁暴露", 0.10, exposure, exploit_layer),
        )
        formula = "Risk = 0.30×敏感性 + 0.25×请求/处理成功度 + 0.20×未授权可信度 + 0.15×资产与业务影响 + 0.10×威胁暴露"
    elif "认证" in classification or "凭据" in classification:
        components = (
            ("凭据敏感性", 0.30, sensitivity, sensitive_layer),
            (
                "认证成功程度",
                0.25,
                business_response or auth_observed,
                _layer_by_id(assessment, "valid_business_response"),
            ),
            ("账号重要性", 0.20, asset_impact, impact_layer),
            ("暴露程度", 0.15, exposure, response_layer),
            ("后续行为", 0.10, exploitation, exploit_layer),
        )
        formula = "Risk = 0.30×凭据敏感性 + 0.25×认证成功程度 + 0.20×账号重要性 + 0.15×暴露程度 + 0.10×后续行为"
    elif "敏感信息" in classification or "数据" in classification:
        components = (
            ("数据敏感性", 0.30, sensitivity, sensitive_layer),
            (
                "访问成功程度",
                0.25,
                business_response or processing,
                _layer_by_id(assessment, "valid_business_response"),
            ),
            ("数据规模", 0.15, asset_impact, impact_layer),
            ("外传可信度", 0.20, exploitation, exploit_layer),
            ("业务影响", 0.10, asset_impact, impact_layer),
        )
        formula = "Risk = 0.30×数据敏感性 + 0.25×访问成功程度 + 0.15×数据规模 + 0.20×外传可信度 + 0.10×业务影响"
    elif "文件" in classification or "主机" in classification:
        malicious = 75 if primary_support else 25
        execution = 75 if positive_execution else processing
        components = (
            ("恶意可信度", 0.30, malicious, _layer_by_id(assessment, "vulnerability")),
            ("执行状态", 0.25, execution, response_layer),
            ("主机重要性", 0.20, asset_impact, impact_layer),
            ("传播能力", 0.15, exposure, response_layer),
            ("后续行为", 0.10, exploitation, exploit_layer),
        )
        formula = "Risk = 0.30×恶意可信度 + 0.25×执行状态 + 0.20×主机重要性 + 0.15×传播能力 + 0.10×后续行为"
    else:
        components = (
            ("敏感性", 0.30, sensitivity, sensitive_layer),
            ("请求/处理成功度", 0.25, processing, response_layer),
            ("未授权可信度", 0.20, authorization, authorization_layer),
            ("资产与业务影响", 0.15, asset_impact, impact_layer),
            ("威胁暴露", 0.10, exposure, exploit_layer),
        )
        formula = "Risk = 0.30×敏感性 + 0.25×请求/处理成功度 + 0.20×未授权可信度 + 0.15×资产与业务影响 + 0.10×威胁暴露"
    raw_score = sum(weight * value for _, weight, value, _ in components)
    score = 0 if raw_score == 0 else int(min(100, max(25, 25 * round(raw_score / 25))))
    level = (
        "严重"
        if score == 100
        else "高"
        if score >= 75
        else "中"
        if score >= 50
        else "低"
    )
    direct_layers = sum(
        1 for item in assessment.get("layers", []) if item.get("status") == "✅ 已覆盖"
    )
    confidence_score = round(
        evidence.get("coverage", 0) * 0.75
        + direct_layers / 9 * 25
        - int(evidence.get("conflicts", 0)) * 15
    )
    confidence_score = int(min(100, max(0, 25 * round(confidence_score / 25))))
    confidence_level = (
        "高" if confidence_score >= 75 else "中" if confidence_score >= 50 else "低"
    )
    dimensions = [
        {
            "label": label,
            "value": value,
            "weight": weight,
            "evidence": layer["evidence"],
            "explanation": layer["conclusion"],
            "color": color,
        }
        for (label, weight, value, layer), color in zip(
            components,
            ("#ff6b7a", "#ffb454", "#6f9dff", "#ad7cff", "#51d7bd"),
            strict=True,
        )
    ]
    return {
        "score": score,
        "level": level,
        "confidence_score": confidence_score,
        "confidence_level": confidence_level,
        "dimensions": dimensions,
        "formula": formula,
        "method": "每个风险维度只取 0/25/50/75/100 固定档位；按固定权重求和后将总分归入最近的 25 分档。研判置信度由有效证据覆盖、九层直接证据和冲突扣减单独计算，不以字段数量替代证据质量。",
        "factors": [
            {
                "source": ", ".join(layer["evidence"]) or "无直接字段",
                "summary": f"{label}：{value}/100，权重 {weight:.2f}；{layer['conclusion']}",
            }
            for label, weight, value, layer in components
        ],
    }


def calculate_risk(arguments: dict[str, Any]) -> dict[str, Any]:
    """Calculate risk from the Router-selected profile.

    The scene fallback is retained only for direct legacy tool callers.  The
    production chain always passes ``router`` and therefore never re-guesses a
    risk profile from report text or keywords.
    """
    alert = _alert(arguments)
    assessment = arguments.get("event_assessment")
    if not isinstance(assessment, dict):
        assessment = assess_event_layers({"alert": alert})
    evidence = arguments.get("evidence")
    if not isinstance(evidence, dict):
        evidence = evidence_matrix({"alert": alert, "event_assessment": assessment})
    selected = assessment.get("selected_scene") or assessment.get("primary_scenario") or {}
    router = arguments.get("router")
    if isinstance(router, dict) and router.get("workflow_id"):
        workflow_id = str(router.get("workflow_id"))
        profile = risk_profile_for_workflow(workflow_id, str(router.get("risk_profile_id") or ""))
        scene_id = str(profile.get("scene_id") or "generic")
        router_selected_scene = str(router.get("selected_scene_id") or "")
    else:
        workflow_id = "legacy_scene_fallback"
        scene_id = str(selected.get("scene_id") or assessment.get("scene_id") or "generic")
        profile = risk_profile_for_scene(scene_id)
        router_selected_scene = scene_id
    normalized = assessment.get("normalized_event") or normalize_alert(alert)

    def layer_score(layer_id: str) -> int:
        return {
            "✅ 已覆盖": 100,
            "⚠️ 部分覆盖": 50,
            "⚡ 存在冲突": 0,
            "❌ 缺失": 0,
        }.get(_layer_by_id(assessment, layer_id).get("status", "❌ 缺失"), 0)

    sensitive = layer_score("sensitive_exposure")
    processing = layer_score("server_processed")
    business_layer = layer_score("valid_business_response")
    authorization = layer_score("authorization")
    asset_impact = layer_score("business_impact")
    exploitation = layer_score("further_exploitation")
    auth_observed = layer_score("auth_observed")
    business_success = normalized.get("business_result", {}).get("success")
    business_outcome = 100 if business_success is True else 0 if business_success is False else business_layer
    behavior = str(normalized.get("behavior_text", ""))
    support = selected.get("support", [])
    public_sources = [
        item
        for item in extract_iocs({"alert": alert})["indicators"]
        if item["type"] == "ip" and item["scope"] == "公网"
    ]
    exposure = 75 if public_sources else 50 if _contains_any(
        behavior.lower(), ("union select", "sql injection", "未授权", "unauthorized", "rce", "xss")
    ) else 25
    execution = 75 if any(
        _has_value(value)
        and _contains_any(path, ("execstatus", "commandexec", "process", "action"))
        for path, value in _flatten(alert)
        if _is_applicable_path(path, normalized)
    ) else 0
    factors = {
        "credential_sensitivity": sensitive or (50 if auth_observed else 0),
        "authentication_outcome": business_outcome or auth_observed,
        "authorization_assurance": authorization,
        "asset_impact": asset_impact,
        "post_auth_behavior": exploitation,
        "data_sensitivity": sensitive,
        "access_success": business_outcome or processing,
        "data_scope": 75 if sensitive else 0,
        "external_transfer": 100 if exploitation else 0,
        "business_impact": asset_impact,
        "processing_success": processing,
        "threat_exposure": exposure,
        "execution_capability": 75 if support else 25,
        "execution_success": execution,
        "payload_capability": 75 if support else 25,
        "rendering_success": business_outcome,
        "session_impact": 75 if normalized.get("authorization", {}).get("present") else 0,
        "malicious_confidence": 75 if support else 25,
        "target_exposure": exposure,
        "scan_confidence": 75 if support else 25,
    }
    layer_for_dimension = {
        "credential_sensitivity": "sensitive_exposure",
        "authentication_outcome": "valid_business_response",
        "authorization_assurance": "authorization",
        "asset_impact": "business_impact",
        "post_auth_behavior": "further_exploitation",
        "data_sensitivity": "sensitive_exposure",
        "access_success": "valid_business_response",
        "data_scope": "sensitive_exposure",
        "external_transfer": "further_exploitation",
        "business_impact": "business_impact",
        "processing_success": "server_processed",
        "threat_exposure": "request_sent",
        "execution_capability": "vulnerability",
        "execution_success": "further_exploitation",
        "payload_capability": "request_sent",
        "rendering_success": "valid_business_response",
        "session_impact": "auth_observed",
        "malicious_confidence": "vulnerability",
        "target_exposure": "request_sent",
        "scan_confidence": "request_sent",
    }
    dimensions: list[dict[str, Any]] = []
    colors = ("#ff6b7a", "#ffb454", "#6f9dff", "#ad7cff", "#51d7bd")
    for index, item in enumerate(profile["dimensions"]):
        key = item["key"]
        layer = _layer_by_id(assessment, layer_for_dimension.get(key, "request_sent"))
        value = int(factors.get(key, 0))
        dimensions.append(
            {
                "key": key,
                "label": item["label"],
                "value": value,
                "weight": item["weight"],
                "evidence": layer.get("evidence", []),
                "explanation": layer.get("conclusion", "由场景相关证据计算"),
                "color": colors[index % len(colors)],
            }
        )
    raw_score = sum(item["weight"] * item["value"] for item in dimensions)
    score = quantize_score(raw_score)
    direct_layers = sum(
        1 for item in assessment.get("layers", []) if item.get("status") == "✅ 已覆盖"
    )
    confidence_score = round(
        float(evidence.get("coverage", 0)) * 0.75
        + direct_layers / 9 * 25
        - int(evidence.get("conflicts", 0)) * 15
    )
    confidence_score = int(min(100, max(0, 25 * round(confidence_score / 25))))
    confidence_level = "高" if confidence_score >= 75 else "中" if confidence_score >= 50 else "低"
    return {
        "scene_id": profile["scene_id"],
        "risk_profile": profile,
        "score": score,
        "level": risk_level(score),
        "confidence_score": confidence_score,
        "confidence_level": confidence_level,
        "dimensions": dimensions,
        "formula": profile["formula"],
        "risk_profile_id": profile.get("risk_profile_id", f"{scene_id.upper()}_RISK"),
        "workflow_id": workflow_id,
        "router_selected_scene_id": router_selected_scene,
        "method": "生产链路先使用 Router 选择的 risk_profile_id；风险表示事件成立时的严重程度，置信度单独由有效证据覆盖、直接证据和冲突计算。直接调用工具时才允许使用兼容性 scene fallback。",
        "factors": [
            {
                "source": ", ".join(item["evidence"]) or "无直接字段",
                "summary": f"{item['label']}：{item['value']}/100，权重 {item['weight']:.2f}；{item['explanation']}",
            }
            for item in dimensions
        ],
    }


def detect_contradictions(arguments: dict[str, Any]) -> dict[str, Any]:
    """Detect contradictions between independently produced, structured Agent outputs."""
    assessment = arguments.get("event_assessment") or {}
    timeline = arguments.get("timeline") or {}
    evidence = arguments.get("evidence") or {}
    risk = arguments.get("risk") or {}
    conflicts: list[dict[str, Any]] = list(assessment.get("semantic_conflicts", []))
    timeline_row = next(
        (row for row in evidence.get("rows", []) if row.get("label") == "时间与关联"),
        None,
    )
    if (
        timeline_row
        and timeline_row.get("status") == "❌ 缺失"
        and timeline.get("total", 0)
    ):
        conflicts.append(
            {
                "area": "时间线",
                "detail": "证据矩阵标记时间缺失，但时间线工具返回了有效事件。",
                "resolution": "重新核验时间字段语义和有效性，以原始字段路径为准。",
            }
        )
    response = _layer_by_id(assessment, "server_processed")
    response_row = next(
        (row for row in evidence.get("rows", []) if row.get("label") == "服务器处理"),
        None,
    )
    if response_row and response_row.get("status") != response.get("status"):
        conflicts.append(
            {
                "area": "服务器处理",
                "detail": "事件层级与证据矩阵对服务器响应的覆盖状态不一致。",
                "resolution": "以 response 状态、响应头/体和服务端日志重新确认。",
            }
        )
    for row in evidence.get("rows", []):
        if row.get("status") != "⚡ 存在冲突":
            continue
        area = str(row.get("label", "字段语义冲突")).removeprefix("字段语义冲突：")
        if any(item.get("area") == area for item in conflicts):
            continue
        conflicts.append(
            {
                "area": area,
                "detail": str(row.get("meaning", "证据矩阵标记原始字段语义冲突。")),
                "resolution": "回到原始字段、采集链路和关联日志重新判定；冲突不能计入有效证据覆盖。",
                "sources": row.get("fields", []),
            }
        )
    if risk.get("confidence_level") == "高" and evidence.get("coverage", 0) < 60:
        conflicts.append(
            {
                "area": "研判置信度",
                "detail": "低有效证据覆盖与高置信度不一致。",
                "resolution": "降低置信度或补充关键证据后再输出结论。",
            }
        )
    return {
        "conflicts": conflicts,
        "consistent": not conflicts,
        "summary": "未发现结构化输出矛盾"
        if not conflicts
        else f"发现 {len(conflicts)} 项待复核矛盾",
    }


def search_knowledge(arguments: dict[str, Any]) -> dict[str, Any]:
    query = str(arguments.get("query", "")).strip()
    if not query:
        query = "当前安全场景待确认 证据核验 处置 修复 验证"
    if not query.strip():
        query = "安全告警 证据核验 处置"
    limit = max(1, min(int(arguments.get("limit", 6)), 12))
    # Chroma returns a relevance score.  It is suitable for ranking retrieval
    # candidates, not for proving the current incident.  The gate avoids a fixed
    # "always return six" template when no fragment is meaningfully related.
    threshold = max(0.0, min(float(arguments.get("min_relevance", 0.05)), 1.0))
    candidates = get_knowledge_service().search(query, min(12, max(limit * 2, limit)))
    query_tokens = {token.lower() for token in re.findall(r"[\w\u4e00-\u9fff]+", query) if len(token) > 1}
    ranked: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in candidates:
        chunk_id = str(item.get("chunk_id") or item.get("title") or "")
        if chunk_id in seen:
            continue
        seen.add(chunk_id)
        excerpt = str(item.get("excerpt", "")).lower()
        lexical = sum(1 for token in query_tokens if token in excerpt)
        rerank_score = min(1.0, float(item.get("score", 0)) + min(0.08, lexical * 0.01))
        if rerank_score < threshold:
            continue
        ranked.append(
            {
                **item,
                "score": round(rerank_score, 6),
                "score_label": "检索相关度（场景相关重排，仅用于排序，非事件证据）",
                "scene_relevance": round(min(1.0, float(item.get("score", 0)) + (0.05 if lexical else 0)), 3),
            }
        )
    results = sorted(ranked, key=lambda item: (-float(item["score"]), item["title"]))[:limit]
    return {
        "query": query,
        "results": results,
        "total": len(results),
        "candidate_total": len(candidates),
        "quality_gate": {
            "metric": "Chroma relevance score",
            "min_relevance": threshold,
            "deduplicated": True,
            "reranked": True,
            "scene_relevance_filter": arguments.get("scene_id") or "query-driven",
            "workflow_filter": arguments.get("workflow_id") or "generic_workflow",
            "risk_profile_id": arguments.get("risk_profile_id") or "GENERIC_RISK",
            "note": "只保留达到相关度门槛且通过去重/场景相关重排的片段；无高质量结果时允许返回 0 条。知识仅支持调查方法与建议，不构成本次事件证据。",
        },
    }


def _first_present(alert: dict[str, Any], names: tuple[str, ...]) -> tuple[Any, str]:
    for name in names:
        value = alert.get(name)
        if value not in (None, "", [], {}):
            return value, f"alert.{name}"
    return "待确认", "-"


def _legacy_improvement_profile(
    alert: dict[str, Any], event_assessment: dict[str, Any] | None = None
) -> dict[str, str]:
    serialized = _behavior_serialized(alert)
    classification = str((event_assessment or {}).get("classification", ""))
    if "访问控制" in classification or "敏感信息暴露" in classification:
        return {
            "scenario": classification,
            "root_cause": "确认 API 或资源的身份认证、Session 校验、对象级授权和字段级访问控制是否按服务端策略执行。",
            "remediation": "补齐服务端身份认证、Session 与对象级/功能级授权校验；采用最小权限和最小化字段返回，禁止返回密码、凭据或密码 Hash。",
            "detection": "关联 API Gateway/WAF、访问日志、认证与 Session、账号行为和敏感字段响应审计，识别越权与异常枚举。",
            "validation": "用已授权、未授权和越权主体在受控环境验证资源、功能和敏感字段均按预期拒绝或脱敏返回。",
        }
    profiles = (
        (
            ("union select", "sql 注入", "sql injection", "sql syntax"),
            {
                "scenario": "SQL 注入或数据库查询操纵",
                "root_cause": "确认外部输入是否以字符串拼接方式进入数据库查询，以及数据库账号权限是否超出业务所需。",
                "remediation": "对受影响接口采用参数化查询和服务端输入校验，移除动态 SQL 拼接，并收紧数据库账号权限。",
                "detection": "为异常 SQL 关键字、错误响应、同源高频探测和数据库审计失败建立关联检测。",
                "validation": "在隔离或受控环境复现原始特征与合理变体，确认其不再进入数据库执行层。",
            },
        ),
        (
            ("rce", "命令执行", "cmd.exe", "powershell", "bash -c"),
            {
                "scenario": "命令执行或危险解释器调用",
                "root_cause": "确认应用是否将外部输入传递至命令解释器、脚本引擎或危险系统调用。",
                "remediation": "移除命令拼接和解释器调用，采用允许列表参数、最小运行权限和受限执行环境。",
                "detection": "关联 Web 请求、异常进程树、脚本解释器、临时目录和异常 DNS/出站连接。",
                "validation": "在受控环境确认输入无法创建子进程、执行命令或产生异常网络访问。",
            },
        ),
        (
            ("xss", "<script", "javascript:", "onerror="),
            {
                "scenario": "跨站脚本或不安全内容渲染",
                "root_cause": "确认不可信内容是否被持久化或未经上下文编码直接回显到浏览器。",
                "remediation": "在所有输出上下文执行正确编码，避免拼接 HTML/脚本，并逐步部署内容安全策略。",
                "detection": "收集请求/响应样本、CSP 报告、页面渲染链路和异常会话行为。",
                "validation": "在测试环境验证原始与变体载荷均被安全编码且浏览器无脚本执行。",
            },
        ),
        (
            ("brute", "爆破", "password spray", "登录失败", "login failed"),
            {
                "scenario": "凭据攻击或异常认证",
                "root_cause": "确认是否存在弱口令、缺少 MFA、认证速率限制不足或异常会话控制缺失。",
                "remediation": "实施 MFA、认证速率限制、弱口令治理和风险登录策略；处置可疑会话。",
                "detection": "关联失败/成功认证序列、来源网络、设备指纹、MFA 和会话撤销记录。",
                "validation": "验证异常尝试被限速或拦截，且不存在对应的异常成功登录和持久会话。",
            },
        ),
    )
    for signals, profile in profiles:
        if any(signal in serialized for signal in signals):
            return profile
    return {
        "scenario": "待分类安全异常",
        "root_cause": "基于关联日志、资产配置和变更记录确定异常发生条件、暴露面及根本原因。",
        "remediation": "依据经验证的根因实施最小范围修复，并对同类资产进行风险排查和变更验证。",
        "detection": "围绕当前来源、目标、协议、时间范围和 IOC 建立可审计的关联检测与告警升级规则。",
        "validation": "通过独立日志复核、受控测试和观察窗口确认异常不再复发且业务保持正常。",
    }


def _improvement_profile(
    alert: dict[str, Any], event_assessment: dict[str, Any] | None = None
) -> dict[str, str]:
    """Build response guidance from the selected scene and business context."""
    del alert
    assessment = event_assessment or {}
    selected = assessment.get("selected_scene") or assessment.get("primary_scenario") or {}
    scene_id = str(selected.get("scene_id") or assessment.get("scene_id") or "generic")
    scenario = str(selected.get("name") or assessment.get("classification") or "主要场景待确认")
    profiles = {
        "credential_authentication": (
            "确认身份凭据、MFA、认证速率限制、Session 生命周期和账号后续行为。",
            "实施 MFA、认证速率限制、弱凭据治理和风险登录策略；保留正常成功登录路径。",
            "关联失败/成功认证序列、来源网络、设备指纹、MFA 和会话撤销记录。",
            "用正常、失败和异常主体验证认证结果、Session 生命周期和后续访问行为。",
        ),
        "data_exposure": (
            "确认 API/资源的身份认证、Session、对象级授权、字段级访问控制和数据访问审计。",
            "补齐服务端身份认证、Session 与对象级/功能级授权校验；采用最小权限和最小化字段返回。",
            "关联 API Gateway/WAF、访问日志、认证与 Session、账号行为和敏感字段响应审计。",
            "用已授权、未授权和越权主体验证资源、功能和敏感字段均按预期拒绝或脱敏返回。",
        ),
        "injection": (
            "确认外部输入是否进入数据库查询或其他解释器，以及服务端是否产生执行结果。",
            "采用参数化查询或安全 API、输入验证和最小服务权限，排查同类接口。",
            "关联请求特征、应用错误、数据库审计、同源高频探测和受控复测。",
            "在隔离环境回放原始特征与合理变体，确认危险语义不再进入执行层。",
        ),
        "command_execution": (
            "确认输入是否传递至命令解释器、脚本引擎或危险系统调用，并核对进程与出站行为。",
            "移除命令拼接和解释器调用，采用允许列表参数、最小运行权限和受限执行环境。",
            "关联 Web 请求、异常进程树、脚本解释器、临时目录和异常 DNS/出站连接。",
            "在受控环境确认输入无法创建子进程、执行命令或产生异常网络访问。",
        ),
        "xss": (
            "确认不可信内容是否被反射/持久化并未经上下文编码进入浏览器。",
            "在所有输出上下文执行正确编码，避免拼接 HTML/脚本，并部署内容安全策略。",
            "收集请求/响应样本、CSP 报告、页面渲染链路和异常会话行为。",
            "验证原始与变体载荷均被安全编码且浏览器无脚本执行。",
        ),
        "malware_file": (
            "确认文件落盘、样本身份、执行状态、进程树和传播路径。",
            "清理恶意文件和持久化入口，收紧执行权限并补充样本检测。",
            "关联文件、Hash、EDR、进程树和主机网络日志。",
            "验证样本不可执行、不可传播且资产完整性恢复。",
        ),
        "scanning": (
            "确认扫描来源、目标范围、授权窗口、速率和实际访问结果。",
            "完善扫描白名单、速率控制、暴露面治理和检测关联。",
            "关联扫描来源、WAF/API Gateway、目标访问和授权记录。",
            "验证授权扫描可识别，非授权探测被记录且不能绕过边界控制。",
        ),
    }
    root_cause, remediation, detection, validation = profiles.get(
        scene_id,
        (
            "基于关联日志、资产配置和变更记录确定异常发生条件、暴露面及根本原因。",
            "依据经验证的根因实施最小范围修复，并对同类资产进行风险排查和变更验证。",
            "围绕当前来源、目标、协议、时间范围和 IOC 建立可审计的关联检测与告警升级规则。",
            "通过独立日志复核、受控测试和观察窗口确认异常不再复发且业务保持正常。",
        ),
    )
    return {
        "scenario": scenario,
        "root_cause": root_cause,
        "remediation": remediation,
        "detection": detection,
        "validation": validation,
    }


def build_improvement_plan(arguments: dict[str, Any]) -> dict[str, Any]:
    """Create a non-executing response, recovery, and improvement plan."""
    alert = _alert(arguments)
    risk = arguments.get("risk")
    if not isinstance(risk, dict):
        risk = calculate_risk({"alert": alert})
    evidence = arguments.get("evidence")
    if not isinstance(evidence, dict):
        evidence = evidence_matrix({"alert": alert})
    event_assessment = arguments.get("event_assessment")
    if not isinstance(event_assessment, dict):
        event_assessment = assess_event_layers({"alert": alert})
    profile = _improvement_profile(alert, event_assessment)
    router = arguments.get("router") if isinstance(arguments.get("router"), dict) else {}
    workflow = arguments.get("workflow") if isinstance(arguments.get("workflow"), dict) else {}

    asset, asset_source = _first_present(
        alert, ("assetId", "hostname", "targetIp", "dstIp", "service", "application")
    )
    service, service_source = _first_present(
        alert, ("businessService", "service", "application", "system")
    )
    owner, owner_source = _first_present(
        alert, ("assetOwner", "owner", "serviceOwner", "department")
    )
    data, data_source = _first_present(
        alert, ("dataClassification", "dataType", "pii", "dataVolume")
    )
    environment, environment_source = _first_present(
        alert, ("environment", "env", "cloudAccount", "region")
    )

    impact_rows = [
        {
            "area": "受影响资产/入口",
            "current": str(asset),
            "source": asset_source,
            "decision": "确认资产边界、暴露状态和技术负责人",
        },
        {
            "area": "业务服务",
            "current": str(service),
            "source": service_source,
            "decision": "评估服务中断、降级和恢复优先级",
        },
        {
            "area": "数据影响",
            "current": str(data),
            "source": data_source,
            "decision": "确认是否涉及敏感/受监管数据及通知义务",
        },
        {
            "area": "责任归属/协作方",
            "current": str(owner),
            "source": owner_source,
            "decision": "指定业务、应用、资产和安全的决策接口人",
        },
        {
            "area": "运行环境",
            "current": str(environment),
            "source": environment_source,
            "decision": "确定变更窗口、恢复依赖和供应商协作范围",
        },
    ]

    response_actions = [
        {
            "priority": "P0 / 0–4 小时",
            "workstream": "事件指挥与证据保全",
            "action": "指定事件负责人；保全原始告警、易失日志、请求/响应、关联证据和时间范围，不覆盖原始数据。",
            "owner": "SOC 负责人 + 资产/应用负责人",
            "success": "事件编号、证据位置、责任人和下一次状态更新时间均已记录",
        },
        {
            "priority": "P0 / 0–4 小时",
            "workstream": "影响确认",
            "action": f"围绕当前场景“{profile['scenario']}”核验：{profile['root_cause']}",
            "owner": "应用、资产、数据库/平台负责人",
            "success": "已确认或排除攻击成功、影响范围和持续时间",
        },
        {
            "priority": "P1 / 当日",
            "workstream": "受控遏制",
            "action": "根据证据和业务影响，经授权采用最小范围限制、会话处置、访问控制或隔离措施；保留回滚方案。",
            "owner": "SOC + 网络/平台变更负责人",
            "success": "措施命中可验证，未引入不可接受的业务中断",
        },
        {
            "priority": "P1 / 7 天内",
            "workstream": "根因修复与恢复",
            "action": profile["remediation"],
            "owner": "研发/运维/安全工程",
            "success": "修复完成、独立验证通过，恢复资产完整性和业务运行状态已确认",
        },
    ]
    improvements = [
        {
            "horizon": "0–7 天",
            "domain": "根因与安全开发",
            "action": profile["remediation"],
            "owner": "研发负责人 + 安全工程",
            "metric": "原始特征和合理变体的受控复测通过率；同类接口覆盖率",
        },
        {
            "horizon": "0–7 天",
            "domain": "检测与日志",
            "action": profile["detection"],
            "owner": "SOC 工程 + 平台团队",
            "metric": "检测规则覆盖率、关键日志字段完整率、关联查询命中可复核率",
        },
        {
            "horizon": "7–30 天",
            "domain": "资产与权限治理",
            "action": "补齐资产重要性、责任人、数据分级和最小权限基线，并复核暴露面与服务依赖。",
            "owner": "资产负责人 + IAM/平台团队",
            "metric": "关键资产责任人覆盖率、最小权限整改完成率、暴露资产复核率",
        },
        {
            "horizon": "30–90 天",
            "domain": "流程与演练",
            "action": "将本次证据缺口、决策延迟和有效处置纳入预案、检测规则和桌面演练场景。",
            "owner": "安全治理 + 业务连续性负责人",
            "metric": "MTTD、MTTC、MTTR、复盘行动按期完成率和演练问题关闭率",
        },
    ]
    communications = [
        {
            "audience": "事件负责人、SOC 与技术处置团队",
            "trigger": "事件分级后立即",
            "content": "当前证据、风险、待决策事项、责任人、处置状态和下一更新时间",
            "boundary": "仅在授权协作渠道共享必要信息",
        },
        {
            "audience": "业务与资产负责人",
            "trigger": "确认可能影响其服务或拟实施变更前",
            "content": "影响假设、业务风险、变更窗口、回滚条件和恢复验收要求",
            "boundary": "不将未验证推断描述为既成事实",
        },
        {
            "audience": "管理层、法务/合规/隐私与外部协作方",
            "trigger": "发生重大影响、涉及受监管数据或达到组织通知阈值时",
            "content": "经核实的范围、处置进展、决策请求和适用通知评估",
            "boundary": "依据组织政策、合同和适用法规确定通知义务",
        },
    ]
    closure_criteria = [
        "根因和受影响范围已被确认，或不确定性已被明确记录并获风险接受批准。",
        "遏制、修复和恢复动作均有审批、执行记录和独立验证证据。",
        "恢复资产、备份或替代服务已完成完整性检查，关键业务负责人确认运行状态。",
        "在约定观察窗口内未出现与本事件相关的复发信号，检测和日志改进已上线或已有受控计划。",
        "复盘会议、改进事项、责任人和目标日期已记录；经验仅在用户/组织授权范围内沉淀。",
    ]
    roadmap = [
        {
            "time": "0–4 小时",
            "label": "分级、保全与影响确认",
            "source": "事件负责人 / SOC",
        },
        {
            "time": "当日",
            "label": "授权遏制与干系人同步",
            "source": "SOC / 资产与业务负责人",
        },
        {
            "time": "7 天内",
            "label": "根因修复、恢复验证与检测补强",
            "source": "研发 / 平台 / 安全工程",
        },
        {
            "time": "30–90 天",
            "label": "治理改进、复盘与演练",
            "source": "安全治理 / 业务连续性",
        },
    ]
    return {
        "scenario": profile["scenario"],
        "workflow_id": router.get("workflow_id", "generic_workflow"),
        "risk_profile_id": router.get("risk_profile_id", risk.get("risk_profile_id", "GENERIC_RISK")),
        "remediation_profile": workflow.get("remediation_profile", "evidence_preservation_and_contextual_validation"),
        "validation_profile": workflow.get("validation_profile", "independent_log_correlation_and_controlled_replay"),
        "risk_context": f"当前风险 {risk.get('score', 0)}/100（{risk.get('level', '未知')}），证据覆盖 {evidence.get('coverage', 0)}%",
        "impact_rows": impact_rows,
        "response_actions": response_actions,
        "improvements": improvements,
        "communications": communications,
        "closure_criteria": closure_criteria,
        "roadmap": roadmap,
        "boundary": "本计划为建议与待审批事项，不会执行隔离、阻断、恢复、通知或任何系统变更。",
    }


def build_report_charts(arguments: dict[str, Any]) -> dict[str, Any]:
    risk = arguments.get("risk") or {}
    evidence = arguments.get("evidence") or {}
    iocs = arguments.get("iocs") or {}
    timeline = arguments.get("timeline") or {}
    improvement_plan = arguments.get("improvement_plan") or {}
    charts: list[dict[str, Any]] = []
    dimensions = risk.get("dimensions", []) if isinstance(risk, dict) else []
    # A chart is useful only when it carries signal.  Empty/flat dimensions
    # should remain in the Markdown tables without forcing a decorative plot.
    if dimensions and any(int(item.get("value", 0) or 0) > 0 for item in dimensions):
        charts.append(
            {
                "id": "risk-dimensions",
                "type": "bar",
                "title": "风险维度分布",
                "subtitle": "0–100 确定性量化，便于比较风险驱动因素",
                "data": dimensions,
            }
        )
    evidence_values = (
        int(evidence.get("covered", 0) or 0)
        + int(evidence.get("partial", 0) or 0)
        + int(evidence.get("missing", 0) or 0)
        + int(evidence.get("conflicts", 0) or 0)
        if isinstance(evidence, dict)
        else 0
    )
    if isinstance(evidence, dict) and evidence_values > 0:
        charts.append(
            {
                "id": "evidence-coverage",
                "type": "donut",
                "title": "证据覆盖率",
                "subtitle": f"当前覆盖 {evidence.get('coverage', 0)}% 的关键证据组",
                "data": [
                    {
                        "label": "已覆盖",
                        "value": evidence.get("covered", 0),
                        "color": "#51d7bd",
                    },
                    {
                        "label": "部分覆盖",
                        "value": evidence.get("partial", 0),
                        "color": "#ffb454",
                    },
                    {
                        "label": "缺失",
                        "value": evidence.get("missing", 0),
                        "color": "#34445e",
                    },
                    {
                        "label": "存在冲突",
                        "value": evidence.get("conflicts", 0),
                        "color": "#ad7cff",
                    },
                ],
            }
        )
    counts = iocs.get("counts", {}) if isinstance(iocs, dict) else {}
    if counts:
        palette = ("#6f9dff", "#ad7cff", "#ffb454", "#51d7bd", "#ff6b7a")
        charts.append(
            {
                "id": "ioc-distribution",
                "type": "donut",
                "title": "IOC 类型分布",
                "subtitle": f"共识别 {iocs.get('total', 0)} 个去重指标",
                "data": [
                    {
                        "label": label.upper(),
                        "value": value,
                        "color": palette[index % len(palette)],
                    }
                    for index, (label, value) in enumerate(sorted(counts.items()))
                ],
            }
        )
    events = timeline.get("events", []) if isinstance(timeline, dict) else []
    if events:
        charts.append(
            {
                "id": "event-timeline",
                "type": "timeline",
                "title": "事件时间线",
                "subtitle": "仅展示告警中可验证的时间字段",
                "events": events,
            }
        )
    roadmap = (
        improvement_plan.get("roadmap", [])
        if isinstance(improvement_plan, dict)
        else []
    )
    complexity = (
        len(dimensions)
        + evidence_values
        + int(iocs.get("total", 0) or 0)
        + len(events)
        + int(evidence.get("conflicts", 0) or 0)
        if isinstance(evidence, dict)
        else len(dimensions) + int(iocs.get("total", 0) or 0) + len(events)
    )
    if roadmap and (
        int(risk.get("score", 0) or 0) >= 50
        or complexity >= 8
        or int(iocs.get("total", 0) or 0) > 0
        or len(events) > 0
    ):
        charts.append(
            {
                "id": "improvement-roadmap",
                "type": "timeline",
                "title": "响应与能力改进路线图",
                "subtitle": "建议节奏；具体执行需经组织授权与变更审批",
                "events": roadmap,
            }
        )
    return {"charts": charts, "total": len(charts)}


def _normalize_event_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    # The normalizer is itself the redaction boundary: it inspects raw header
    # syntax only long enough to derive scheme/presence/value-state metadata,
    # and its returned object contains no header/body values.  Redacting before
    # this call would destroy useful metadata such as the Bearer scheme.
    alert = arguments.get("alert", arguments)
    if not isinstance(alert, dict):
        raise TypeError("工具参数 alert 必须是 JSON 对象")
    return normalize_alert(alert)


def _business_context_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    normalized = arguments.get("normalized_event")
    if not isinstance(normalized, dict):
        normalized = normalize_alert(_alert(arguments))
    alert = arguments.get("alert")
    return infer_business_context(normalized, alert if isinstance(alert, dict) else None)


def _scene_candidates_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    normalized = arguments.get("normalized_event")
    if not isinstance(normalized, dict):
        normalized = normalize_alert(_alert(arguments))
    context = arguments.get("business_context")
    if not isinstance(context, dict):
        context = infer_business_context(normalized, arguments.get("alert"))
    alert = arguments.get("alert")
    return generate_scene_candidates(
        normalized,
        context,
        context.get("direct_evidence", []),
        context.get("negative_evidence", []),
        alert if isinstance(alert, dict) else None,
    )


def _select_scene_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    scene_result = arguments.get("scene_result")
    if not isinstance(scene_result, dict):
        raise TypeError("select_primary_scene 需要 scene_result 对象")
    return select_primary_scene(scene_result)


def _evidence_store_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    normalized = arguments.get("normalized_event")
    if not isinstance(normalized, dict):
        normalized = normalize_alert(_alert(arguments))
    alert = arguments.get("alert")
    context = arguments.get("business_context")
    return build_evidence_store(
        normalized,
        alert if isinstance(alert, dict) else _alert(arguments),
        context if isinstance(context, dict) else None,
    )


def _security_problem_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    normalized = arguments.get("normalized_event")
    context = arguments.get("business_context")
    evidence_store = arguments.get("evidence_store")
    if not isinstance(normalized, dict) or not isinstance(context, dict) or not isinstance(evidence_store, dict):
        raise TypeError("classify_security_problems 需要 normalized_event、business_context 和 evidence_store")
    return classify_security_problems(
        normalized,
        context,
        evidence_store,
        arguments.get("alert") if isinstance(arguments.get("alert"), dict) else None,
    )


def _workflow_router_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    context = arguments.get("business_context")
    security_result = arguments.get("security_result")
    evidence_store = arguments.get("evidence_store")
    if not isinstance(context, dict) or not isinstance(security_result, dict) or not isinstance(evidence_store, dict):
        raise TypeError("route_workflow 需要 business_context、security_result 和 evidence_store")
    return route_workflow(context, security_result, evidence_store)


def _workflow_evidence_tool(arguments: dict[str, Any]) -> dict[str, Any]:
    route = arguments.get("router")
    store = arguments.get("evidence_store")
    security_result = arguments.get("security_result")
    if not isinstance(route, dict) or not isinstance(store, dict) or not isinstance(security_result, dict):
        raise TypeError("build_workflow_evidence 需要 router、evidence_store 和 security_result")
    return workflow_evidence_result(route, store, security_result)


class AgentToolRegistry:
    def __init__(self) -> None:
        alert_schema = {
            "type": "object",
            "properties": {"alert": {"type": "object"}},
            "required": ["alert"],
        }
        sample_alert = {
            "alert": {
                "name": "SQL 注入攻击",
                "srcIp": ["203.0.113.50"],
                "dstIp": ["10.0.0.20"],
                "url": "/api/search?id=1 UNION SELECT",
                "riskLevel": 3,
            }
        }
        definitions = (
            ToolDefinition(
                "normalize_alert",
                "告警规范化器",
                "解析 HTTP 请求/响应、Header、业务 JSON、认证状态、网络地址和时间字段；不输出敏感原始值。",
                "规范化",
                alert_schema,
                sample_alert,
                _normalize_event_tool,
            ),
            ToolDefinition(
                "infer_business_context",
                "业务上下文推断器",
                "从规范化事件识别独立的业务动作、对象、正常预期、观察偏差和字段适用性；输出可路由 context_id 与数值置信度。",
                "业务语义",
                {
                    "type": "object",
                    "properties": {"alert": {"type": "object"}, "normalized_event": {"type": "object"}},
                },
                sample_alert,
                _business_context_tool,
            ),
            ToolDefinition(
                "build_evidence_store",
                "统一证据存储",
                "为当前事件、嵌入工件和历史引用生成稳定 evidence_id、语义值、适用性与 provenance；安全值不输出原文。",
                "证据",
                {
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "normalized_event": {"type": "object"},
                        "business_context": {"type": "object"},
                    },
                    "required": ["normalized_event"],
                },
                sample_alert,
                _evidence_store_tool,
            ),
            ToolDefinition(
                "classify_security_problems",
                "安全问题分类器",
                "在开放世界候选集上识别安全问题，候选支持必须引用 evidence_id，不能把业务动作、规则名或嵌入日志当作安全结论。",
                "场景",
                {
                    "type": "object",
                    "properties": {
                        "normalized_event": {"type": "object"},
                        "business_context": {"type": "object"},
                        "evidence_store": {"type": "object"},
                        "alert": {"type": "object"},
                    },
                    "required": ["normalized_event", "business_context", "evidence_store"],
                },
                sample_alert,
                _security_problem_tool,
            ),
            ToolDefinition(
                "route_workflow",
                "确定性 Workflow Router",
                "根据业务上下文、安全问题候选、置信度和当前证据覆盖选择 primary/secondary Workflow 与 risk_profile_id，不运行无关流程。",
                "路由",
                {
                    "type": "object",
                    "properties": {
                        "business_context": {"type": "object"},
                        "security_result": {"type": "object"},
                        "evidence_store": {"type": "object"},
                    },
                    "required": ["business_context", "security_result", "evidence_store"],
                },
                sample_alert,
                _workflow_router_tool,
            ),
            ToolDefinition(
                "build_workflow_evidence",
                "场景 Workflow 证据计划",
                "按 Router 选择的 Workflow 返回专用证据 schema、缺口、知识策略、响应和验证策略。",
                "路由",
                {
                    "type": "object",
                    "properties": {
                        "router": {"type": "object"},
                        "evidence_store": {"type": "object"},
                        "security_result": {"type": "object"},
                    },
                    "required": ["router", "evidence_store", "security_result"],
                },
                sample_alert,
                _workflow_evidence_tool,
            ),
            ToolDefinition(
                "generate_scene_candidates",
                "场景候选生成器",
                "以 normalized_event、business_context、正证据和反证生成可解释候选，不把规则名当作行为证据。",
                "场景",
                {
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "normalized_event": {"type": "object"},
                        "business_context": {"type": "object"},
                    },
                },
                sample_alert,
                _scene_candidates_tool,
            ),
            ToolDefinition(
                "select_primary_scene",
                "主场景选择器",
                "根据候选的业务适配度、证据强度、反证和缺失证据选择主场景。",
                "场景",
                {"type": "object", "properties": {"scene_result": {"type": "object"}}, "required": ["scene_result"]},
                {"scene_result": {"candidates": [{"scene_id": "generic", "name": "主要场景待确认"}]}},
                _select_scene_tool,
            ),
            ToolDefinition(
                "assess_event_layers",
                "事件证据分层器",
                "将事实、合理推断和未知项分开，并按九层判断请求、处理、业务响应、敏感暴露、认证观察、授权、漏洞、利用和影响。",
                "证据",
                alert_schema,
                sample_alert,
                assess_event_layers,
            ),
            ToolDefinition(
                "extract_iocs",
                "IOC 提取器",
                "仅在字段语义支持攻击关联时提取 IP、域名、URL、哈希和 CVE，并说明理由、范围与可信度。",
                "证据",
                alert_schema,
                sample_alert,
                extract_iocs,
            ),
            ToolDefinition(
                "extract_security_entities",
                "安全实体语义分类器",
                "先将网络指标、文件/样本、资产、应用、技术栈、敏感数据、身份、漏洞和系统标识符分开，再明确哪些可作为 IOC。",
                "证据",
                alert_schema,
                sample_alert,
                extract_security_entities,
            ),
            ToolDefinition(
                "build_timeline",
                "时间线构建器",
                "只使用语义明确且有效的时间字段；0、空值和无效时间戳标记为未记录，不转换为 1970 年。",
                "证据",
                alert_schema,
                sample_alert,
                build_timeline,
            ),
            ToolDefinition(
                "calculate_risk",
                "风险量化器",
                "按主场景选择公开风险公式，并独立计算研判置信度；每个维度都保留字段路径和权重。",
                "分析",
                alert_schema,
                sample_alert,
                calculate_risk,
            ),
            ToolDefinition(
                "evidence_matrix",
                "证据矩阵",
                "以 ✅ 已覆盖、⚠️ 部分覆盖、❌ 缺失、⚡ 存在冲突评价有效证据；冲突不计入覆盖。",
                "分析",
                alert_schema,
                sample_alert,
                evidence_matrix,
            ),
            ToolDefinition(
                "search_knowledge",
                "本地知识检索",
                "在内置 Chroma 集合中进行只读检索并返回可引用知识片段。",
                "知识",
                {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 12},
                    },
                    "required": ["query"],
                },
                {"query": "SQL 注入 参数化查询 处置", "limit": 6},
                search_knowledge,
            ),
            ToolDefinition(
                "detect_contradictions",
                "结论矛盾检测器",
                "在报告输出前检查时间线、事件层级、证据矩阵和风险置信度之间是否存在结构化矛盾。",
                "复核",
                {
                    "type": "object",
                    "properties": {
                        "event_assessment": {"type": "object"},
                        "timeline": {"type": "object"},
                        "evidence": {"type": "object"},
                        "risk": {"type": "object"},
                    },
                },
                {
                    "timeline": {"events": [], "total": 0},
                    "evidence": {"coverage": 0, "rows": []},
                },
                detect_contradictions,
            ),
            ToolDefinition(
                "build_report_charts",
                "报告图表生成器",
                "把有有效信号的风险、证据、IOC 与时间线结果转换为前端可安全渲染的结构化图表，不强制生成空图。",
                "呈现",
                {
                    "type": "object",
                    "properties": {
                        "risk": {"type": "object"},
                        "evidence": {"type": "object"},
                        "iocs": {"type": "object"},
                        "timeline": {"type": "object"},
                    },
                },
                {
                    "risk": {
                        "score": 78,
                        "dimensions": [{"label": "可利用性", "value": 88}],
                    },
                    "evidence": {"covered": 4, "missing": 2, "coverage": 67},
                    "iocs": {"total": 2, "counts": {"ip": 2}},
                    "timeline": {"events": []},
                },
                build_report_charts,
            ),
            ToolDefinition(
                "build_improvement_plan",
                "响应与改进规划器",
                "基于当前告警、风险和证据缺口生成待审批的响应、恢复、沟通、复盘与能力改进计划。",
                "治理",
                {
                    "type": "object",
                    "properties": {
                        "alert": {"type": "object"},
                        "risk": {"type": "object"},
                        "evidence": {"type": "object"},
                        "event_assessment": {"type": "object"},
                    },
                    "required": ["alert"],
                },
                sample_alert,
                build_improvement_plan,
            ),
        )
        self._tools = {definition.name: definition for definition in definitions}

    def catalog(self) -> list[dict[str, Any]]:
        return [definition.public() for definition in self._tools.values()]

    def execute(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        definition = self._tools.get(name)
        if not definition:
            raise ValueError(f"未知工具：{name}")
        started = time.perf_counter()
        try:
            output = definition.handler(arguments)
        except ToolExecutionError:
            raise
        except Exception as error:
            message = str(redact(str(error)))[:500]
            raise ToolExecutionError(name, type(error).__name__, message) from error
        duration = max(0, round((time.perf_counter() - started) * 1_000, 2))
        return {
            "tool": name,
            "label": definition.label,
            "status": "success",
            "duration_ms": duration,
            "output": output,
        }


tool_registry = AgentToolRegistry()
