from __future__ import annotations

import json
import re
from typing import Any


IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
TIMESTAMP_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
USER_RE = re.compile(r"(?:user(?:name)?|account|src_user|dst_user)[=:]\s*\"?([\w.\-@\\]+)", re.IGNORECASE)
HOST_RE = re.compile(r"(?:host(?:name)?|computer|endpoint|device)[=:]\s*\"?([\w.\-]+)", re.IGNORECASE)
PROC_RE = re.compile(r"(?:process(?:_name)?|image|exe)[=:]\s*\"?([^\",\s]+)", re.IGNORECASE)
EVENT_RE = re.compile(r"(?:event(?:_type)?|action|eventid|event_id)[=:]\s*\"?([\w.\-:/]+)", re.IGNORECASE)


def parse_log_content(content: str) -> list[dict[str, Any]]:
    lines = [line for line in content.splitlines() if line.strip()]
    if not lines and content.strip():
        lines = [content.strip()]
    return [parse_log_line(line) for line in lines]


def parse_log_line(line: str) -> dict[str, Any]:
    raw = line.strip()
    parsed = {
        "timestamp": None,
        "source_ip": None,
        "destination_ip": None,
        "username": None,
        "hostname": None,
        "process_name": None,
        "event_type": None,
        "message": raw,
        "raw_message": raw,
        "parse_error": None,
    }
    try:
        if raw.startswith("{"):
            payload = json.loads(raw)
            parsed.update(_parse_json_payload(payload, raw))
        else:
            parsed.update(_parse_text_payload(raw))
    except Exception as exc:
        parsed["parse_error"] = str(exc)
    return parsed


def _parse_json_payload(payload: dict[str, Any], raw: str) -> dict[str, Any]:
    source_ip = _first(payload, ["source_ip", "src_ip", "src", "client_ip", "SourceIp"])
    destination_ip = _first(payload, ["destination_ip", "dst_ip", "dest_ip", "dst", "DestinationIp"])
    message = _first(payload, ["message", "msg", "description", "event", "raw_message"]) or raw
    return {
        "timestamp": _first(payload, ["timestamp", "@timestamp", "time", "event_time", "TimeCreated"]),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": _first(payload, ["username", "user", "account", "src_user", "UserName"]),
        "hostname": _first(payload, ["hostname", "host", "computer", "device", "Computer"]),
        "process_name": _first(payload, ["process_name", "process", "image", "exe", "NewProcessName"]),
        "event_type": _first(payload, ["event_type", "event_id", "eventid", "action", "category"]),
        "message": str(message),
    }


def _parse_text_payload(raw: str) -> dict[str, Any]:
    ips = IP_RE.findall(raw)
    return {
        "timestamp": _first_match(TIMESTAMP_RE, raw),
        "source_ip": _kv_or_index(raw, ["src_ip", "source_ip", "src"], ips, 0),
        "destination_ip": _kv_or_index(raw, ["dst_ip", "destination_ip", "dest", "dst"], ips, 1),
        "username": _first_match(USER_RE, raw),
        "hostname": _first_match(HOST_RE, raw),
        "process_name": _first_match(PROC_RE, raw),
        "event_type": _first_match(EVENT_RE, raw),
        "message": raw,
    }


def _first(payload: dict[str, Any], keys: list[str]) -> str | None:
    for key in keys:
        value = payload.get(key)
        if value is not None and value != "":
            return str(value)
    return None


def _first_match(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1) if match and match.groups() else (match.group(0) if match else None)


def _kv_or_index(raw: str, keys: list[str], ips: list[str], index: int) -> str | None:
    for key in keys:
        match = re.search(rf"{re.escape(key)}[=:]\s*\"?({IP_RE.pattern})", raw, re.IGNORECASE)
        if match:
            return match.group(1)
    return ips[index] if len(ips) > index else None
