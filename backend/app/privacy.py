"""Value redaction preserving JSON shape and credential-field existence."""
from __future__ import annotations

import json
import re
from typing import Any

SECRET_KEY = re.compile(r"password|passwd|pwd|secret|token|cookie|authorization|api.?key", re.I)


def redact_secrets(value: Any, depth: int = 0) -> Any:
    if depth > 24:
        return "[内容过深，已隐藏]"
    if isinstance(value, dict):
        out = {}
        for key, child in value.items():
            sensitive = SECRET_KEY.search(str(key)) or (
                key == "value" and SECRET_KEY.search(str(value.get("key", "")))
            )
            if sensitive and isinstance(child, str) and child.strip().lower() not in {"", "null", "none", "invalid", "expired", "undefined"}:
                prefix = "Bearer " if child.lower().startswith("bearer ") else ""
                out[str(key)] = prefix + "[敏感值已隐藏]"
            else:
                out[str(key)] = redact_secrets(child, depth + 1)
        return out
    if isinstance(value, list):
        return [redact_secrets(child, depth + 1) for child in value]
    if not isinstance(value, str):
        return value
    try:
        parsed = json.loads(value)
    except (ValueError, TypeError):
        parsed = None
    if isinstance(parsed, (dict, list)):
        return json.dumps(redact_secrets(parsed, depth + 1), ensure_ascii=False)
    text = re.sub(r"(?im)((?:authorization|cookie|set-cookie)\s*:\s*)([^\r\n]+)",
                  lambda m: m[1] + ("Bearer " if m[2].lower().startswith("bearer ") else "") + "[敏感值已隐藏]", value)
    return re.sub(r'(?i)((?:password|passwd|secret|token|api_key)\s*[=:]\s*)[^\s,;]+', r'\1[敏感值已隐藏]', text)
