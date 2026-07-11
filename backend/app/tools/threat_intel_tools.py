from __future__ import annotations

from typing import Any

import httpx

from app.config import Settings, get_settings
from app.tools.rag_tools import retrieve_security_knowledge


def lookup_cve(cve_id_or_keyword: str, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    local = retrieve_security_knowledge(cve_id_or_keyword, settings=settings)
    results = []
    if local["status"] == "ok":
        results.extend(local["results"])
    external = {"status": "not_configured", "results": [], "reason": "NVD_API_KEY is not configured; no external CVE lookup was executed."}
    if settings.NVD_API_KEY:
        try:
            params = {"keywordSearch": cve_id_or_keyword}
            if cve_id_or_keyword.upper().startswith("CVE-"):
                params = {"cveId": cve_id_or_keyword.upper()}
            response = httpx.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers={"apiKey": settings.NVD_API_KEY},
                params=params,
                timeout=20,
            )
            response.raise_for_status()
            external = {"status": "ok", "results": response.json().get("vulnerabilities", []), "reason": None}
        except Exception as exc:
            external = {"status": "error", "results": [], "reason": str(exc)}
    if not results and not external["results"]:
        return {"status": "empty", "results": [], "reason": "未在本地知识库或已配置外部来源中找到 CVE 结果。", "external": external}
    return {"status": "ok", "results": results, "external": external, "reason": None}


def lookup_attack_technique(keyword: str, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    local = retrieve_security_knowledge(f"MITRE ATT&CK {keyword}", settings=settings)
    if local["status"] == "empty":
        return {"status": "empty", "results": [], "reason": "MITRE ATT&CK 数据未入库，无法从知识库查询技术信息。"}
    return local
