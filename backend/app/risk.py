"""Scene-bound, reproducible risk profiles.

Risk answers "how serious would this be if the scenario is true".  Evidence
confidence is calculated separately by the caller and is never used as a
substitute for the risk score.
"""

from __future__ import annotations

from typing import Any

RISK_PROFILES: dict[str, dict[str, Any]] = {
    "credential_authentication": {
        "label": "身份认证/凭据",
        "dimensions": (
            ("credential_sensitivity", "凭据敏感性", 0.30),
            ("authentication_outcome", "认证成功程度", 0.25),
            ("authorization_assurance", "授权可信度", 0.20),
            ("asset_impact", "账号与业务影响", 0.15),
            ("post_auth_behavior", "后续行为", 0.10),
        ),
        "formula": "Risk = 0.30×凭据敏感性 + 0.25×认证成功程度 + 0.20×授权可信度 + 0.15×账号与业务影响 + 0.10×后续行为",
    },
    "data_exposure": {
        "label": "敏感数据暴露",
        "dimensions": (
            ("data_sensitivity", "数据敏感性", 0.30),
            ("access_success", "访问成功程度", 0.25),
            ("data_scope", "数据范围", 0.15),
            ("external_transfer", "外传可信度", 0.20),
            ("business_impact", "业务影响", 0.10),
        ),
        "formula": "Risk = 0.30×数据敏感性 + 0.25×访问成功程度 + 0.15×数据范围 + 0.20×外传可信度 + 0.10×业务影响",
    },
    "injection": {
        "label": "注入",
        "dimensions": (
            ("data_sensitivity", "敏感性", 0.30),
            ("processing_success", "请求/处理成功度", 0.25),
            ("authorization_assurance", "未授权可信度", 0.20),
            ("asset_impact", "资产与业务影响", 0.15),
            ("threat_exposure", "威胁暴露", 0.10),
        ),
        "formula": "Risk = 0.30×敏感性 + 0.25×请求/处理成功度 + 0.20×未授权可信度 + 0.15×资产与业务影响 + 0.10×威胁暴露",
    },
    "command_execution": {
        "label": "命令执行",
        "dimensions": (
            ("execution_capability", "执行能力", 0.30),
            ("processing_success", "执行成功程度", 0.25),
            ("authorization_assurance", "授权可信度", 0.20),
            ("asset_impact", "主机与业务影响", 0.15),
            ("post_auth_behavior", "后续行为", 0.10),
        ),
        "formula": "Risk = 0.30×执行能力 + 0.25×执行成功程度 + 0.20×授权可信度 + 0.15×主机与业务影响 + 0.10×后续行为",
    },
    "xss": {
        "label": "跨站脚本",
        "dimensions": (
            ("payload_capability", "脚本载荷能力", 0.30),
            ("rendering_success", "渲染/执行成功程度", 0.25),
            ("session_impact", "会话影响", 0.20),
            ("asset_impact", "业务影响", 0.15),
            ("post_auth_behavior", "后续行为", 0.10),
        ),
        "formula": "Risk = 0.30×脚本载荷能力 + 0.25×渲染/执行成功程度 + 0.20×会话影响 + 0.15×业务影响 + 0.10×后续行为",
    },
    "malware_file": {
        "label": "恶意文件/主机",
        "dimensions": (
            ("malicious_confidence", "恶意可信度", 0.30),
            ("execution_success", "执行状态", 0.25),
            ("asset_impact", "主机重要性", 0.20),
            ("threat_exposure", "传播能力", 0.15),
            ("post_auth_behavior", "后续行为", 0.10),
        ),
        "formula": "Risk = 0.30×恶意可信度 + 0.25×执行状态 + 0.20×主机重要性 + 0.15×传播能力 + 0.10×后续行为",
    },
    "scanning": {
        "label": "扫描/探测",
        "dimensions": (
            ("target_exposure", "目标暴露度", 0.30),
            ("scan_confidence", "扫描可信度", 0.25),
            ("authorization_assurance", "授权可信度", 0.20),
            ("asset_impact", "资产重要性", 0.15),
            ("post_auth_behavior", "后续行为", 0.10),
        ),
        "formula": "Risk = 0.30×目标暴露度 + 0.25×扫描可信度 + 0.20×授权可信度 + 0.15×资产重要性 + 0.10×后续行为",
    },
    "generic": {
        "label": "通用安全异常",
        "dimensions": (
            ("sensitivity", "敏感性", 0.30),
            ("processing_success", "请求/处理成功度", 0.25),
            ("authorization_assurance", "未授权可信度", 0.20),
            ("asset_impact", "资产与业务影响", 0.15),
            ("threat_exposure", "威胁暴露", 0.10),
        ),
        "formula": "Risk = 0.30×敏感性 + 0.25×请求/处理成功度 + 0.20×未授权可信度 + 0.15×资产与业务影响 + 0.10×威胁暴露",
    },
}


def risk_profile_for_scene(scene_id: str) -> dict[str, Any]:
    profile = RISK_PROFILES.get(scene_id, RISK_PROFILES["generic"])
    return {
        "scene_id": scene_id if scene_id in RISK_PROFILES else "generic",
        "label": profile["label"],
        "dimensions": [
            {"key": key, "label": label, "weight": weight}
            for key, label, weight in profile["dimensions"]
        ],
        "formula": profile["formula"],
    }


WORKFLOW_PROFILE_BASE = {
    "auth_workflow": "credential_authentication",
    "authorization_workflow": "generic",
    "web_attack_workflow": "injection",
    "file_workflow": "malware_file",
    "data_exposure_workflow": "data_exposure",
    "host_workflow": "command_execution",
    "network_workflow": "scanning",
    "database_workflow": "injection",
    "cloud_workflow": "generic",
    "generic_workflow": "generic",
}


def risk_profile_for_workflow(
    workflow_id: str, risk_profile_id: str | None = None
) -> dict[str, Any]:
    """Resolve a profile selected by the Router, not by a second scene guess."""
    base_scene = WORKFLOW_PROFILE_BASE.get(workflow_id, "generic")
    profile = risk_profile_for_scene(base_scene)
    profile["workflow_id"] = workflow_id if workflow_id in WORKFLOW_PROFILE_BASE else "generic_workflow"
    profile["risk_profile_id"] = risk_profile_id or f"{profile['workflow_id'].upper()}_RISK"
    return profile


def quantize_score(raw_score: float) -> int:
    if raw_score <= 0:
        return 0
    return int(min(100, max(25, 25 * round(raw_score / 25))))


def risk_level(score: int) -> str:
    return "严重" if score == 100 else "高" if score >= 75 else "中" if score >= 50 else "低"
