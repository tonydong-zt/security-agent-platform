from __future__ import annotations

from typing import Any

from app.config import Settings, get_settings
from app.errors import ToolNotConfiguredError
from app.integrations.edr_client import EDRClient
from app.integrations.firewall_client import FirewallClient


def propose_firewall_block(ip: str, reason: str | None = None) -> dict[str, Any]:
    return {
        "action_type": "firewall_block_ip",
        "target": ip,
        "reason": reason or "检测到该 IP 与当前证据相关，建议人工复核后再执行封禁。",
        "requires_human_approval": True,
        "executed": False,
    }


async def execute_firewall_block(ip: str, approved: bool, settings: Settings | None = None) -> dict[str, Any]:
    if not approved:
        return {"status": "blocked", "code": "approval_required", "message": "Human approval is required. No real action was executed."}
    client = FirewallClient(settings or get_settings())
    return await client.block_ip(ip)


def propose_edr_isolation(hostname: str, reason: str | None = None) -> dict[str, Any]:
    return {
        "action_type": "edr_isolate_host",
        "target": hostname,
        "reason": reason or "检测到该主机与当前证据相关，建议人工复核后再执行隔离。",
        "requires_human_approval": True,
        "executed": False,
    }


async def execute_edr_isolation(hostname: str, approved: bool, settings: Settings | None = None) -> dict[str, Any]:
    if not approved:
        return {"status": "blocked", "code": "approval_required", "message": "Human approval is required. No real action was executed."}
    client = EDRClient(settings or get_settings())
    return await client.isolate_host(hostname)


def generate_incident_report(case_data: dict[str, Any]) -> dict[str, Any]:
    if not case_data:
        return {"status": "error", "reason": "case_data 为空，无法生成报告。", "report": None}
    report = f"""# 安全事件调查报告

## 事件摘要
{case_data.get("summary") or case_data.get("final_answer") or "未生成摘要。"}

## 风险等级
{case_data.get("risk_level") or "未判定"}

## 攻击类型
{case_data.get("attack_type") or "未判定"}

## 证据链
{_markdown_list(case_data.get("evidence") or [])}

## 关联知识
{_markdown_list(case_data.get("retrieved_knowledge") or [])}

## 工具调用结果
{_markdown_list(case_data.get("tool_calls") or [])}

## 处置建议
{_markdown_list(case_data.get("recommended_actions") or [])}

## 未执行动作及原因
{_markdown_list(case_data.get("not_executed") or ["高危动作需要人工审批；未配置真实外部 API 时不会执行封禁、隔离或阻断。"])}

## 后续建议
{case_data.get("next_steps") or "补充更多安全日志、知识库文档和真实 SIEM/EDR/防火墙 API 后复核。"}
"""
    return {"status": "ok", "report": report, "reason": None}


def _markdown_list(items: list[Any]) -> str:
    if not items:
        return "- 无"
    lines = []
    for item in items[:20]:
        if isinstance(item, dict):
            lines.append(f"- `{item}`")
        else:
            lines.append(f"- {item}")
    return "\n".join(lines)
