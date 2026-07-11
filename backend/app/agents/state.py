from __future__ import annotations

from typing import Any, TypedDict


class SecurityAgentState(TypedDict, total=False):
    user_query: str
    alert_text: str | None
    case_id: str | None
    use_uploaded_logs: bool
    use_knowledge_base: bool
    runtime_config_status: dict[str, Any]
    parsed_entities: dict[str, Any]
    uploaded_logs: list[dict[str, Any]]
    retrieved_docs: list[dict[str, Any]]
    tool_results: list[dict[str, Any]]
    risk_level: str | None
    attack_type: str | None
    evidence_chain: list[dict[str, Any]]
    recommended_actions: list[dict[str, Any]]
    requires_human_approval: bool
    approved_actions: list[dict[str, Any]]
    executed_actions: list[dict[str, Any]]
    final_report: str | None
    final_answer: str | None
    agent_trace: list[dict[str, Any]]
    errors: list[dict[str, Any]]
    intent: str | None
