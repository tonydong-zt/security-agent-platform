from __future__ import annotations

import json
import re
from typing import Any

from langgraph.graph import END, StateGraph
from sqlalchemy.orm import Session

from app.agents.llm_provider import get_chat_model
from app.agents.prompts import INTENT_PROMPT, THREAT_ANALYSIS_PROMPT
from app.agents.state import SecurityAgentState
from app.config import Settings, get_settings, require_llm_config
from app.errors import ConfigError
from app.rag.retriever import check_chroma_status
from app.tools.log_tools import search_historical_cases, search_uploaded_logs
from app.tools.rag_tools import retrieve_security_knowledge
from app.tools.response_tools import generate_incident_report, propose_edr_isolation, propose_firewall_block
from app.tools.threat_intel_tools import lookup_attack_technique, lookup_cve


IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_RE = re.compile(r"https?://[^\s\"']+")
PROCESS_RE = re.compile(r"\b[\w.-]+\.(?:exe|dll|ps1|bat|sh|py)\b", re.IGNORECASE)


def build_security_graph(db: Session, settings: Settings | None = None):
    settings = settings or get_settings()

    def validate_runtime_config(state: SecurityAgentState) -> SecurityAgentState:
        errors = list(state.get("errors", []))
        runtime = {
            "llm": "unknown",
            "chroma": "unknown",
            "logs": "unknown",
            "siem": "configured" if settings.SIEM_API_URL and settings.SIEM_API_KEY else "not_configured",
            "edr": "configured" if settings.EDR_API_URL and settings.EDR_API_KEY else "not_configured",
            "firewall": "configured" if settings.FIREWALL_API_URL and settings.FIREWALL_API_KEY else "not_configured",
        }
        try:
            require_llm_config(settings)
            runtime["llm"] = "ok"
        except ConfigError as exc:
            runtime["llm"] = "missing_config"
            errors.append({"code": "llm_missing_config", "message": "LLM 未配置，Agent 无法运行。", "detail": str(exc)})
        chroma_status, chroma_detail = check_chroma_status(settings)
        runtime["chroma"] = chroma_status
        runtime["chroma_detail"] = chroma_detail
        runtime["logs"] = "ok" if db.execute(__import__("sqlalchemy").text("SELECT COUNT(*) FROM parsed_logs")).scalar() else "empty"
        trace = list(state.get("agent_trace", []))
        trace.append({"node": "validate_runtime_config", "summary": "完成运行时配置检查。", "status": runtime})
        return {**state, "runtime_config_status": runtime, "errors": errors, "agent_trace": trace}

    def should_continue_after_validation(state: SecurityAgentState) -> str:
        if any(error.get("code") == "llm_missing_config" for error in state.get("errors", [])):
            return "stop"
        return "continue"

    def intent_classification(state: SecurityAgentState) -> SecurityAgentState:
        llm = get_chat_model(settings)
        prompt = INTENT_PROMPT.format(query=state["user_query"], alert_text=state.get("alert_text") or "")
        response = llm.invoke(prompt)
        intent = _content(response).strip().splitlines()[0][:80] or "其他"
        trace = list(state.get("agent_trace", []))
        trace.append({"node": "intent_classification", "summary": f"识别意图：{intent}"})
        return {**state, "intent": intent, "agent_trace": trace}

    def entity_extraction(state: SecurityAgentState) -> SecurityAgentState:
        text = f"{state.get('user_query') or ''}\n{state.get('alert_text') or ''}"
        entities = {
            "ips": sorted(set(IP_RE.findall(text))),
            "domains": sorted(set(DOMAIN_RE.findall(text))),
            "urls": sorted(set(URL_RE.findall(text))),
            "usernames": sorted(set(_extract_key_values(text, ["user", "username", "account"]))),
            "hostnames": sorted(set(_extract_key_values(text, ["host", "hostname", "computer"]))),
            "process_names": sorted(set(PROCESS_RE.findall(text) + _extract_key_values(text, ["process", "image", "exe"]))),
            "cves": sorted(set(match.upper() for match in CVE_RE.findall(text))),
            "keywords": _derive_keywords(text),
            "time_range": {},
        }
        trace = list(state.get("agent_trace", []))
        trace.append({"node": "entity_extraction", "summary": "从用户输入和告警中提取实体。", "entities": entities})
        return {**state, "parsed_entities": entities, "agent_trace": trace}

    def evidence_collection(state: SecurityAgentState) -> SecurityAgentState:
        tool_results = list(state.get("tool_results", []))
        evidence = list(state.get("evidence_chain", []))
        logs: list[dict[str, Any]] = []
        if state.get("use_uploaded_logs", True):
            result = search_uploaded_logs(state.get("parsed_entities", {}), db)
            logs = result["results"]
            tool_results.append({"tool": "search_uploaded_logs", "input": state.get("parsed_entities", {}), "output": result, "status": result["status"]})
            evidence.extend({"type": "uploaded_log", "content": item} for item in logs[:20])
        else:
            result = {"status": "skipped", "results": [], "reason": "用户未启用已上传日志检索。"}
            tool_results.append({"tool": "search_uploaded_logs", "input": {}, "output": result, "status": "skipped"})
        history = search_historical_cases(state.get("parsed_entities", {}), db)
        tool_results.append({"tool": "search_historical_cases", "input": state.get("parsed_entities", {}), "output": history, "status": history["status"]})
        trace = list(state.get("agent_trace", []))
        trace.append({"node": "evidence_collection", "summary": f"收集到 {len(logs)} 条日志证据。"})
        return {**state, "uploaded_logs": logs, "tool_results": tool_results, "evidence_chain": evidence, "agent_trace": trace}

    def rag_retrieval(state: SecurityAgentState) -> SecurityAgentState:
        tool_results = list(state.get("tool_results", []))
        docs: list[dict[str, Any]] = []
        query = f"{state.get('user_query') or ''}\n{state.get('alert_text') or ''}"
        if state.get("use_knowledge_base", True):
            result = retrieve_security_knowledge(query, settings=settings)
            docs = result["results"]
            tool_results.append({"tool": "retrieve_security_knowledge", "input": {"query": query[:500]}, "output": result, "status": result["status"]})
        else:
            result = {"status": "skipped", "results": [], "reason": "用户未启用知识库检索。"}
            tool_results.append({"tool": "retrieve_security_knowledge", "input": {}, "output": result, "status": "skipped"})
        trace = list(state.get("agent_trace", []))
        trace.append({"node": "rag_retrieval", "summary": f"检索到 {len(docs)} 条知识库片段。", "reason": result.get("reason")})
        return {**state, "retrieved_docs": docs, "tool_results": tool_results, "agent_trace": trace}

    def threat_analysis(state: SecurityAgentState) -> SecurityAgentState:
        llm = get_chat_model(settings)
        prompt = THREAT_ANALYSIS_PROMPT.format(
            query=state.get("user_query"),
            alert_text=state.get("alert_text") or "",
            entities=json.dumps(state.get("parsed_entities", {}), ensure_ascii=False),
            logs=json.dumps(state.get("uploaded_logs", []), ensure_ascii=False)[:8000],
            docs=json.dumps(state.get("retrieved_docs", []), ensure_ascii=False)[:8000],
            tool_results=json.dumps(state.get("tool_results", []), ensure_ascii=False)[:8000],
        )
        response = llm.invoke(prompt)
        final_answer = _content(response)
        risk_level = _infer_risk_level(final_answer, state)
        attack_type = _infer_attack_type(final_answer, state)
        trace = list(state.get("agent_trace", []))
        trace.append({"node": "threat_analysis", "summary": "LLM 已基于工具返回结果生成安全分析。"})
        return {**state, "final_answer": final_answer, "risk_level": risk_level, "attack_type": attack_type, "agent_trace": trace}

    def tool_decision(state: SecurityAgentState) -> SecurityAgentState:
        tool_results = list(state.get("tool_results", []))
        entities = state.get("parsed_entities", {})
        for cve in entities.get("cves", [])[:3]:
            result = lookup_cve(cve, settings=settings)
            tool_results.append({"tool": "lookup_cve", "input": {"cve": cve}, "output": result, "status": result["status"]})
        for keyword in entities.get("keywords", [])[:2]:
            result = lookup_attack_technique(keyword, settings=settings)
            tool_results.append({"tool": "lookup_attack_technique", "input": {"keyword": keyword}, "output": result, "status": result["status"]})
        trace = list(state.get("agent_trace", []))
        trace.append({"node": "tool_decision", "summary": "完成威胁情报和外部工具可用性判断；未配置工具不会执行真实动作。"})
        return {**state, "tool_results": tool_results, "agent_trace": trace}

    def action_planning(state: SecurityAgentState) -> SecurityAgentState:
        entities = state.get("parsed_entities", {})
        actions = list(state.get("recommended_actions", []))
        if state.get("risk_level") in {"high", "critical"}:
            for ip in entities.get("ips", [])[:3]:
                actions.append(propose_firewall_block(ip, reason="当前调查风险较高，且该 IP 出现在告警或日志证据中。"))
            for hostname in entities.get("hostnames", [])[:3]:
                actions.append(propose_edr_isolation(hostname, reason="当前调查风险较高，且该主机出现在告警或日志证据中。"))
        requires = any(action.get("requires_human_approval") for action in actions)
        trace = list(state.get("agent_trace", []))
        trace.append({"node": "action_planning", "summary": f"生成 {len(actions)} 条建议动作；高危动作需要人工审批。"})
        return {**state, "recommended_actions": actions, "requires_human_approval": requires, "agent_trace": trace}

    def human_approval_check(state: SecurityAgentState) -> SecurityAgentState:
        trace = list(state.get("agent_trace", []))
        approved = state.get("approved_actions", [])
        if state.get("requires_human_approval") and not approved:
            trace.append({"node": "human_approval_check", "summary": "未收到人工批准，停留在建议阶段，未执行真实动作。"})
        else:
            trace.append({"node": "human_approval_check", "summary": "已检查人工批准状态。真实动作请通过 /api/actions/approve 执行并记录。"})
        return {**state, "agent_trace": trace}

    def report_generation(state: SecurityAgentState) -> SecurityAgentState:
        case_data = {
            "summary": state.get("final_answer"),
            "final_answer": state.get("final_answer"),
            "risk_level": state.get("risk_level"),
            "attack_type": state.get("attack_type"),
            "evidence": state.get("evidence_chain", []),
            "retrieved_knowledge": state.get("retrieved_docs", []),
            "tool_calls": state.get("tool_results", []),
            "recommended_actions": state.get("recommended_actions", []),
            "not_executed": ["所有高危处置动作均需人工审批；未配置真实外部 API 时不会执行。"],
        }
        report_result = generate_incident_report(case_data)
        trace = list(state.get("agent_trace", []))
        trace.append({"node": "report_generation", "summary": "生成 Markdown 事件报告。", "status": report_result["status"]})
        return {**state, "final_report": report_result.get("report"), "agent_trace": trace}

    graph = StateGraph(SecurityAgentState)
    graph.add_node("validate_runtime_config", validate_runtime_config)
    graph.add_node("intent_classification", intent_classification)
    graph.add_node("entity_extraction", entity_extraction)
    graph.add_node("evidence_collection", evidence_collection)
    graph.add_node("rag_retrieval", rag_retrieval)
    graph.add_node("threat_analysis", threat_analysis)
    graph.add_node("tool_decision", tool_decision)
    graph.add_node("action_planning", action_planning)
    graph.add_node("human_approval_check", human_approval_check)
    graph.add_node("report_generation", report_generation)
    graph.set_entry_point("validate_runtime_config")
    graph.add_conditional_edges("validate_runtime_config", should_continue_after_validation, {"continue": "intent_classification", "stop": END})
    graph.add_edge("intent_classification", "entity_extraction")
    graph.add_edge("entity_extraction", "evidence_collection")
    graph.add_edge("evidence_collection", "rag_retrieval")
    graph.add_edge("rag_retrieval", "threat_analysis")
    graph.add_edge("threat_analysis", "tool_decision")
    graph.add_edge("tool_decision", "action_planning")
    graph.add_edge("action_planning", "human_approval_check")
    graph.add_edge("human_approval_check", "report_generation")
    graph.add_edge("report_generation", END)
    return graph.compile()


def _content(response: Any) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, list):
        return "\n".join(str(item) for item in content)
    return str(content)


def _extract_key_values(text: str, keys: list[str]) -> list[str]:
    values: list[str] = []
    for key in keys:
        values.extend(re.findall(rf"{re.escape(key)}[=:]\s*\"?([\w.\-@\\/]+)", text, flags=re.IGNORECASE))
    return values


def _derive_keywords(text: str) -> list[str]:
    candidates = []
    for word in re.findall(r"[A-Za-z][A-Za-z0-9_-]{4,}", text):
        if word.lower() not in {"https", "username", "source", "destination", "process"}:
            candidates.append(word)
    return sorted(set(candidates))[:10]


def _infer_risk_level(answer: str, state: SecurityAgentState) -> str:
    text = f"{answer}\n{state.get('alert_text') or ''}".lower()
    if any(word in text for word in ["critical", "勒索", "ransom", "domain admin", "横向移动"]):
        return "critical"
    if any(word in text for word in ["high", "高危", "malware", "c2", "credential", "powershell", "mimikatz"]):
        return "high"
    if any(word in text for word in ["medium", "中危", "suspicious", "可疑", "bruteforce", "暴力破解"]):
        return "medium"
    return "low"


def _infer_attack_type(answer: str, state: SecurityAgentState) -> str:
    text = f"{answer}\n{state.get('alert_text') or ''}".lower()
    mapping = {
        "ransom": "ransomware",
        "勒索": "ransomware",
        "bruteforce": "credential_attack",
        "暴力破解": "credential_attack",
        "powershell": "suspicious_script_execution",
        "cve-": "vulnerability_exploitation",
        "c2": "command_and_control",
        "lateral": "lateral_movement",
        "横向": "lateral_movement",
    }
    for needle, value in mapping.items():
        if needle in text:
            return value
    return "unknown"
