from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.agents.graph import build_security_graph
from app.database import get_db
from app.models import AgentToolCall, InvestigationCase, RecommendedAction, Report
from app.schemas.api import InvestigationRequest, InvestigationResponse

router = APIRouter(prefix="/api", tags=["investigate"])


@router.post("/investigate", response_model=InvestigationResponse)
def investigate(payload: InvestigationRequest, db: Session = Depends(get_db)) -> InvestigationResponse:
    case = db.get(InvestigationCase, payload.case_id) if payload.case_id else None
    if not case:
        case = InvestigationCase(user_query=payload.query, alert_text=payload.alert_text)
        db.add(case)
        db.commit()
        db.refresh(case)

    initial_state = {
        "user_query": payload.query,
        "alert_text": payload.alert_text,
        "case_id": case.id,
        "use_uploaded_logs": payload.use_uploaded_logs,
        "use_knowledge_base": payload.use_knowledge_base,
        "approved_actions": payload.approved_actions,
        "uploaded_logs": [],
        "retrieved_docs": [],
        "tool_results": [],
        "evidence_chain": [],
        "recommended_actions": [],
        "requires_human_approval": True,
        "executed_actions": [],
        "agent_trace": [],
        "errors": [],
    }
    try:
        result = build_security_graph(db).invoke(initial_state)
    except Exception as exc:
        result = {
            **initial_state,
            "errors": [{"code": "agent_runtime_error", "message": str(exc)}],
            "agent_trace": initial_state["agent_trace"] + [{"node": "agent_runtime_error", "summary": "Agent 运行失败，未生成最终分析。"}],
        }

    _persist_case_result(db, case, result)
    final_answer = result.get("final_report") or result.get("final_answer")
    return InvestigationResponse(
        case_id=case.id,
        final_answer=final_answer,
        risk_level=result.get("risk_level"),
        attack_type=result.get("attack_type"),
        evidence=result.get("evidence_chain", []),
        recommended_actions=result.get("recommended_actions", []),
        tool_calls=result.get("tool_results", []),
        retrieved_knowledge=result.get("retrieved_docs", []),
        agent_trace=result.get("agent_trace", []),
        requires_human_approval=result.get("requires_human_approval", True),
        errors=result.get("errors", []),
    )


def _persist_case_result(db: Session, case: InvestigationCase, result: dict) -> None:
    case.risk_level = result.get("risk_level")
    case.attack_type = result.get("attack_type")
    case.final_answer = result.get("final_report") or result.get("final_answer")
    case.evidence_json = result.get("evidence_chain", [])
    case.recommended_actions_json = result.get("recommended_actions", [])
    case.retrieved_knowledge_json = result.get("retrieved_docs", [])
    case.agent_trace_json = result.get("agent_trace", [])
    case.errors_json = result.get("errors", [])
    case.requires_human_approval = result.get("requires_human_approval", True)
    for tool in result.get("tool_results", []):
        db.add(
            AgentToolCall(
                case_id=case.id,
                tool_name=tool.get("tool", "unknown"),
                input_json=tool.get("input", {}),
                output_json=tool.get("output", {}),
                status=tool.get("status", "unknown"),
            )
        )
    for action in result.get("recommended_actions", []):
        db.add(
            RecommendedAction(
                case_id=case.id,
                action_type=action.get("action_type", "unknown"),
                target=action.get("target", ""),
                reason=action.get("reason", ""),
                requires_human_approval=action.get("requires_human_approval", True),
            )
        )
    if result.get("final_report"):
        db.add(Report(case_id=case.id, format="markdown", content=result["final_report"]))
    db.commit()
    db.refresh(case)
