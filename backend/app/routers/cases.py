from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import InvestigationCase, Report
from app.schemas.api import CaseResponse

router = APIRouter(prefix="/api/cases", tags=["cases"])


@router.get("/{case_id}", response_model=CaseResponse)
def get_case(case_id: str, db: Session = Depends(get_db)) -> CaseResponse:
    case = db.get(InvestigationCase, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    return CaseResponse(
        id=case.id,
        user_query=case.user_query,
        alert_text=case.alert_text,
        risk_level=case.risk_level,
        attack_type=case.attack_type,
        final_answer=case.final_answer,
        evidence=case.evidence_json,
        recommended_actions=case.recommended_actions_json,
        retrieved_knowledge=case.retrieved_knowledge_json,
        agent_trace=case.agent_trace_json,
        errors=case.errors_json,
        requires_human_approval=case.requires_human_approval,
    )


@router.get("/{case_id}/report.md")
def download_report(case_id: str, db: Session = Depends(get_db)) -> Response:
    report = db.query(Report).filter(Report.case_id == case_id).order_by(Report.created_at.desc()).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    return Response(content=report.content, media_type="text/markdown")
