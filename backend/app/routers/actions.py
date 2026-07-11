from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.errors import ToolNotConfiguredError
from app.models import ExecutedAction
from app.schemas.api import ActionApprovalRequest, ActionApprovalResponse
from app.tools.response_tools import execute_edr_isolation, execute_firewall_block

router = APIRouter(prefix="/api/actions", tags=["actions"])


@router.post("/approve", response_model=ActionApprovalResponse)
async def approve_action(payload: ActionApprovalRequest, db: Session = Depends(get_db)) -> ActionApprovalResponse:
    if not payload.approved:
        result = {"status": "failed", "code": "approval_required", "message": "Human approval is required. No real action was executed."}
        _record(db, payload, result)
        return ActionApprovalResponse(**result)
    try:
        if payload.action_type == "firewall_block_ip":
            result_body = await execute_firewall_block(payload.target, approved=True, settings=get_settings())
        elif payload.action_type == "edr_isolate_host":
            result_body = await execute_edr_isolation(payload.target, approved=True, settings=get_settings())
        else:
            result = {"status": "failed", "code": "unsupported_action", "message": f"Unsupported action type: {payload.action_type}", "result": {}}
            _record(db, payload, result)
            return ActionApprovalResponse(**result)
        result = {"status": "ok", "code": "executed", "message": "Real external API returned successfully.", "result": result_body}
        _record(db, payload, result)
        return ActionApprovalResponse(**result)
    except ToolNotConfiguredError as exc:
        code = "tool_not_configured"
        result = {"status": "failed", "code": code, "message": str(exc), "result": {}}
        _record(db, payload, result)
        return ActionApprovalResponse(**result)
    except Exception as exc:
        result = {"status": "failed", "code": "external_api_error", "message": str(exc), "result": {}}
        _record(db, payload, result)
        return ActionApprovalResponse(**result)


def _record(db: Session, payload: ActionApprovalRequest, result: dict) -> None:
    db.add(
        ExecutedAction(
            case_id=payload.case_id,
            action_type=payload.action_type,
            target=payload.target,
            status=result["status"],
            request_json=payload.model_dump(),
            response_json=result.get("result", {}),
            error_message=None if result["status"] == "ok" else result["message"],
        )
    )
    db.commit()
