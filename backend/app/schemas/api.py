from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    backend: str
    database: str
    chroma: str
    llm: str
    embedding: str
    siem: str
    edr: str
    firewall: str
    missing_required_config: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class DocumentUploadResponse(BaseModel):
    document_id: str
    filename: str
    chunk_count: int
    duplicate: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class LogUploadResponse(BaseModel):
    log_file_id: str
    filename: str
    parsed_count: int
    failed_count: int
    samples: list[dict[str, Any]] = Field(default_factory=list)


class InvestigationRequest(BaseModel):
    query: str
    alert_text: str | None = None
    case_id: str | None = None
    use_uploaded_logs: bool = True
    use_knowledge_base: bool = True
    approved_actions: list[dict[str, Any]] = Field(default_factory=list)


class InvestigationResponse(BaseModel):
    case_id: str
    final_answer: str | None
    risk_level: str | None
    attack_type: str | None
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    recommended_actions: list[dict[str, Any]] = Field(default_factory=list)
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    retrieved_knowledge: list[dict[str, Any]] = Field(default_factory=list)
    agent_trace: list[dict[str, Any] | str] = Field(default_factory=list)
    requires_human_approval: bool = True
    errors: list[dict[str, Any] | str] = Field(default_factory=list)


class CaseResponse(BaseModel):
    id: str
    user_query: str
    alert_text: str | None
    risk_level: str | None
    attack_type: str | None
    final_answer: str | None
    evidence: list[Any]
    recommended_actions: list[Any]
    retrieved_knowledge: list[Any]
    agent_trace: list[Any]
    errors: list[Any]
    requires_human_approval: bool


class ActionApprovalRequest(BaseModel):
    case_id: str | None = None
    action_type: str
    target: str
    approved: bool = False


class ActionApprovalResponse(BaseModel):
    status: str
    code: str
    message: str
    result: dict[str, Any] = Field(default_factory=dict)
