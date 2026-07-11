from __future__ import annotations

from fastapi import APIRouter

from app.agents.llm_provider import check_llm_status
from app.config import get_settings, missing_required_config, require_embedding_config
from app.database import check_database
from app.rag.retriever import check_chroma_status
from app.schemas.api import HealthResponse

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    settings = get_settings()
    database_status, database_error = check_database()
    chroma_status, chroma_detail = check_chroma_status(settings)
    llm_status, llm_detail = check_llm_status(settings)
    try:
        require_embedding_config(settings)
        embedding_status = "ok"
        embedding_detail = None
    except Exception as exc:
        embedding_status = "missing_config"
        embedding_detail = str(exc)

    details = {
        "database": database_error,
        "chroma": chroma_detail,
        "llm": llm_detail,
        "embedding": embedding_detail,
        "database_fallback": "sqlite" if not settings.DATABASE_URL else "configured",
    }

    return HealthResponse(
        backend="ok",
        database=database_status,
        chroma=chroma_status,
        llm=llm_status,
        embedding=embedding_status,
        siem="configured" if settings.SIEM_API_URL and settings.SIEM_API_KEY else "not_configured",
        edr="configured" if settings.EDR_API_URL and settings.EDR_API_KEY else "not_configured",
        firewall="configured" if settings.FIREWALL_API_URL and settings.FIREWALL_API_KEY else "not_configured",
        missing_required_config=missing_required_config(settings),
        details={key: value for key, value in details.items() if value is not None},
    )
