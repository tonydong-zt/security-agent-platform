from __future__ import annotations

from typing import Any

from app.config import Settings, get_settings
from app.errors import KnowledgeBaseEmptyError
from app.rag.retriever import retrieve_documents


def retrieve_security_knowledge(query: str, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or get_settings()
    try:
        docs = retrieve_documents(query, settings=settings)
        return {"status": "ok", "results": docs, "reason": None}
    except KnowledgeBaseEmptyError as exc:
        return {"status": "empty", "results": [], "reason": str(exc)}
    except Exception as exc:
        return {"status": "error", "results": [], "reason": str(exc)}
