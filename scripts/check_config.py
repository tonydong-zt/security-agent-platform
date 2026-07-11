from app.agents.llm_provider import check_llm_status
from app.config import get_settings, missing_required_config, require_embedding_config
from app.database import check_database
from app.rag.retriever import check_chroma_status


if __name__ == "__main__":
    settings = get_settings()
    database, database_detail = check_database()
    chroma, chroma_detail = check_chroma_status(settings)
    llm, llm_detail = check_llm_status(settings)
    try:
        require_embedding_config(settings)
        embedding, embedding_detail = "ok", None
    except Exception as exc:
        embedding, embedding_detail = "missing_config", str(exc)
    print(
        {
            "database": database,
            "database_detail": database_detail,
            "chroma": chroma,
            "chroma_detail": chroma_detail,
            "llm": llm,
            "llm_detail": llm_detail,
            "embedding": embedding,
            "embedding_detail": embedding_detail,
            "missing_required_config": missing_required_config(settings),
        }
    )
