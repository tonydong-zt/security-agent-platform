from __future__ import annotations

from pathlib import Path
from typing import Any

from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings

from app.config import Settings, get_settings, require_embedding_config
from app.errors import KnowledgeBaseEmptyError


def get_embeddings(settings: Settings | None = None):
    settings = settings or get_settings()
    require_embedding_config(settings)
    if settings.EMBEDDING_PROVIDER == "local":
        from langchain_huggingface import HuggingFaceEmbeddings

        return HuggingFaceEmbeddings(model_name=settings.LOCAL_EMBEDDING_MODEL)
    if settings.EMBEDDING_PROVIDER == "gemini":
        from app.rag.gemini_embeddings import GeminiEmbeddings

        return GeminiEmbeddings(settings)
    return OpenAIEmbeddings(
        api_key=settings.EMBEDDING_API_KEY,
        base_url=settings.EMBEDDING_BASE_URL,
        model=settings.EMBEDDING_MODEL,
        timeout=settings.LLM_TIMEOUT_SECONDS,
    )


def get_vectorstore(settings: Settings | None = None):
    settings = settings or get_settings()
    from langchain_chroma import Chroma

    Path(settings.chroma_persist_path).mkdir(parents=True, exist_ok=True)
    return Chroma(
        collection_name=settings.CHROMA_COLLECTION_NAME,
        persist_directory=str(settings.chroma_persist_path),
        embedding_function=get_embeddings(settings),
    )


def get_chroma_count(settings: Settings | None = None) -> int:
    settings = settings or get_settings()
    try:
        import chromadb

        client = chromadb.PersistentClient(path=str(settings.chroma_persist_path))
        collection = client.get_or_create_collection(settings.CHROMA_COLLECTION_NAME)
        return collection.count()
    except Exception:
        return 0


def check_chroma_status(settings: Settings | None = None) -> tuple[str, str | None]:
    settings = settings or get_settings()
    try:
        import chromadb

        Path(settings.chroma_persist_path).mkdir(parents=True, exist_ok=True)
        client = chromadb.PersistentClient(path=str(settings.chroma_persist_path))
        collection = client.get_or_create_collection(settings.CHROMA_COLLECTION_NAME)
        count = collection.count()
        if count == 0:
            return "empty", "知识库为空，请先上传文档或抓取公开安全资料。"
        return "ok", f"{count} chunks"
    except Exception as exc:
        return "error", str(exc)


def retrieve_documents(query: str, k: int = 5, settings: Settings | None = None) -> list[dict[str, Any]]:
    settings = settings or get_settings()
    if get_chroma_count(settings) == 0:
        raise KnowledgeBaseEmptyError("知识库为空，请先上传文档或抓取公开安全资料。")
    vectorstore = get_vectorstore(settings)
    results: list[tuple[Document, float]] = vectorstore.similarity_search_with_score(query, k=k)
    return [
        {
            "chunk": doc.page_content,
            "source": doc.metadata.get("source"),
            "metadata": doc.metadata,
            "score": float(score),
        }
        for doc, score in results
    ]
