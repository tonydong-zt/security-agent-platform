from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from chromadb.config import Settings
from langchain_chroma import Chroma

from .embeddings import LocalSecurityEmbeddings

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CHROMA_ROOT = PROJECT_ROOT / "knowledge" / "chroma_db"
MANIFEST_PATH = PROJECT_ROOT / "knowledge" / "manifest.json"
COLLECTION_NAME = "security_knowledge"


class KnowledgeService:
    def __init__(self, chroma_root: Path = CHROMA_ROOT):
        if not chroma_root.exists():
            raise FileNotFoundError(f"内置 Chroma 向量库不存在：{chroma_root}")
        self.chroma_root = chroma_root
        self._remove_incomplete_hnsw_metadata()
        self.vector_store = Chroma(
            collection_name=COLLECTION_NAME,
            embedding_function=LocalSecurityEmbeddings(),
            persist_directory=str(chroma_root),
            client_settings=Settings(anonymized_telemetry=False),
        )

    def _remove_incomplete_hnsw_metadata(self) -> None:
        # Chroma 1.5 can leave metadata before its HNSW binary files when a
        # build process exits. Removing only that incomplete cache lets Chroma
        # safely backfill from its persisted collection on the next open.
        for metadata in self.chroma_root.rglob("index_metadata.pickle"):
            if not (metadata.parent / "header.bin").exists():
                metadata.unlink()

    def status(self) -> dict[str, Any]:
        manifest: dict[str, Any] = {}
        if MANIFEST_PATH.exists():
            manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        return {
            "ready": self.vector_store._collection.count() > 0,
            "collection": COLLECTION_NAME,
            "document_count": manifest.get("document_count", 0),
            "chunk_count": self.vector_store._collection.count(),
            "embedding": "local-security-hash-384",
            "source_sha256": manifest.get("source_sha256", ""),
            "storage": "LangChain Chroma（项目内嵌，无独立数据库服务）",
        }

    def search(self, query: str, limit: int = 6) -> list[dict[str, Any]]:
        results = self.vector_store.similarity_search_with_relevance_scores(
            query,
            k=max(1, min(limit, 12)),
        )
        return [
            {
                "id": f"K-{index + 1:02d}",
                "chunk_id": str(document.metadata.get("chunk_id", "")),
                "title": str(document.metadata.get("title", "知识片段")),
                "source": str(document.metadata.get("source", "")),
                "category": str(document.metadata.get("category", "")),
                "score": round(max(0.0, min(1.0, float(score))), 6),
                "excerpt": document.page_content[:800],
            }
            for index, (document, score) in enumerate(results)
        ]


@lru_cache
def get_knowledge_service() -> KnowledgeService:
    return KnowledgeService()
