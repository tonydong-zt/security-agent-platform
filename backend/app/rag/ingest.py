from __future__ import annotations

import hashlib
import shutil
from datetime import datetime, timezone
from pathlib import Path

from langchain_core.documents import Document
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.models import UploadedDocument
from app.rag.chunking import split_text
from app.rag.loaders import load_document_text
from app.rag.retriever import get_vectorstore


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def ingest_file(source_path: Path, original_filename: str, db: Session, settings: Settings | None = None) -> dict:
    settings = settings or get_settings()
    content = source_path.read_bytes()
    content_hash = sha256_bytes(content)
    existing = db.query(UploadedDocument).filter(UploadedDocument.content_hash == content_hash).first()
    if existing:
        return {
            "document_id": existing.id,
            "filename": existing.filename,
            "chunk_count": existing.chunk_count,
            "duplicate": True,
            "metadata": existing.metadata_json,
        }

    settings.raw_data_dir.mkdir(parents=True, exist_ok=True)
    stored_path = settings.raw_data_dir / f"{content_hash}{source_path.suffix.lower()}"
    if source_path.resolve() != stored_path.resolve():
        shutil.copyfile(source_path, stored_path)

    text = load_document_text(stored_path)
    chunks = split_text(text)
    metadata_base = {
        "source": original_filename,
        "url": None,
        "title": Path(original_filename).stem,
        "doc_type": source_path.suffix.lower().lstrip("."),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hash": content_hash,
    }
    documents = [
        Document(page_content=chunk, metadata={**metadata_base, "chunk_index": index})
        for index, chunk in enumerate(chunks)
    ]
    if documents:
        vectorstore = get_vectorstore(settings)
        ids = [f"{content_hash}-{index}" for index in range(len(documents))]
        vectorstore.add_documents(documents, ids=ids)

    record = UploadedDocument(
        filename=original_filename,
        stored_path=str(stored_path),
        content_hash=content_hash,
        doc_type=source_path.suffix.lower().lstrip("."),
        chunk_count=len(documents),
        metadata_json=metadata_base,
    )
    db.add(record)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.query(UploadedDocument).filter(UploadedDocument.content_hash == content_hash).first()
        if existing:
            return {
                "document_id": existing.id,
                "filename": existing.filename,
                "chunk_count": existing.chunk_count,
                "duplicate": True,
                "metadata": existing.metadata_json,
            }
        raise
    db.refresh(record)
    return {
        "document_id": record.id,
        "filename": record.filename,
        "chunk_count": record.chunk_count,
        "duplicate": False,
        "metadata": record.metadata_json,
    }
