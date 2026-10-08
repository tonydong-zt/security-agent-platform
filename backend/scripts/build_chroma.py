from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

from chromadb.config import Settings
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.embeddings import LocalSecurityEmbeddings
from app.knowledge import COLLECTION_NAME


def safe_extract(source_zip: Path, target: Path) -> None:
    with zipfile.ZipFile(source_zip) as archive:
        total_size = 0
        file_count = 0
        for item in archive.infolist():
            normalized = Path(item.filename.replace("\\", "/"))
            if normalized.is_absolute() or ".." in normalized.parts:
                raise ValueError(f"知识库 ZIP 包含不安全路径：{item.filename}")
            if item.is_dir():
                continue
            total_size += item.file_size
            file_count += 1
            if file_count > 2_000 or total_size > 200 * 1024 * 1024:
                raise ValueError("知识库 ZIP 超过安全上限")
            destination = (target / normalized).resolve()
            if target.resolve() not in destination.parents:
                raise ValueError(f"知识库 ZIP 路径越界：{item.filename}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)


def build(source_zip: Path, output: Path, manifest_path: Path) -> dict[str, object]:
    source_zip = source_zip.resolve()
    output = output.resolve()
    allowed_root = (BACKEND_ROOT.parent / "knowledge").resolve()
    if allowed_root not in output.parents:
        raise ValueError(f"拒绝清理知识库目录之外的路径：{output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        shutil.rmtree(output)

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=1_400,
        chunk_overlap=160,
        separators=["\n## ", "\n### ", "\n\n", "\n", "。", "；", " "],
    )
    documents: list[Document] = []
    with tempfile.TemporaryDirectory(prefix="security-knowledge-") as temporary:
        extracted = Path(temporary)
        safe_extract(source_zip, extracted)
        markdown_files = sorted(extracted.rglob("*.md"))
        for path in markdown_files:
            relative = path.relative_to(extracted).as_posix()
            text = path.read_text(encoding="utf-8", errors="replace")
            title = next(
                (
                    line.lstrip("# ").strip()
                    for line in text.splitlines()
                    if line.startswith("#")
                ),
                path.stem,
            )
            category = (
                relative.split("/")[1] if relative.count("/") >= 1 else path.parent.name
            )
            for index, chunk in enumerate(splitter.split_text(text)):
                if not chunk.strip():
                    continue
                chunk_id = hashlib.sha256(
                    f"{relative}:{index}:{chunk}".encode()
                ).hexdigest()[:24]
                documents.append(
                    Document(
                        page_content=chunk,
                        metadata={
                            "chunk_id": chunk_id,
                            "title": title,
                            "source": relative,
                            "category": category,
                        },
                    )
                )

    vector_store = Chroma(
        collection_name=COLLECTION_NAME,
        embedding_function=LocalSecurityEmbeddings(),
        persist_directory=str(output),
        collection_metadata={"hnsw:space": "cosine"},
        client_settings=Settings(anonymized_telemetry=False),
    )
    for start in range(0, len(documents), 200):
        batch = documents[start : start + 200]
        vector_store.add_documents(
            batch, ids=[doc.metadata["chunk_id"] for doc in batch]
        )
    stored_count = vector_store._collection.count()
    if stored_count != len(documents):
        raise RuntimeError(f"Chroma 写入不完整：{stored_count}/{len(documents)}")
    vector_store.similarity_search("安全告警", k=1)
    close = getattr(vector_store._client, "close", None)
    if callable(close):
        close()
    for metadata in output.rglob("index_metadata.pickle"):
        if not (metadata.parent / "header.bin").exists():
            metadata.unlink()

    manifest: dict[str, object] = {
        "format": "langchain-chroma-local-v1",
        "collection": COLLECTION_NAME,
        "source": source_zip.name,
        "source_sha256": hashlib.sha256(source_zip.read_bytes()).hexdigest(),
        "document_count": len({doc.metadata["source"] for doc in documents}),
        "chunk_count": len(documents),
        "embedding": "local-security-hash-384",
        "dimensions": LocalSecurityEmbeddings.dimensions,
        "external_database_required": False,
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_zip", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("manifest", type=Path)
    arguments = parser.parse_args()
    print(
        json.dumps(
            build(arguments.source_zip, arguments.output, arguments.manifest),
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
