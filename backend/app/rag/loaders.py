from __future__ import annotations

import csv
import json
from pathlib import Path

from app.errors import DataUnavailableError


SUPPORTED_EXTENSIONS = {".pdf", ".txt", ".md", ".csv", ".json", ".log"}


def load_document_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        raise DataUnavailableError(f"Unsupported file type: {suffix}")
    if suffix == ".pdf":
        return _load_pdf(path)
    if suffix == ".csv":
        return _load_csv(path)
    if suffix == ".json":
        return _load_json(path)
    return path.read_text(encoding="utf-8", errors="replace")


def _load_pdf(path: Path) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover
        raise DataUnavailableError("PDF support requires pypdf to be installed.") from exc
    reader = PdfReader(str(path))
    pages = []
    for page in reader.pages:
        pages.append(page.extract_text() or "")
    return "\n".join(pages)


def _load_csv(path: Path) -> str:
    rows = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames:
            for row in reader:
                rows.append(json.dumps(row, ensure_ascii=False))
        else:
            handle.seek(0)
            rows.append(handle.read())
    return "\n".join(rows)


def _load_json(path: Path) -> str:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    return json.dumps(data, ensure_ascii=False, indent=2)
