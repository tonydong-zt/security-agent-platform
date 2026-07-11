from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import LogFile, ParsedLog
from app.schemas.api import LogUploadResponse
from app.services.log_parser import parse_log_content

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.post("/upload", response_model=LogUploadResponse)
async def upload_logs(file: UploadFile = File(...), db: Session = Depends(get_db)) -> LogUploadResponse:
    settings = get_settings()
    filename = Path(file.filename or "uploaded.log").name
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded log file is empty.")
    content_hash = hashlib.sha256(content).hexdigest()
    settings.log_data_dir.mkdir(parents=True, exist_ok=True)
    stored_path = settings.log_data_dir / f"{content_hash}{Path(filename).suffix.lower() or '.log'}"
    stored_path.write_bytes(content)
    text = content.decode("utf-8", errors="replace")
    parsed = parse_log_content(text)
    log_file = LogFile(filename=filename, stored_path=str(stored_path), content_hash=content_hash)
    db.add(log_file)
    db.flush()
    failed_count = 0
    for item in parsed:
        if item.get("parse_error"):
            failed_count += 1
        db.add(ParsedLog(log_file_id=log_file.id, **item))
    log_file.parsed_count = len(parsed)
    log_file.failed_count = failed_count
    db.commit()
    db.refresh(log_file)
    samples = [
        {
            "timestamp": item.get("timestamp"),
            "source_ip": item.get("source_ip"),
            "destination_ip": item.get("destination_ip"),
            "username": item.get("username"),
            "hostname": item.get("hostname"),
            "process_name": item.get("process_name"),
            "event_type": item.get("event_type"),
            "message": item.get("message"),
            "parse_error": item.get("parse_error"),
        }
        for item in parsed[:10]
    ]
    return LogUploadResponse(
        log_file_id=log_file.id,
        filename=filename,
        parsed_count=log_file.parsed_count,
        failed_count=failed_count,
        samples=samples,
    )
