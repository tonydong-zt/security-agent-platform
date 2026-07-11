from __future__ import annotations

from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models import InvestigationCase, ParsedLog


def search_uploaded_logs(entities: dict[str, Any], db: Session, time_range: dict | None = None, limit: int = 50) -> dict[str, Any]:
    query = db.query(ParsedLog)
    filters = []
    for ip in entities.get("ips", []) or []:
        filters.append(ParsedLog.source_ip == ip)
        filters.append(ParsedLog.destination_ip == ip)
        filters.append(ParsedLog.raw_message.ilike(f"%{ip}%"))
    for username in entities.get("usernames", []) or []:
        filters.append(ParsedLog.username.ilike(f"%{username}%"))
        filters.append(ParsedLog.raw_message.ilike(f"%{username}%"))
    for hostname in entities.get("hostnames", []) or []:
        filters.append(ParsedLog.hostname.ilike(f"%{hostname}%"))
        filters.append(ParsedLog.raw_message.ilike(f"%{hostname}%"))
    for process in entities.get("process_names", []) or []:
        filters.append(ParsedLog.process_name.ilike(f"%{process}%"))
        filters.append(ParsedLog.raw_message.ilike(f"%{process}%"))
    for keyword in entities.get("keywords", []) or []:
        filters.append(ParsedLog.raw_message.ilike(f"%{keyword}%"))
    if filters:
        query = query.filter(or_(*filters))
    total_logs = db.query(ParsedLog).count()
    if total_logs == 0:
        return {"status": "empty", "results": [], "reason": "未发现可用日志，只能基于当前输入和知识库分析。"}
    rows = query.order_by(ParsedLog.created_at.desc()).limit(limit).all()
    results = [
        {
            "id": row.id,
            "timestamp": row.timestamp,
            "source_ip": row.source_ip,
            "destination_ip": row.destination_ip,
            "username": row.username,
            "hostname": row.hostname,
            "process_name": row.process_name,
            "event_type": row.event_type,
            "message": row.message,
            "raw_message": row.raw_message,
        }
        for row in rows
    ]
    if not results:
        return {"status": "ok", "results": [], "reason": "没有找到匹配实体的已上传日志。"}
    return {"status": "ok", "results": results, "reason": None}


def search_historical_cases(entities: dict[str, Any], db: Session, limit: int = 10) -> dict[str, Any]:
    terms = []
    for key in ["ips", "usernames", "hostnames", "process_names", "cves"]:
        terms.extend(entities.get(key, []) or [])
    if not terms:
        return {"status": "ok", "results": [], "reason": "未提取到可用于历史 case 查询的实体。"}
    filters = []
    for term in terms:
        filters.append(InvestigationCase.user_query.ilike(f"%{term}%"))
        filters.append(InvestigationCase.alert_text.ilike(f"%{term}%"))
        filters.append(InvestigationCase.final_answer.ilike(f"%{term}%"))
    rows = db.query(InvestigationCase).filter(or_(*filters)).order_by(InvestigationCase.created_at.desc()).limit(limit).all()
    return {
        "status": "ok",
        "results": [{"id": row.id, "risk_level": row.risk_level, "attack_type": row.attack_type, "created_at": row.created_at.isoformat()} for row in rows],
        "reason": None if rows else "没有找到相关历史 case。",
    }
