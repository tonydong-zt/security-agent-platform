"""Replay the persisted E7854CE3B57C alert through the configured real model.

Only a redacted diagnostic summary is printed.  The report, prompt context,
API key, and response contents are intentionally not printed.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from app.agent_tools import redact
from app.analysis import analyze
from app.memory import INPUTS_PATH, memory_store
from app.model_client import ModelExecutionError

TARGET_MEMORY_ID = "MEM-E7854CE3B57C"


def _target_input() -> tuple[dict[str, Any] | str, str]:
    rows = [
        json.loads(line)
        for line in INPUTS_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    row = next(item for item in reversed(rows) if item.get("memory_id") == TARGET_MEMORY_ID)
    alert = row["alert"]
    if isinstance(alert, str):
        alert = json.loads(alert)
    return alert, str(row.get("requirement", ""))


def _summary(review: dict[str, Any], history: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "status": review.get("status"),
        "approved": review.get("approved"),
        "error_code": review.get("error_code"),
        "error_category": review.get("error_category"),
        "failure_type": review.get("failure_type"),
        "failure_rules": review.get("failure_rules", []),
        "failure_reason": review.get("failure_reason", ""),
        "rollback_target": review.get("rollback_target"),
        "revision_action": review.get("revision_action", ""),
        "review_iterations": history or review.get("review_iterations", []),
        "state_version": review.get("state_version"),
        "state_fingerprint": review.get("state_fingerprint"),
        "report_fingerprint": review.get("report_fingerprint"),
    }


async def main() -> None:
    alert, requirement = _target_input()
    # The persisted sample is historical sensitive data.  Preserve its schema,
    # field paths, HTTP status, and credential-field existence, but never send
    # credential values or Cookie/Authorization contents to the provider.
    alert = redact(alert)
    replay_memory_id = memory_store.create_input(alert, requirement)
    try:
        result = await analyze(alert, requirement, True, memory_id=replay_memory_id)
    except ModelExecutionError as error:
        diagnostic = error.diagnostic if isinstance(error.diagnostic, dict) else {}
        review = diagnostic.get("review") or {}
        print(
            json.dumps(
                {
                    "status": "failed",
                    "memory_id": replay_memory_id,
                    "api_error_code": error.code,
                    "stage": error.stage,
                    "diagnostic": _summary(review, diagnostic.get("review_history")),
                },
                ensure_ascii=False,
            )
        )
        return
    review = result.get("review") or {}
    print(
        json.dumps(
            {
                "status": "completed",
                "memory_id": replay_memory_id,
                "analysis_id": result.get("analysis_id"),
                "review": _summary(review),
                "router": {
                    "selected_scene_id": (result.get("router") or {}).get("selected_scene_id"),
                    "workflow_id": (result.get("router") or {}).get("workflow_id"),
                    "risk_profile_id": (result.get("router") or {}).get("risk_profile_id"),
                },
                "model_stages": [call.get("stage") for call in result.get("model_calls", [])],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
