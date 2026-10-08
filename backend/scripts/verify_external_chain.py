"""Run the configured external model on a non-production synthetic alert."""

from __future__ import annotations

import asyncio
import json

from app.analysis import analyze
from app.memory import memory_store
from app.model_client import ModelExecutionError

SYNTHETIC_ALERT = {
    "name": "合成凭据字段暴露验证样本",
    "description": "Synthetic only; not copied from a production alert.",
    "protocol": "http",
    "url": "/api/demo/resource",
    "requestHead": "GET /api/demo/resource HTTP/1.1\r\nHost: synthetic.example\r\nCookie: session=synthetic-session\r\n",
    "responseHead": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n",
    "responseBody": json.dumps(
        {
            "ret": True,
            "code": "SUCCESS",
            "data": {"profile": {"credential": "SYNTHETIC_VALUE_ONLY"}},
        },
        ensure_ascii=False,
    ),
}


async def main() -> None:
    memory_id = memory_store.create_input(
        SYNTHETIC_ALERT,
        "严格基于证据研判，验证真实外部模型链路和复核诊断。",
    )
    try:
        result = await analyze(
            SYNTHETIC_ALERT,
            "严格基于证据研判，验证真实外部模型链路和复核诊断。",
            True,
            memory_id=memory_id,
        )
    except ModelExecutionError as error:
        diagnostic = error.diagnostic if isinstance(error.diagnostic, dict) else {}
        review = diagnostic.get("review") or {}
        print(
            json.dumps(
                {
                    "status": "failed",
                    "memory_id": memory_id,
                    "api_error_code": error.code,
                    "stage": error.stage,
                    "diagnostic_error_code": diagnostic.get("error_code"),
                    "error_category": review.get("error_category"),
                    "failure_rules": review.get("failure_rules", []),
                    "failure_reason": review.get("failure_reason", ""),
                    "model_stages": [
                        call.get("stage") for call in diagnostic.get("model_calls", [])
                    ],
                },
                ensure_ascii=False,
            )
        )
        return
    print(
        json.dumps(
            {
                "status": "completed",
                "memory_id": memory_id,
                "analysis_id": result.get("analysis_id"),
                "review_approved": (result.get("review") or {}).get("approved"),
                "state_version": result.get("state_version"),
                "router": {
                    "selected_scene_id": (result.get("router") or {}).get("selected_scene_id"),
                    "workflow_id": (result.get("router") or {}).get("workflow_id"),
                },
                "model_stages": [call.get("stage") for call in result.get("model_calls", [])],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
