from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import init_db
from app.routers import actions, cases, documents, health, investigate, logs


def create_app() -> FastAPI:
    app = FastAPI(
        title="AI Security Agent Platform",
        description="Defensive security operations agent platform with real RAG, logs, cases, and guarded external actions.",
        version="0.1.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(health.router)
    app.include_router(documents.router)
    app.include_router(logs.router)
    app.include_router(investigate.router)
    app.include_router(cases.router)
    app.include_router(actions.router)

    @app.on_event("startup")
    def on_startup() -> None:
        init_db()

    return app


app = create_app()
