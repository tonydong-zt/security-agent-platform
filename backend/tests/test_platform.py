from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.agents.graph import build_security_graph
from app.config import Settings, require_embedding_config
from app.database import SessionLocal, init_db
from app.main import app
from app.tools.rag_tools import retrieve_security_knowledge


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_health_config_missing():
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["backend"] == "ok"
    assert body["llm"] in {"ok", "missing_config"}
    assert "missing_required_config" in body


def test_gemini_embedding_missing_config():
    settings = Settings(EMBEDDING_PROVIDER="gemini", GEMINI_API_KEY="", GEMINI_EMBEDDING_MODEL="")
    with pytest.raises(Exception) as exc:
        require_embedding_config(settings)
    assert "GEMINI_API_KEY" in str(exc.value)
    assert "GEMINI_EMBEDDING_MODEL" in str(exc.value)


def test_chroma_empty_retrieval():
    result = retrieve_security_knowledge("CVE-2099-0001")
    assert result["status"] in {"empty", "error"}
    assert result["results"] == []
    assert result["reason"]


def test_document_upload(monkeypatch):
    class FakeVectorStore:
        def add_documents(self, documents, ids):
            self.documents = documents
            self.ids = ids

    monkeypatch.setattr("app.rag.ingest.get_vectorstore", lambda settings=None: FakeVectorStore())
    client = TestClient(app)
    response = client.post(
        "/api/documents/upload",
        files={"file": ("note.txt", b"phishing login alert\nsource ip 1.2.3.4", "text/plain")},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["chunk_count"] >= 1


def test_log_upload_parse():
    client = TestClient(app)
    data = (
        b'{"timestamp":"2026-01-01T00:00:00Z","src_ip":"10.0.0.1",'
        b'"user":"alice","host":"host-a","process":"powershell.exe",'
        b'"event_type":"process_start","message":"suspicious"}'
    )
    response = client.post("/api/logs/upload", files={"file": ("events.log", data, "text/plain")})
    assert response.status_code == 200
    body = response.json()
    assert body["parsed_count"] == 1
    assert body["samples"][0]["source_ip"] == "10.0.0.1"
    assert body["samples"][0]["username"] == "alice"


def test_investigate_without_llm_config_fails_clearly(monkeypatch):
    monkeypatch.setattr("app.agents.graph.require_llm_config", lambda settings=None: (_ for _ in ()).throw(Exception("LLM missing")))
    client = TestClient(app)
    response = client.post("/api/investigate", json={"query": "analyze this alert", "alert_text": "src_ip=10.0.0.1 powershell.exe"})
    assert response.status_code == 200
    body = response.json()
    assert body["final_answer"] is None
    assert body["errors"]


def test_investigate_with_mocked_llm_executes_graph_nodes(monkeypatch):
    class FakeLLM:
        def invoke(self, prompt):
            if "判断意图" in prompt:
                return SimpleNamespace(content="alert investigation")
            return SimpleNamespace(content="Based on alert and log evidence, risk level high. Suspicious powershell execution was observed.")

    monkeypatch.setattr("app.agents.graph.require_llm_config", lambda settings=None: None)
    monkeypatch.setattr("app.agents.graph.get_chat_model", lambda settings=None: FakeLLM())
    with SessionLocal() as db:
        result = build_security_graph(db).invoke(
            {
                "user_query": "analyze this alert",
                "alert_text": "src_ip=10.0.0.1 user=alice process=powershell.exe",
                "case_id": None,
                "use_uploaded_logs": True,
                "use_knowledge_base": True,
                "approved_actions": [],
                "uploaded_logs": [],
                "retrieved_docs": [],
                "tool_results": [],
                "evidence_chain": [],
                "recommended_actions": [],
                "requires_human_approval": True,
                "executed_actions": [],
                "agent_trace": [],
                "errors": [],
            }
        )
    nodes = [step["node"] for step in result["agent_trace"]]
    assert "validate_runtime_config" in nodes
    assert "threat_analysis" in nodes
    assert "report_generation" in nodes
    assert result["final_report"]


def test_firewall_execute_without_config_returns_tool_not_configured():
    client = TestClient(app)
    response = client.post("/api/actions/approve", json={"action_type": "firewall_block_ip", "target": "203.0.113.10", "approved": True})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "failed"
    assert body["code"] == "tool_not_configured"
    assert "No real action was executed" in body["message"]


def test_no_fake_success_for_unconfigured_action():
    client = TestClient(app)
    response = client.post("/api/actions/approve", json={"action_type": "edr_isolate_host", "target": "host-a", "approved": True})
    body = response.json()
    assert body["status"] != "ok"
    assert body["code"] == "tool_not_configured"
