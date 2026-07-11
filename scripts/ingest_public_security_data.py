from __future__ import annotations

import tempfile
from pathlib import Path

import httpx

from app.config import get_settings
from app.database import SessionLocal, init_db
from app.rag.ingest import ingest_file


SOURCES = {
    "CISA_KEV_SOURCE_URL": "cisa_kev.json",
    "MITRE_ATTACK_SOURCE_URL": "mitre_attack.json",
    "OWASP_SOURCE_URL": "owasp.md",
}


def main() -> None:
    settings = get_settings()
    init_db()
    configured = [(key, getattr(settings, key), filename) for key, filename in SOURCES.items() if getattr(settings, key)]
    if not configured:
        print("No public security source URL configured. Fill CISA_KEV_SOURCE_URL, MITRE_ATTACK_SOURCE_URL, or OWASP_SOURCE_URL in .env.")
        print("Manual download targets: MITRE ATT&CK Enterprise, CISA KEV catalog, NVD CVE feeds, OWASP Top 10.")
        return
    with SessionLocal() as db:
        for key, url, filename in configured:
            try:
                response = httpx.get(url, timeout=60)
                response.raise_for_status()
                suffix = Path(filename).suffix
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as handle:
                    handle.write(response.content)
                    temp_path = Path(handle.name)
                result = ingest_file(temp_path, filename, db, settings=settings)
                print({key: url, "result": result})
            except Exception as exc:
                print({key: url, "status": "failed", "error": str(exc)})
            finally:
                if "temp_path" in locals() and temp_path.exists():
                    temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
