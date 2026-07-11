from __future__ import annotations

import httpx

from app.config import Settings, get_settings
from app.errors import ToolNotConfiguredError


class SIEMClient:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.api_url = self.settings.SIEM_API_URL
        self.api_key = self.settings.SIEM_API_KEY

    def ensure_configured(self) -> None:
        if not self.api_url or not self.api_key:
            raise ToolNotConfiguredError("SIEM API is not configured. No real query was executed.")

    async def query_logs(self, query: dict) -> dict:
        self.ensure_configured()
        url = f"{self.api_url.rstrip('/')}/query"
        async with httpx.AsyncClient(verify=self.settings.SIEM_VERIFY_SSL, timeout=60) as client:
            response = await client.post(
                url,
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json=query,
            )
            response.raise_for_status()
            try:
                body = response.json()
            except Exception:
                body = {"text": response.text}
            return {"vendor": self.settings.SIEM_VENDOR, "status_code": response.status_code, "response": body}
