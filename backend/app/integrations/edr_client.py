from __future__ import annotations

import httpx

from app.config import Settings, get_settings
from app.errors import ToolNotConfiguredError


class EDRClient:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.api_url = self.settings.EDR_API_URL
        self.api_key = self.settings.EDR_API_KEY

    def ensure_configured(self) -> None:
        if not self.api_url or not self.api_key:
            raise ToolNotConfiguredError("EDR API is not configured. No real action was executed.")

    async def isolate_host(self, hostname: str) -> dict:
        self.ensure_configured()
        url = f"{self.api_url.rstrip('/')}/isolate-host"
        async with httpx.AsyncClient(verify=self.settings.EDR_VERIFY_SSL, timeout=30) as client:
            response = await client.post(
                url,
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={"hostname": hostname, "reason": "security_agent_human_approved_isolation"},
            )
            response.raise_for_status()
            try:
                body = response.json()
            except Exception:
                body = {"text": response.text}
            return {"vendor": self.settings.EDR_VENDOR, "status_code": response.status_code, "response": body}
