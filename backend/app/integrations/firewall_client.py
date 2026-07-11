from __future__ import annotations

import httpx

from app.config import Settings, get_settings
from app.errors import ToolNotConfiguredError


class FirewallClient:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.api_url = self.settings.FIREWALL_API_URL
        self.api_key = self.settings.FIREWALL_API_KEY

    def ensure_configured(self) -> None:
        if not self.api_url or not self.api_key:
            raise ToolNotConfiguredError("Firewall API is not configured. No real action was executed.")

    async def block_ip(self, ip: str) -> dict:
        self.ensure_configured()
        url = f"{self.api_url.rstrip('/')}/block-ip"
        async with httpx.AsyncClient(verify=self.settings.FIREWALL_VERIFY_SSL, timeout=30) as client:
            response = await client.post(
                url,
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={"ip": ip, "reason": "security_agent_human_approved_block"},
            )
            response.raise_for_status()
            try:
                body = response.json()
            except Exception:
                body = {"text": response.text}
            return {"vendor": self.settings.FIREWALL_VENDOR, "status_code": response.status_code, "response": body}
