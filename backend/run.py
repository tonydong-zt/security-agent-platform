from __future__ import annotations

import os
import threading
import time
import urllib.request
import webbrowser

import uvicorn
from dotenv import load_dotenv

load_dotenv()


def open_browser_when_ready(port: int) -> None:
    address = f"http://127.0.0.1:{port}"
    for _ in range(120):
        try:
            with urllib.request.urlopen(f"{address}/healthz", timeout=1) as response:
                if response.status == 200:
                    webbrowser.open(address)
                    return
        except OSError:
            time.sleep(0.25)


if __name__ == "__main__":
    server_port = int(os.getenv("PORT", "8090"))
    if os.getenv("OPEN_BROWSER", "1") != "0":
        threading.Thread(
            target=open_browser_when_ready, args=(server_port,), daemon=True
        ).start()
    uvicorn.run("app.main:app", host="127.0.0.1", port=server_port, app_dir="backend")
