"""Manual browser regression fixture, isolated from user keys and memories.

Run with PYTHONPATH=backend, using the dev requirements. Binds only 127.0.0.1:8091.
All model replies are synthetic HTTP fixtures, NOT real-provider verification.
This module is not imported by the production application.
"""
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import uvicorn
from conftest import isolated_config, isolated_memory, mock_llm

if __name__ == "__main__":
    with TemporaryDirectory(prefix="security-ui-test-") as directory, pytest.MonkeyPatch.context() as patch:
        isolated_config.__wrapped__(patch)
        isolated_memory.__wrapped__(Path(directory), patch)
        mock_llm.__wrapped__(patch)
        uvicorn.run("app.main:app", host="127.0.0.1", port=8091)
