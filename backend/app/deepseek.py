"""向后兼容导入；新代码使用 provider-neutral model_client。"""

from __future__ import annotations

from .model_client import chat

__all__ = ["chat"]
