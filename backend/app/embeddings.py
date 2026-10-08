from __future__ import annotations

import hashlib
import math
import re

from langchain_core.embeddings import Embeddings


class LocalSecurityEmbeddings(Embeddings):
    """Deterministic local embeddings with no model download or API call.

    Chinese character bigrams and Latin security tokens are projected into a
    normalized hashing vector. The same implementation is used when building
    and querying the bundled Chroma collection.
    """

    dimensions = 384

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(text) for text in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)

    def _embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        for token in _tokens(text):
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
            bucket = int.from_bytes(digest[:4], "big") % self.dimensions
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[bucket] += sign
        norm = math.sqrt(sum(value * value for value in vector))
        return [value / norm for value in vector] if norm else vector


def _tokens(text: str) -> list[str]:
    lowered = text.lower()
    latin = re.findall(r"[a-z0-9_./:-]{2,}", lowered)
    chinese_runs = re.findall(r"[\u3400-\u9fff]+", lowered)
    chinese = [
        run[index : index + 2]
        for run in chinese_runs
        for index in range(max(1, len(run) - 1))
    ]
    return latin + chinese
