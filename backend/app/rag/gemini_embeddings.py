from __future__ import annotations

from typing import Any

from langchain_core.embeddings import Embeddings

from app.config import Settings


class GeminiEmbeddings(Embeddings):
    """LangChain-compatible Gemini embedding adapter.

    The Google Gemini API is not OpenAI-compatible for embeddings, so this
    adapter calls the native Google GenAI SDK and exposes LangChain's
    embed_documents/embed_query interface for Chroma.
    """

    def __init__(self, settings: Settings, batch_size: int = 64):
        if not settings.GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY is missing")
        if not settings.GEMINI_EMBEDDING_MODEL:
            raise ValueError("GEMINI_EMBEDDING_MODEL is missing")
        from google import genai

        self.client = genai.Client(api_key=settings.GEMINI_API_KEY)
        self.model = settings.GEMINI_EMBEDDING_MODEL
        self.document_task_type = settings.GEMINI_EMBEDDING_TASK_TYPE or "RETRIEVAL_DOCUMENT"
        self.output_dimension = settings.GEMINI_EMBEDDING_OUTPUT_DIMENSION
        self.batch_size = batch_size

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        if self._uses_embedding_2():
            return [self._embed_single_v2(self._format_document(text), is_query=False) for text in texts]
        embeddings: list[list[float]] = []
        for start in range(0, len(texts), self.batch_size):
            batch = texts[start : start + self.batch_size]
            embeddings.extend(self._embed(batch, task_type=self.document_task_type))
        return embeddings

    def embed_query(self, text: str) -> list[float]:
        if self._uses_embedding_2():
            return self._embed_single_v2(f"task: search result | query: {text}", is_query=True)
        return self._embed([text], task_type="RETRIEVAL_QUERY")[0]

    def _embed(self, texts: list[str], task_type: str) -> list[list[float]]:
        from google.genai import types

        config_kwargs: dict[str, Any] = {"task_type": task_type}
        if self.output_dimension:
            config_kwargs["output_dimensionality"] = self.output_dimension

        response = self.client.models.embed_content(
            model=self.model,
            contents=texts,
            config=types.EmbedContentConfig(**config_kwargs),
        )
        raw_embeddings = getattr(response, "embeddings", None)
        if not raw_embeddings:
            raise RuntimeError("Gemini embedding API returned no embeddings.")

        vectors: list[list[float]] = []
        for item in raw_embeddings:
            values = getattr(item, "values", None)
            if values is None and isinstance(item, dict):
                values = item.get("values")
            if not values:
                raise RuntimeError("Gemini embedding API returned an empty vector.")
            vectors.append([float(value) for value in values])
        return vectors

    def _embed_single_v2(self, text: str, is_query: bool) -> list[float]:
        from google.genai import types

        config = None
        if self.output_dimension:
            config = types.EmbedContentConfig(output_dimensionality=self.output_dimension)
        response = self.client.models.embed_content(
            model=self.model,
            contents=text,
            config=config,
        )
        raw_embeddings = getattr(response, "embeddings", None)
        if not raw_embeddings:
            raise RuntimeError("Gemini embedding API returned no embeddings.")
        values = getattr(raw_embeddings[0], "values", None)
        if values is None and isinstance(raw_embeddings[0], dict):
            values = raw_embeddings[0].get("values")
        if not values:
            role = "query" if is_query else "document"
            raise RuntimeError(f"Gemini embedding API returned an empty {role} vector.")
        return [float(value) for value in values]

    def _uses_embedding_2(self) -> bool:
        return self.model.endswith("embedding-2") or "gemini-embedding-2" in self.model

    def _format_document(self, text: str) -> str:
        return f"title: none | text: {text}"
