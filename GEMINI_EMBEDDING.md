# Gemini Embedding Configuration

This project supports Gemini embeddings through Google's native Gemini API.

Use this configuration in `.env`:

```env
EMBEDDING_PROVIDER=gemini
GEMINI_API_KEY=
GEMINI_EMBEDDING_MODEL=gemini-embedding-001
GEMINI_EMBEDDING_TASK_TYPE=RETRIEVAL_DOCUMENT
GEMINI_EMBEDDING_OUTPUT_DIMENSION=
```

Notes:

- `GEMINI_API_KEY` must be your real Google Gemini API key.
- `GEMINI_EMBEDDING_MODEL` must be an embedding model available to your account.
- `gemini-embedding-001` supports `GEMINI_EMBEDDING_TASK_TYPE`, which defaults to `RETRIEVAL_DOCUMENT` for document chunks.
- Query embeddings automatically use `RETRIEVAL_QUERY` with `gemini-embedding-001`.
- `gemini-embedding-2` is also handled: document chunks are formatted as `title: none | text: ...`, and queries as `task: search result | query: ...`.
- `GEMINI_EMBEDDING_OUTPUT_DIMENSION` can be left empty.
- Do not put a native Gemini URL into `EMBEDDING_BASE_URL`; that field is only for OpenAI-compatible `/embeddings` services.

After editing `.env`, restart the backend and check:

```powershell
curl http://localhost:8000/api/health
```

Expected result when configured correctly:

```json
{
  "embedding": "ok"
}
```

If `GEMINI_API_KEY` or `GEMINI_EMBEDDING_MODEL` is missing, `/api/health` returns `embedding: missing_config` and lists the missing field names.
