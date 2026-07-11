import { Search, Upload } from "lucide-react";
import { useState } from "react";
import { searchKnowledge, uploadDocument } from "../api/client";
import { JsonBlock } from "../components/JsonBlock";

export function KnowledgeBase() {
  const [file, setFile] = useState<File | null>(null);
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState("");

  async function submitUpload() {
    if (!file) return;
    setError("");
    try {
      setResult(await uploadDocument(file));
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function submitSearch() {
    setError("");
    try {
      setResult(await searchKnowledge(query));
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <section>
      <h1>Knowledge Base</h1>
      {error && <div className="alert bad">{error}</div>}
      <div className="panel">
        <h2>上传文档入库</h2>
        <div className="form-row">
          <input type="file" accept=".pdf,.txt,.md,.csv,.json,.log" onChange={(event) => setFile(event.target.files?.[0] || null)} />
          <button onClick={submitUpload} disabled={!file} title="上传并写入 Chroma">
            <Upload size={18} />
          </button>
        </div>
      </div>
      <div className="panel">
        <h2>检索测试</h2>
        <div className="form-row">
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="输入 CVE、攻击技术、日志关键词" />
          <button onClick={submitSearch} disabled={!query.trim()} title="检索知识库">
            <Search size={18} />
          </button>
        </div>
      </div>
      {result && <JsonBlock data={result} />}
    </section>
  );
}
