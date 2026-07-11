import { Upload } from "lucide-react";
import { useState } from "react";
import { uploadLogs } from "../api/client";
import { JsonBlock } from "../components/JsonBlock";

export function LogUpload() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState("");

  async function submit() {
    if (!file) return;
    setError("");
    try {
      setResult(await uploadLogs(file));
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <section>
      <h1>Log Upload</h1>
      {error && <div className="alert bad">{error}</div>}
      <div className="panel">
        <h2>上传日志</h2>
        <div className="form-row">
          <input type="file" accept=".log,.txt,.json,.csv" onChange={(event) => setFile(event.target.files?.[0] || null)} />
          <button onClick={submit} disabled={!file} title="上传日志">
            <Upload size={18} />
          </button>
        </div>
      </div>
      {result && <JsonBlock data={result} />}
    </section>
  );
}
