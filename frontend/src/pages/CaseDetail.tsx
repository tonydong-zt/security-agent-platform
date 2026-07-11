import { Download, Search } from "lucide-react";
import { useState } from "react";
import { getCase, reportUrl } from "../api/client";
import { JsonBlock } from "../components/JsonBlock";

export function CaseDetail() {
  const [caseId, setCaseId] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      setResult(await getCase(caseId));
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <section>
      <h1>Case Detail</h1>
      {error && <div className="alert bad">{error}</div>}
      <div className="panel">
        <h2>查询 Case</h2>
        <div className="form-row">
          <input value={caseId} onChange={(event) => setCaseId(event.target.value)} placeholder="case_id" />
          <button onClick={load} disabled={!caseId.trim()} title="查询">
            <Search size={18} />
          </button>
          <a className={`button ${caseId.trim() ? "" : "disabled"}`} href={caseId.trim() ? reportUrl(caseId) : undefined} title="下载 Markdown 报告">
            <Download size={18} />
          </a>
        </div>
      </div>
      {result && <JsonBlock data={result} />}
    </section>
  );
}
