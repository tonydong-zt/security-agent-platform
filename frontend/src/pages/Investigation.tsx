import { Play } from "lucide-react";
import { useEffect, useState } from "react";
import { getHealth, investigate } from "../api/client";
import { JsonBlock } from "../components/JsonBlock";
import type { HealthResponse } from "../types/api";
import type { InvestigationResponse } from "../types/api";

export function Investigation() {
  const [query, setQuery] = useState("请分析这条告警");
  const [alertText, setAlertText] = useState("");
  const [useLogs, setUseLogs] = useState(true);
  const [useKb, setUseKb] = useState(true);
  const [result, setResult] = useState<InvestigationResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    getHealth().then(setHealth).catch((err) => setError((err as Error).message));
  }, []);

  async function run() {
    setLoading(true);
    setError("");
    try {
      setResult(await investigate({ query, alert_text: alertText, use_uploaded_logs: useLogs, use_knowledge_base: useKb }));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section>
      <h1>Investigation</h1>
      {error && <div className="alert bad">{error}</div>}
      {health?.llm !== "ok" && (
        <div className="alert bad">LLM 未配置，Agent 无法运行。请先在 .env 中补齐 DeepSeek 或 OpenAI-compatible 配置。</div>
      )}
      <div className="panel">
        <h2>发起调查</h2>
        <label>问题</label>
        <input value={query} onChange={(event) => setQuery(event.target.value)} />
        <label>告警文本</label>
        <textarea rows={8} value={alertText} onChange={(event) => setAlertText(event.target.value)} />
        <div className="checks">
          <label><input type="checkbox" checked={useLogs} onChange={(event) => setUseLogs(event.target.checked)} /> 使用已上传日志</label>
          <label><input type="checkbox" checked={useKb} onChange={(event) => setUseKb(event.target.checked)} /> 使用知识库</label>
        </div>
        <button onClick={run} disabled={loading || !query.trim() || health?.llm !== "ok"} title="开始调查">
          <Play size={18} />
          <span>{loading ? "运行中" : "开始"}</span>
        </button>
      </div>
      {result && (
        <div className="results">
          <div className="panel">
            <h2>最终报告</h2>
            <pre className="report">{result.final_answer || "未生成 final_answer。请检查 LLM 配置或错误列表。"}</pre>
          </div>
          <div className="panel">
            <h2>Agent Trace</h2>
            <JsonBlock data={result.agent_trace} />
          </div>
          <div className="panel">
            <h2>检索知识</h2>
            <JsonBlock data={result.retrieved_knowledge} />
          </div>
          <div className="panel">
            <h2>工具调用</h2>
            <JsonBlock data={result.tool_calls} />
          </div>
          <div className="panel">
            <h2>建议动作</h2>
            <JsonBlock data={result.recommended_actions} />
          </div>
          <div className="panel">
            <h2>错误</h2>
            <JsonBlock data={result.errors} />
          </div>
        </div>
      )}
    </section>
  );
}
