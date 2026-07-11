import { RefreshCcw } from "lucide-react";
import { useEffect, useState } from "react";
import { getHealth } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { JsonBlock } from "../components/JsonBlock";
import type { HealthResponse } from "../types/api";

export function Dashboard() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      setHealth(await getHealth());
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const entries = health
    ? [
        ["Backend", health.backend],
        ["Database", health.database],
        ["Chroma", health.chroma],
        ["LLM", health.llm],
        ["Embedding", health.embedding],
        ["SIEM", health.siem],
        ["EDR", health.edr],
        ["Firewall", health.firewall]
      ]
    : [];

  return (
    <section>
      <div className="section-header">
        <h1>Dashboard</h1>
        <button onClick={load} title="刷新状态">
          <RefreshCcw size={18} />
        </button>
      </div>
      {error && <div className="alert bad">{error}</div>}
      <div className="status-grid">
        {entries.map(([label, value]) => (
          <div className="status-row" key={label}>
            <span>{label}</span>
            <StatusBadge value={value} />
          </div>
        ))}
      </div>
      {health?.missing_required_config.length ? (
        <div className="panel warn-panel">
          <h2>缺失配置</h2>
          <div className="tag-list">
            {health.missing_required_config.map((item) => (
              <span className="tag" key={item}>{item}</span>
            ))}
          </div>
        </div>
      ) : null}
      {health && (
        <div className="panel">
          <h2>状态详情</h2>
          <JsonBlock data={health.details} />
        </div>
      )}
    </section>
  );
}
