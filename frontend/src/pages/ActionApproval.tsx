import { ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { approveAction, getHealth } from "../api/client";
import { JsonBlock } from "../components/JsonBlock";
import type { HealthResponse } from "../types/api";

export function ActionApproval() {
  const [caseId, setCaseId] = useState("");
  const [actionType, setActionType] = useState("firewall_block_ip");
  const [target, setTarget] = useState("");
  const [approved, setApproved] = useState(false);
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState("");
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    getHealth().then(setHealth).catch((err) => setError((err as Error).message));
  }, []);

  const toolConfigured =
    actionType === "firewall_block_ip"
      ? health?.firewall === "configured"
      : health?.edr === "configured";

  async function submit() {
    setError("");
    try {
      setResult(await approveAction({ case_id: caseId || null, action_type: actionType, target, approved }));
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <section>
      <h1>Action Approval</h1>
      {error && <div className="alert bad">{error}</div>}
      {health && !toolConfigured && (
        <div className="alert bad">对应外部工具 API 未配置，执行按钮已禁用。系统不会伪造真实封禁或隔离结果。</div>
      )}
      <div className="panel">
        <h2>人工审批</h2>
        <label>Case ID</label>
        <input value={caseId} onChange={(event) => setCaseId(event.target.value)} placeholder="可为空" />
        <label>动作类型</label>
        <select value={actionType} onChange={(event) => setActionType(event.target.value)}>
          <option value="firewall_block_ip">Firewall block IP</option>
          <option value="edr_isolate_host">EDR isolate host</option>
        </select>
        <label>目标</label>
        <input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="IP 或主机名" />
        <div className="checks">
          <label><input type="checkbox" checked={approved} onChange={(event) => setApproved(event.target.checked)} /> 我确认执行真实外部动作</label>
        </div>
        <button onClick={submit} disabled={!target.trim() || !toolConfigured} title="提交审批">
          <ShieldCheck size={18} />
          <span>提交</span>
        </button>
      </div>
      {result && <JsonBlock data={result} />}
    </section>
  );
}
