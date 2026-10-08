import { useEffect, useMemo, useState } from 'react';
import {
  api,
  ApiError,
  type AgentChainStep,
  type AnalysisResult,
  type Citation,
  type KnowledgeStatus,
  type MemoryRecord,
  type MemoryStatus,
  type ModelConfig,
  type ReasoningTrace,
  type ReviewDiagnostic,
  type ToolDefinition,
  type ToolExecution,
} from './api';
import { ReportRenderer } from './ReportRenderer';

type Page = 'analysis' | 'tools' | 'memory' | 'knowledge' | 'settings';

const sampleAlert = {
  name: 'SQL 注入攻击',
  description: '互联网来源向查询接口提交 UNION SELECT 载荷',
  srcIp: ['203.0.113.50'],
  dstIp: ['10.0.0.20'],
  protocol: 'http',
  riskLevel: 3,
  eventTime: '2026-08-30T09:30:00+08:00',
  url: '/api/search?id=1 UNION SELECT password FROM users',
  responseBody: 'SQL syntax error',
};

export default function App() {
  const [page, setPage] = useState<Page>('analysis');
  const [knowledge, setKnowledge] = useState<KnowledgeStatus | null>(null);
  const [config, setConfig] = useState<ModelConfig | null>(null);
  const [memory, setMemory] = useState<MemoryStatus | null>(null);

  async function reload(): Promise<void> {
    const [knowledgeStatus, modelConfig, memoryStatus] = await Promise.all([
      api.knowledgeStatus(),
      api.config(),
      api.memoryStatus(),
    ]);
    setKnowledge(knowledgeStatus);
    setConfig(modelConfig);
    setMemory(memoryStatus);
  }

  useEffect(() => {
    void reload();
  }, []);

  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <span>AI</span>
          <div>
            <b>SECURITY</b>
            <small>AGENT WORKBENCH</small>
          </div>
        </div>
        <nav>
          <NavButton active={page === 'analysis'} onClick={() => setPage('analysis')} label="安全研判" icon="◎" />
          <NavButton active={page === 'tools'} onClick={() => setPage('tools')} label="Agent 工具" icon="⌘" />
          <NavButton active={page === 'memory'} onClick={() => setPage('memory')} label="记忆与反馈" icon="◌" />
          <NavButton active={page === 'knowledge'} onClick={() => setPage('knowledge')} label="内置知识库" icon="◇" />
          <NavButton active={page === 'settings'} onClick={() => setPage('settings')} label="模型供应商" icon="⚙" />
        </nav>
        <div className="side-status">
          <span className={knowledge?.ready ? 'dot online' : 'dot'} />
          <div>
            <b>{knowledge?.ready ? 'AGENT READY' : 'LOADING'}</b>
            <small>{memory?.learned_count ?? 0} 条已授权经验 · {knowledge?.chunk_count ?? 0} 知识片段</small>
          </div>
        </div>
      </aside>
      <main>
        <header>
          <div>
            <small>AI SECURITY / {page.toUpperCase()}</small>
            <h1>{pageTitle(page)}</h1>
          </div>
          <span className={`chip ${config?.configured ? 'ok' : ''}`}>
            {config?.configured ? `${config.provider_label} · ${config.model}` : '模型未配置 · 研判不可用'}
          </span>
        </header>
        {page === 'analysis' && <AnalysisPage modelReady={Boolean(config?.configured)} onMemoryChanged={reload} />}
        {page === 'tools' && <ToolsPage />}
        {page === 'memory' && <MemoryPage status={memory} onChanged={reload} />}
        {page === 'knowledge' && <KnowledgePage status={knowledge} />}
        {page === 'settings' && <SettingsPage config={config} onChanged={reload} />}
      </main>
    </div>
  );
}

function NavButton({ active, onClick, label, icon }: { active: boolean; onClick: () => void; label: string; icon: string }) {
  return (
    <button className={active ? 'active' : ''} onClick={onClick}>
      <span>{icon}</span>
      {label}
    </button>
  );
}

function pageTitle(page: Page): string {
  return {
    analysis: 'Agent 安全告警研判',
    tools: 'React 工具调用工作台',
    memory: '本地记忆与反馈中心',
    knowledge: '内置 Chroma 向量库',
    settings: '模型与供应商配置',
  }[page];
}

function AnalysisPage({ modelReady, onMemoryChanged }: { modelReady: boolean; onMemoryChanged: () => Promise<void> }) {
  const [alert, setAlert] = useState(JSON.stringify(sampleAlert, null, 2));
  const [requirement, setRequirement] = useState('严格基于证据研判，生成适合 SOC 汇报的完整报告和可视化图表。');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [errorDiagnostic, setErrorDiagnostic] = useState<ReviewDiagnostic | null>(null);
  const [notice, setNotice] = useState('');

  async function run(): Promise<void> {
    if (!modelReady) {
      setError('请先在“模型供应商”中配置大模型并测试连接。');
      return;
    }
    setBusy(true);
    setResult(null);
    setError('');
    setErrorDiagnostic(null);
    setNotice('');
    try {
      setResult(await api.analyze(alert, requirement));
      await onMemoryChanged().catch(() => setNotice('研判已完成；记忆列表刷新失败，请刷新页面查看。'));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '研判失败');
      if (reason instanceof ApiError && reason.details && typeof reason.details === 'object') {
        const detail = reason.details as { diagnostic?: ReviewDiagnostic };
        setErrorDiagnostic(detail.diagnostic ?? null);
      }
    } finally {
      setBusy(false);
    }
  }

  async function copyReport(): Promise<void> {
    if (!result) return;
    await navigator.clipboard.writeText(result.report_markdown);
    setNotice('Markdown 报告已复制');
  }

  function downloadReport(): void {
    if (!result) return;
    const blob = new Blob([result.report_markdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${result.analysis_id}.md`;
    anchor.click();
    URL.revokeObjectURL(url);
    setNotice('Markdown 报告已下载');
  }

  return (
    <div className="page-stack">
      <section className="panel input-panel">
        <div className="panel-title">
          <div>
            <span className="eyebrow">UNTRUSTED INPUT</span>
            <h2>告警 JSON</h2>
            <p>Agent 只调用白名单只读工具；手机号、证件号、邮箱和令牌会先脱敏</p>
          </div>
          <span className="chip">LangChain · LLM 必经研判链</span>
        </div>
        <textarea className="editor" value={alert} onChange={(event) => setAlert(event.target.value)} />
        <label className="field">
          报告与研判要求
          <input value={requirement} onChange={(event) => setRequirement(event.target.value)} />
        </label>
        {error && <div className="error">{error}</div>}
        {errorDiagnostic && <ReviewFailureSummary diagnostic={errorDiagnostic} />}
        <div className="actions">
          <small>{modelReady ? '证据推理 → 报告生成 → 独立复核；模型调用失败才停止，复核未通过仍保留草稿' : '未配置大模型，请先前往“模型供应商”配置并测试连接'}</small>
          <button className="primary" disabled={busy || !modelReady} onClick={() => void run()}>
            {busy ? 'LLM 研判与复核中，请稍候…' : '启动 Agent 研判'}
          </button>
        </div>
      </section>

      {result && (
        <>
          <SummaryHero result={result} />
          {result.review_status === 'failed' && <ReviewStatusBanner result={result} />}
          <section className="panel">
            <span className="eyebrow">VERIFIED MODEL CALLS · {result.framework}</span>
            <h2>本次模型调用</h2>
            <p>以下为实际接口调用记录，不展示模型私密思维链。风险分数为工具计算指标，研判结论与置信度来自 LLM。</p>
            <div className="table-scroll"><table>
              <thead><tr><th>步骤</th><th>模型</th><th>状态</th><th>耗时</th><th>Token</th></tr></thead>
              <tbody>{result.model_calls.map((call, index) => (
                <tr key={index}><td>{call.stage}</td><td>{call.model_provider} / {call.model_name}</td>
                  <td>{call.success ? '成功' : '失败'}</td><td>{(call.latency_ms / 1000).toFixed(1)} 秒</td>
                  <td>{call.usage?.total_tokens ?? '供应商未返回'}</td></tr>
              ))}</tbody>
            </table></div>
            {result.llm_assessment.feedback_checks.map((check) => (
              <p key={check.lesson_id}>{check.lesson_id} · {check.applicable ? '适用' : '不适用'}：{check.check}</p>
            ))}
          </section>
          <AgentChainPanel steps={result.agent_chain} insights={result.memory_insights} review={result.review} />
          <ReasoningPanel traces={result.reasoning_trace} />
          {result.debug_trace && <DebugTracePanel trace={result.debug_trace} />}
          <section className="panel report-panel">
            <div className="panel-title report-toolbar">
              <div>
                <span className="eyebrow">SECURITY REPORT</span>
                <h2>调查与处置报告</h2>
                <p>
                  {new Date(result.generated_at).toLocaleString()} · {result.engine}
                </p>
              </div>
              <div className="button-row compact">
                <button onClick={() => void copyReport()}>复制 Markdown</button>
                <button onClick={downloadReport}>下载 .md</button>
              </div>
            </div>
            {notice && <div className="message inline-message">{notice}</div>}
            <ReportRenderer markdown={result.report_markdown} charts={result.charts} />
          </section>
          <FeedbackPanel memoryId={result.memory_id} onSubmitted={onMemoryChanged} />
          <CitationGrid citations={result.citations} />
        </>
      )}
    </div>
  );
}

function ReviewStatusBanner({ result }: { result: AnalysisResult }) {
  const review = result.review;
  return (
    <div className="error review-failure-summary">
      <b>研判已完成，但独立复核未通过</b>
      <p>{review.failure_reason || '请结合复核规则和修订建议人工确认。'}</p>
      <div className="review-failure-meta">
        <span>范围：{review.error_scope === 'analysis' ? '分析状态/风险' : '报告'}</span>
        <span>类别：{review.error_category || 'UNKNOWN_ERROR'}</span>
        <span>规则：{review.failure_rules?.join('、') || '未提供'}</span>
      </div>
      {review.revision_action && <small>修订动作：{review.revision_action}</small>}
      <small>{result.report_available ? '已保留最后一版报告草稿，未将其标记为已审核通过。' : '当前没有报告草稿，需根据上游复核失败原因重新研判。'}</small>
    </div>
  );
}

function ReviewFailureSummary({ diagnostic }: { diagnostic: ReviewDiagnostic }) {
  const review = diagnostic.review;
  const history = diagnostic.review_history ?? review?.review_iterations ?? [];
  if (!review && !history.length) return null;
  return (
    <div className="error review-failure-summary">
      <b>未交付原因（结构化复核诊断）</b>
      {review && (
        <>
          <p>{review.failure_reason || '复核未通过，未生成可交付结果。'}</p>
          <div className="review-failure-meta">
            <span>类别：{review.error_category || 'UNKNOWN_ERROR'}</span>
            <span>回滚：{review.rollback_target || 'report'}</span>
            <span>规则：{review.failure_rules?.join('、') || '未提供'}</span>
          </div>
          {review.revision_action && <small>修订动作：{review.revision_action}</small>}
        </>
      )}
      {history.length > 0 && (
        <small>
          复核迭代：{history.length} 次；State Version：{diagnostic.state_version ?? '未知'}
        </small>
      )}
    </div>
  );
}

function SummaryHero({ result }: { result: AnalysisResult }) {
  const score = result.summary.risk_score;
  return (
    <section className="summary-hero">
      <div className="risk-gauge" style={{ '--score': `${score * 3.6}deg` } as React.CSSProperties}>
        <div>
          <b>{score}</b>
          <small>/ 100</small>
        </div>
      </div>
      <div className="summary-copy">
        <span className={`severity severity-${result.summary.risk_level}`}>工具风险指标：{result.summary.risk_level}</span>
        <span className={`chip ${result.review_status === 'passed' ? 'ok' : ''}`}>
          {result.review_status === 'passed' ? '复核通过' : '复核未通过 · 已保留草稿'}
        </span>
        <h2>{result.summary.title}</h2>
        <p>{result.summary.key_finding}</p>
        {result.router && (
          <small className="route-meta">
            工具路由：{result.summary.context_id || 'unknown'} → {result.router.primary_workflow} · {result.router.risk_profile_id}
          </small>
        )}
      </div>
      <div className="summary-metrics">
        <div>
          <small>证据覆盖</small>
          <b>{result.summary.evidence_coverage}%</b>
        </div>
        <div>
          <small>LLM 研判置信度</small>
          <b>{result.summary.confidence_score}% · {result.summary.confidence_level}</b>
        </div>
        <div>
          <small>IOC</small>
          <b>{result.summary.ioc_count}</b>
        </div>
        <div>
          <small>工具调用</small>
          <b>{result.reasoning_trace.length}</b>
        </div>
        <div>
          <small>知识引用</small>
          <b>{result.citations.length}</b>
        </div>
      </div>
    </section>
  );
}

function AgentChainPanel({
  steps,
  insights,
  review,
}: {
  steps: AgentChainStep[];
  insights: AnalysisResult['memory_insights'];
  review: AnalysisResult['review'];
}) {
  return (
    <section className="panel chain-panel">
      <div className="panel-title">
        <div>
          <span className="eyebrow">MULTI-AGENT ORCHESTRATION</span>
          <h2>多 Agent 研判链路</h2>
            <p>LangChain 编排工具证据整理、LLM 证据研判、LLM 报告生成和独立 LLM 复核</p>
        </div>
        <span className={`chip ${review.approved ? 'ok' : ''}`}>{review.approved ? 'REVIEW PASSED' : 'REVIEW REQUIRED'}</span>
      </div>
      <div className="agent-flow">
        {steps.map((step, index) => (
          <div className="agent-flow-wrap" key={`${step.agent_id}-${index}`}>
            <article className="agent-node">
              <span>{String(step.step).padStart(2, '0')}</span>
              <b>{step.label}</b>
              <small>{step.role}</small>
              <p>{step.output_summary}</p>
              <code>{step.tools.length ? step.tools.join(' · ') : 'state routing'}</code>
              <em>{step.duration_ms.toFixed(2)} ms</em>
            </article>
            {index < steps.length - 1 && <i className="agent-arrow">→</i>}
          </div>
        ))}
      </div>
      <div className="chain-boundary">
        <b>复核结论：</b>
        {review.boundary}
      </div>
      {insights.length > 0 && (
        <div className="memory-insights">
          <b>本次匹配的用户授权经验</b>
          {insights.map((item) => (
            <article key={item.lesson_id}>
              <code>{item.lesson_id} · {item.feedback_type === 'negative' ? '反面样例' : '正面样例'}</code>
              <span>{item.title}</span>
              <small>{item.learning_directive || item.lesson}</small>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function ReasoningPanel({ traces }: { traces: ReasoningTrace[] }) {
  return (
    <section className="panel trace-panel">
      <div className="panel-title">
        <div>
          <span className="eyebrow">AUDITABLE REASONING</span>
          <h2>可验证推理轨迹</h2>
          <p>展示工具目标、证据来源和结果摘要；不暴露私密思维链、隐藏提示词或敏感凭据</p>
        </div>
        <span className="chip ok">{traces.length} STEPS</span>
      </div>
      <div className="trace-line">
        {traces.map((trace) => (
          <details key={trace.step} className="trace-step">
            <summary>
              <i>{trace.step}</i>
              <div>
                <b>{trace.title}</b>
                <small>{trace.output_summary}</small>
              </div>
              <code>{trace.tool}</code>
            </summary>
            <div className="trace-detail">
              <p>
                <b>目的：</b>
                {trace.purpose}
              </p>
              <p>
                <b>输入摘要：</b>
                {trace.input_summary}
              </p>
              <p>
                <b>证据：</b>
                {trace.evidence.length ? trace.evidence.join('、') : '当前步骤未发现可引用字段'}
              </p>
              <small>
                {trace.status} · {trace.duration_ms.toFixed(2)} ms
              </small>
            </div>
          </details>
        ))}
      </div>
    </section>
  );
}

function DebugTracePanel({ trace }: { trace: NonNullable<AnalysisResult['debug_trace']> }) {
  return (
    <section className="panel debug-panel">
      <div className="panel-title">
        <div>
          <span className="eyebrow">RUNTIME DEBUG MODE</span>
          <h2>结构化运行 Trace</h2>
          <p>仅在后端 ANALYSIS_DEBUG 开启时返回；展示真实阶段、回退、模型调用和语义复核事件。</p>
        </div>
        <span className="chip ok">{trace.schema_version}</span>
      </div>
      <pre>{JSON.stringify(trace, null, 2)}</pre>
    </section>
  );
}

function FeedbackPanel({ memoryId, onSubmitted }: { memoryId: string; onSubmitted: () => Promise<void> }) {
  const [liked, setLiked] = useState<boolean | null>(null);
  const [comment, setComment] = useState('');
  const [learn, setLearn] = useState(false);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);

  function selectVote(value: boolean): void {
    setLiked(value);
    setLearn(false);
  }

  async function submit(): Promise<void> {
    if (liked === null) {
      setMessage('请先选择“有帮助”或“需要改进”');
      return;
    }
    setBusy(true);
    setMessage('');
    try {
      const result = await api.submitFeedback({ memory_id: memoryId, liked, comment, learn });
      setMessage(result.message);
      await onSubmitted().catch(() => setMessage(`${result.message}；列表刷新失败，请刷新页面查看。`));
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : '反馈提交失败');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel feedback-panel">
      <div className="panel-title">
        <div>
          <span className="eyebrow">HUMAN FEEDBACK LOOP</span>
          <h2>本次研判是否有帮助？</h2>
          <p>反馈先保存为本机脱敏记录；明确授权后，由 LLM 提炼正面或反面经验。提炼失败不会计为已学习。</p>
        </div>
        <code>{memoryId}</code>
      </div>
      <div className="feedback-actions">
        <button className={liked === true ? 'vote selected positive' : 'vote'} onClick={() => selectVote(true)}>
          👍 有帮助
        </button>
        <button className={liked === false ? 'vote selected negative' : 'vote'} onClick={() => selectVote(false)}>
          👎 需要改进
        </button>
      </div>
      <label className="field">
        反馈说明（普通评价可选，学习请填写具体问题或认可点；{comment.length}/2000）
        <textarea className="feedback-text" maxLength={2000} value={comment} onChange={(event) => setComment(event.target.value)} placeholder="例如：缺少执行日志却判定攻击成功，下次请先核验执行证据……" />
      </label>
      <label className="check learning-check">
        <input type="checkbox" checked={learn} disabled={liked === null} onChange={(event) => setLearn(event.target.checked)} />
        我明确同意将本次反馈作为可学习样例（包括正面或反面）；后续仅作提示，不能替代新告警的证据。
      </label>
      {message && <div className="message">{message}</div>}
      <div className="actions">
        <small>经验用于后续检索和自检，不修改模型权重，也不能保证完全避免错误。</small>
        <button className="primary" disabled={busy} onClick={() => void submit()}>{busy ? (learn ? '反馈保存与 LLM 提炼中…' : '记录中…') : '提交反馈'}</button>
      </div>
    </section>
  );
}

function ToolsPage() {
  const [tools, setTools] = useState<ToolDefinition[]>([]);
  const [selectedName, setSelectedName] = useState('');
  const [input, setInput] = useState('{}');
  const [result, setResult] = useState<ToolExecution | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const selected = tools.find((item) => item.name === selectedName);

  useEffect(() => {
    void api.tools().then((catalog) => {
      setTools(catalog.tools);
      if (catalog.tools[0]) {
        setSelectedName(catalog.tools[0].name);
        setInput(JSON.stringify(catalog.tools[0].sample_input, null, 2));
      }
    });
  }, []);

  function choose(tool: ToolDefinition): void {
    setSelectedName(tool.name);
    setInput(JSON.stringify(tool.sample_input, null, 2));
    setResult(null);
    setError('');
  }

  async function execute(): Promise<void> {
    setBusy(true);
    setError('');
    try {
      const parsed = JSON.parse(input) as Record<string, unknown>;
      setResult(await api.executeTool(selectedName, parsed));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '工具调用失败');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page-stack tools-page">
      <section className="tool-catalog">
        {tools.map((tool) => (
          <button key={tool.name} className={tool.name === selectedName ? 'tool-card active' : 'tool-card'} onClick={() => choose(tool)}>
            <span>{tool.category}</span>
            <b>{tool.label}</b>
            <p>{tool.description}</p>
            <small>
              {tool.safety} · {tool.name}
            </small>
          </button>
        ))}
      </section>
      <section className="tool-console">
        <div className="panel tool-input">
          <div className="panel-title">
            <div>
              <span className="eyebrow">TOOL INPUT</span>
              <h2>{selected?.label ?? '加载工具'}</h2>
              <p>React 通过受控 API 调用后端白名单工具</p>
            </div>
            <span className="chip ok">READ ONLY</span>
          </div>
          <textarea className="editor tool-editor" value={input} onChange={(event) => setInput(event.target.value)} />
          {error && <div className="error">{error}</div>}
          <div className="actions">
            <small>参数必须是 JSON 对象</small>
            <button className="primary" disabled={busy || !selectedName} onClick={() => void execute()}>
              {busy ? '执行中…' : '调用工具'}
            </button>
          </div>
        </div>
        <div className="panel tool-output">
          <div className="panel-title">
            <div>
              <span className="eyebrow">STRUCTURED OUTPUT</span>
              <h2>工具结果</h2>
              <p>{result ? `${result.status} · ${result.duration_ms.toFixed(2)} ms` : '等待调用'}</p>
            </div>
          </div>
          <pre>{result ? JSON.stringify(result.output, null, 2) : '// 结果将在这里显示'}</pre>
        </div>
      </section>
    </div>
  );
}

function MemoryPage({ status, onChanged }: { status: MemoryStatus | null; onChanged: () => Promise<void> }) {
  const [records, setRecords] = useState<MemoryRecord[]>([]);
  const [busy, setBusy] = useState(false);

  async function refresh(): Promise<void> {
    setBusy(true);
    try {
      const recent = await api.recentMemories();
      setRecords(recent.records);
      await onChanged();
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  return (
    <div className="page-stack memory-page">
      <section className="memory-hero">
        <div>
          <span className="eyebrow">LOCAL, REDACTED, USER-GOVERNED</span>
          <h2>每次研判输入都会记录在本机</h2>
          <p>{status?.storage ?? '正在读取本机记忆状态'}。敏感字段先脱敏；学习必须由用户选择评价并明确勾选授权，点踩也会作为反面样例保存。</p>
        </div>
        <button onClick={() => void refresh()} disabled={busy}>{busy ? '刷新中…' : '刷新记录'}</button>
      </section>
      <section className="stats memory-stats">
        <div><small>已记录输入</small><b>{status?.input_count ?? 0}</b></div>
        <div><small>用户反馈</small><b>{status?.feedback_count ?? 0}</b></div>
        <div><small>正向点赞</small><b>{status?.liked_count ?? 0}</b></div>
        <div><small>已学习经验</small><b>{status?.learned_count ?? 0}</b></div>
      </section>
      <section className="panel">
        <div className="panel-title">
          <div>
            <span className="eyebrow">APPEND-ONLY MEMORY LOG</span>
            <h2>最近输入与反馈</h2>
            <p>{status?.learning_policy}</p>
          </div>
        </div>
        {records.length ? (
          <div className="memory-records">
            {records.map((record) => (
              <article key={record.memory_id}>
                <div>
                  <span className={`record-status ${record.status}`}>{record.status}</span>
                  <b>{record.title}</b>
                  <small>{new Date(record.created_at).toLocaleString()} · {record.memory_id}</small>
                </div>
                <div className="record-metrics">
                  <span>风险 {record.risk_score ?? '-'} {record.risk_level}</span>
                  <span>{record.feedback_count} 条反馈</span>
                  <span>{record.learning_status === 'learned' ? 'LLM 已提炼' : record.learning_status === 'not_learned' ? '已授权 · 尚未提炼成功' : '未授权学习'}</span>
                </div>
              </article>
            ))}
          </div>
        ) : (
          <div className="empty-memory">尚未保存研判输入。运行一次“安全研判”后，脱敏记录会出现在这里。</div>
        )}
      </section>
    </div>
  );
}

function KnowledgePage({ status }: { status: KnowledgeStatus | null }) {
  const [query, setQuery] = useState('SQL 注入 证据 处置');
  const [results, setResults] = useState<Citation[]>([]);
  const [busy, setBusy] = useState(false);
  async function search(): Promise<void> {
    setBusy(true);
    try {
      setResults((await api.search(query)).results);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="page-stack">
      <section className="stats">
        <div>
          <small>状态</small>
          <b>{status?.ready ? '已内置' : '未就绪'}</b>
        </div>
        <div>
          <small>文档</small>
          <b>{status?.document_count ?? 0}</b>
        </div>
        <div>
          <small>向量片段</small>
          <b>{status?.chunk_count ?? 0}</b>
        </div>
        <div>
          <small>嵌入</small>
          <b>{status?.embedding ?? '-'}</b>
        </div>
      </section>
      <section className="panel">
        <div className="panel-title">
          <div>
            <h2>向量检索</h2>
            <p>{status?.storage}</p>
          </div>
        </div>
        <div className="search">
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') void search();
            }}
          />
          <button className="primary" disabled={busy} onClick={() => void search()}>
            {busy ? '检索中…' : '检索'}
          </button>
        </div>
      </section>
      <CitationGrid citations={results} />
    </div>
  );
}

function SettingsPage({ config, onChanged }: { config: ModelConfig | null; onChanged: () => Promise<void> }) {
  const [apiKey, setApiKey] = useState('');
  const [provider, setProvider] = useState(config?.provider ?? 'deepseek');
  const [model, setModel] = useState(config?.model ?? 'deepseek-chat');
  const [baseUrl, setBaseUrl] = useState(config?.base_url ?? 'https://api.deepseek.com');
  const [persist, setPersist] = useState(true);
  const [message, setMessage] = useState('');
  const preset = useMemo(() => config?.providers.find((item) => item.id === provider), [config, provider]);

  useEffect(() => {
    if (!config) return;
    setProvider(config.provider);
    setModel(config.model);
    setBaseUrl(config.base_url);
  }, [config]);

  function changeProvider(value: string): void {
    setProvider(value);
    const next = config?.providers.find((item) => item.id === value);
    if (next) {
      setModel(next.default_model);
      setBaseUrl(next.base_url);
    }
  }

  async function save(): Promise<void> {
    try {
      await api.saveConfig({ api_key: apiKey, provider, model, base_url: baseUrl, persist });
      setApiKey('');
      setMessage('模型配置已保存');
      await onChanged();
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : '保存失败');
    }
  }
  async function test(): Promise<void> {
    try {
      const result = await api.testConfig();
      setMessage(`${result.provider}/${result.model}：${result.content}`);
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : '测试失败');
    }
  }
  async function clear(): Promise<void> {
    await api.clearConfig();
    setMessage('API Key 已清除');
    await onChanged();
  }

  return (
    <section className="panel settings">
      <div className="panel-title">
        <div>
          <span className="eyebrow">MODEL ROUTER</span>
          <h2>OpenAI-compatible 模型接口</h2>
          <p>DeepSeek、云端兼容接口或本机模型可以随时切换；API Key 不进入浏览器存储</p>
        </div>
        <span className={`chip ${config?.configured ? 'ok' : ''}`}>{config?.configured ? config.masked_key : '未配置'}</span>
      </div>
      <div className="settings-grid">
        <label className="field">
          供应商
          <select value={provider} onChange={(event) => changeProvider(event.target.value)}>
            {(config?.providers ?? []).map((item) => (
              <option value={item.id} key={item.id}>
                {item.label}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          模型名称
          <input list="model-options" value={model} onChange={(event) => setModel(event.target.value)} />
          <datalist id="model-options">
            {(preset?.models ?? []).map((item) => (
              <option value={item} key={item} />
            ))}
          </datalist>
        </label>
      </div>
      <label className="field">
        接口地址
        <input value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} />
      </label>
      <label className="field">
        API Key
        <input type="password" autoComplete="off" placeholder="输入供应商 API Key" value={apiKey} onChange={(event) => setApiKey(event.target.value)} />
      </label>
      <label className="check">
        <input type="checkbox" checked={persist} onChange={(event) => setPersist(event.target.checked)} />
        保存到 Windows 凭据管理器（推荐）
      </label>
      <div className="notice">非本机地址必须使用 HTTPS。本机 `127.0.0.1`/`localhost` 可使用 HTTP；模型只负责报告增强，基础工具链不依赖模型。</div>
      {message && <div className="message">{message}</div>}
      <div className="button-row">
        <button className="primary" disabled={!apiKey || !model || !baseUrl} onClick={() => void save()}>
          保存配置
        </button>
        <button disabled={!config?.configured} onClick={() => void test()}>
          测试连接
        </button>
        <button className="danger" onClick={() => void clear()}>
          清除 Key
        </button>
      </div>
    </section>
  );
}

function CitationGrid({ citations }: { citations: Citation[] }) {
  if (!citations.length) return null;
  return (
    <section className="panel">
      <div className="panel-title">
        <div>
          <span className="eyebrow">TRACEABLE SOURCES</span>
          <h2>知识库引用</h2>
          <p>结果来自项目内置 Chroma 集合，每条引用保留文件与分块</p>
        </div>
      </div>
      <div className="citations">
        {citations.map((item) => (
          <article key={item.chunk_id}>
            <b>
              [{item.id}] {item.title}
            </b>
            <small>
              {item.source} · {item.score.toFixed(3)}
            </small>
            <p>{item.excerpt}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
