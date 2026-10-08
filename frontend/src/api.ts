export class ApiError extends Error {
  status: number;
  details: unknown;

  constructor(message: string, details: unknown = null, status = 0) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

function formatApiError(detail: unknown): string {
  if (typeof detail === 'string' && detail.trim()) {
    return detail;
  }
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (typeof item === 'string') {
          return item;
        }
        if (item && typeof item === 'object') {
          const record = item as { loc?: unknown; msg?: unknown };
          const location = Array.isArray(record.loc)
            ? record.loc.filter((part) => typeof part === 'string' || typeof part === 'number').join('.')
            : '';
          const message = typeof record.msg === 'string' ? record.msg : '';
          return message ? (location ? `${location}: ${message}` : message) : JSON.stringify(item);
        }
        return String(item);
      })
      .filter(Boolean);
    return messages.join('；') || '请求参数校验失败';
  }
  if (detail && typeof detail === 'object') {
    const message = (detail as { message?: unknown }).message;
    if (typeof message === 'string') return message;
    return JSON.stringify(detail);
  }
  return '';
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  });
  if (!response.ok) {
    const payload = (await response.json().catch(() => ({}))) as { detail?: unknown };
    throw new ApiError(formatApiError(payload.detail) || `HTTP ${response.status}`, payload.detail, response.status);
  }
  return (await response.json()) as T;
}

export const api = {
  knowledgeStatus: () => request<KnowledgeStatus>('/api/knowledge/status'),
  search: (query: string) =>
    request<{ query: string; results: Citation[] }>('/api/knowledge/search', {
      method: 'POST',
      body: JSON.stringify({ query, limit: 8 }),
    }),
  analyze: (alert: string, requirement: string) =>
    request<AnalysisResult>('/api/analyze', {
      method: 'POST',
      body: JSON.stringify({ alert, requirement, use_model: true }),
    }),
  tools: () => request<ToolCatalog>('/api/tools'),
  agentChain: () => request<{ nodes: AgentDefinition[]; policy: string }>('/api/agent/chain'),
  executeTool: (tool: string, args: Record<string, unknown>) =>
    request<ToolExecution>('/api/tools/execute', {
      method: 'POST',
      body: JSON.stringify({ tool, arguments: args }),
    }),
  memoryStatus: () => request<MemoryStatus>('/api/memory/status'),
  recentMemories: () => request<{ records: MemoryRecord[] }>('/api/memory/recent'),
  submitFeedback: (input: FeedbackInput) =>
    request<FeedbackResult>('/api/memory/feedback', {
      method: 'POST',
      body: JSON.stringify(input),
    }),
  config: () => request<ModelConfig>('/api/config/model'),
  saveConfig: (input: SaveModelConfig) =>
    request<ModelConfig>('/api/config/model', {
      method: 'PUT',
      body: JSON.stringify(input),
    }),
  clearConfig: () => request<ModelConfig>('/api/config/model', { method: 'DELETE' }),
  testConfig: () =>
    request<{ ok: boolean; content: string; model: string; provider: string }>(
      '/api/config/model/test',
      { method: 'POST' },
    ),
};

export interface Citation {
  id: string;
  chunk_id: string;
  title: string;
  source: string;
  category: string;
  score: number;
  excerpt: string;
}

export interface KnowledgeStatus {
  ready: boolean;
  collection: string;
  document_count: number;
  chunk_count: number;
  embedding: string;
  source_sha256: string;
  storage: string;
}

export interface AnalysisSummary {
  title: string;
  risk_score: number;
  risk_level: string;
  confidence_score: number;
  confidence_level: string;
  evidence_coverage: number;
  ioc_count: number;
  key_finding: string;
  context_id?: string;
  security_problem_id?: string;
  primary_workflow?: string;
  risk_profile_id?: string;
}

export interface ChartDatum {
  label: string;
  value: number;
  color?: string;
}

export interface TimelineEvent {
  time: string;
  label: string;
  source: string;
  description: string;
}

export interface ChartSpec {
  id: string;
  type: 'bar' | 'donut' | 'timeline';
  title: string;
  subtitle: string;
  data?: ChartDatum[];
  events?: TimelineEvent[];
}

export interface ReasoningTrace {
  step: number;
  stage: string;
  title: string;
  tool: string;
  purpose: string;
  input_summary: string;
  output_summary: string;
  evidence: string[];
  duration_ms: number;
  status: string;
}

export interface AnalysisResult {
  run_status: 'completed' | 'failed';
  review_status: 'passed' | 'failed';
  report_available: boolean;
  state_version: number;
  framework: string;
  model_calls: Array<{
    stage: string;
    model_provider: string;
    model_name: string;
    success: boolean;
    latency_ms: number;
    usage?: Record<string, number>;
  }>;
  llm_assessment: {
    conclusion: string;
    verdict: string;
    feedback_checks: Array<{ lesson_id: string; applicable: boolean; check: string }>;
  };
  analysis_id: string;
  memory_id: string;
  generated_at: string;
  engine: string;
  provider: string;
  summary: AnalysisSummary;
  report_markdown: string;
  charts: ChartSpec[];
  reasoning_trace: ReasoningTrace[];
  agent_chain: AgentChainStep[];
  memory_insights: MemoryInsight[];
  review: ReviewResult;
  business_context?: Record<string, unknown>;
  security_problem_candidates?: Array<Record<string, unknown>>;
  router?: WorkflowRoute;
  workflow?: Record<string, unknown>;
  evidence_store?: Record<string, unknown>;
  citations: Citation[];
  usage: Record<string, number>;
  database_used: boolean;
  debug_trace?: DebugTrace;
}

export interface DebugTrace {
  schema_version: string;
  normalization: Record<string, unknown>;
  business_context: Record<string, unknown>;
  security_problem_candidates: Array<Record<string, unknown>>;
  router: WorkflowRoute;
  workflow: Record<string, unknown>;
  evidence_store: Record<string, unknown>;
  scene_candidates: Array<Record<string, unknown>>;
  selected_scene: Record<string, unknown>;
  evidence_template: Array<Record<string, unknown>>;
  evidence: Record<string, unknown>;
  risk_profile: Record<string, unknown>;
  risk: Record<string, unknown>;
  knowledge: Record<string, unknown>;
  semantic_review: Record<string, unknown>;
  structured_state_review: Record<string, unknown>;
  revision_feedback: Record<string, unknown>;
  review_iterations: Array<Record<string, unknown>>;
  fallbacks: Array<Record<string, unknown>>;
  model_calls: Array<Record<string, unknown>>;
  execution_events: Array<Record<string, unknown>>;
}

export interface WorkflowRoute {
  schema_version: string;
  primary_workflow: string;
  workflow_id: string;
  secondary_workflows: string[];
  selected_scene_id: string;
  risk_profile_id: string;
  confidence: number;
  reason: string;
  tool_plan: string[];
  workflow: Record<string, unknown>;
}

export interface AgentDefinition {
  id: string;
  label: string;
  role: string;
}

export interface AgentChainStep {
  step: number;
  agent_id: string;
  label: string;
  role: string;
  status: string;
  input_summary: string;
  output_summary: string;
  next_agent: string | null;
  tools: string[];
  duration_ms: number;
}

export interface MemoryInsight {
  lesson_id: string;
  title: string;
  feedback: string;
  feedback_type: 'positive' | 'negative';
  lesson: string;
  learning_directive: string;
  risk_level: string;
  matched_terms: string[];
  boundary: string;
}

export interface ReviewResult {
  approved: boolean;
  error_scope?: 'none' | 'report' | 'analysis' | string;
  review_status?: 'passed' | 'failed' | string;
  report_available?: boolean;
  status?: string;
  error_category?: string | null;
  failure_type?: string | null;
  failure_rules?: string[];
  issues?: string[];
  failure_details?: string[][];
  failure_reason?: string;
  rollback_target?: string | null;
  revision_action?: string;
  review_iterations?: Array<Record<string, unknown>>;
  state_version?: number;
  generated_from_state_version?: number | null;
  missing_sections: string[];
  conflicts?: Array<{ area: string; detail: string; resolution: string }>;
  boundary?: string;
}

export interface ReviewDiagnostic {
  review?: ReviewResult;
  review_history?: Array<Record<string, unknown>>;
  state_version?: number;
  state_fingerprint?: string;
  report_fingerprint?: string;
}

export interface ApiReviewDetail {
  code?: string;
  stage?: string;
  message?: string;
  diagnostic?: ReviewDiagnostic;
}

export interface MemoryStatus {
  input_count: number;
  feedback_count: number;
  liked_count: number;
  learned_count: number;
  storage: string;
  learning_policy: string;
}

export interface MemoryRecord {
  learning_status: 'learned' | 'not_learned' | 'not_requested';
  memory_id: string;
  created_at: string;
  status: string;
  title: string;
  analysis_id: string;
  risk_level: string;
  risk_score: number | null;
  feedback_count: number;
  liked: boolean | null;
  learn_requested: boolean;
}

export interface FeedbackInput {
  memory_id: string;
  liked: boolean;
  comment: string;
  learn: boolean;
}

export interface FeedbackResult {
  feedback_id: string;
  memory_id: string;
  liked: boolean;
  learning: { created: boolean; lesson_id?: string; reason?: string } | null;
  message: string;
}

export interface ProviderPreset {
  id: string;
  label: string;
  base_url: string;
  default_model: string;
  models: string[];
}

export interface ModelConfig {
  configured: boolean;
  masked_key: string;
  provider: string;
  provider_label: string;
  model: string;
  base_url: string;
  storage: string;
  providers: ProviderPreset[];
}

export interface SaveModelConfig {
  api_key: string;
  provider: string;
  model: string;
  base_url: string;
  persist: boolean;
}

export interface ToolDefinition {
  name: string;
  label: string;
  description: string;
  category: string;
  safety: string;
  input_schema: Record<string, unknown>;
  sample_input: Record<string, unknown>;
}

export interface ToolCatalog {
  tools: ToolDefinition[];
  total: number;
  execution_policy: string;
}

export interface ToolExecution {
  tool: string;
  label: string;
  status: string;
  duration_ms: number;
  output: Record<string, unknown>;
}
