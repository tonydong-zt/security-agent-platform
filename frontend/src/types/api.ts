export type HealthResponse = {
  backend: string;
  database: string;
  chroma: string;
  llm: string;
  embedding: string;
  siem: string;
  edr: string;
  firewall: string;
  missing_required_config: string[];
  details: Record<string, unknown>;
};

export type InvestigationResponse = {
  case_id: string;
  final_answer: string | null;
  risk_level: string | null;
  attack_type: string | null;
  evidence: Record<string, unknown>[];
  recommended_actions: Record<string, unknown>[];
  tool_calls: Record<string, unknown>[];
  retrieved_knowledge: Record<string, unknown>[];
  agent_trace: Array<Record<string, unknown> | string>;
  requires_human_approval: boolean;
  errors: Array<Record<string, unknown> | string>;
};
