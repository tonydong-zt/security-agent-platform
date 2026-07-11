import type { HealthResponse, InvestigationResponse } from "../types/api";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, options);
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      detail = await response.text();
    }
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}

export function getHealth() {
  return request<HealthResponse>("/api/health");
}

export function uploadDocument(file: File) {
  const body = new FormData();
  body.append("file", file);
  return request<Record<string, unknown>>("/api/documents/upload", { method: "POST", body });
}

export function searchKnowledge(query: string) {
  return request<Record<string, unknown>>(`/api/documents/search?query=${encodeURIComponent(query)}`);
}

export function uploadLogs(file: File) {
  const body = new FormData();
  body.append("file", file);
  return request<Record<string, unknown>>("/api/logs/upload", { method: "POST", body });
}

export function investigate(payload: Record<string, unknown>) {
  return request<InvestigationResponse>("/api/investigate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
}

export function getCase(caseId: string) {
  return request<Record<string, unknown>>(`/api/cases/${encodeURIComponent(caseId)}`);
}

export function approveAction(payload: Record<string, unknown>) {
  return request<Record<string, unknown>>("/api/actions/approve", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
}

export function reportUrl(caseId: string) {
  return `${API_BASE}/api/cases/${encodeURIComponent(caseId)}/report.md`;
}
