import type {
  ActionResponse,
  BatchResult,
  DemoPack,
  EvaluationReport,
  HealthResponse,
  IncidentDetail,
  IncidentList,
  Metrics,
  QueueFilters,
  VerdictFeedback,
} from "../features/incidents";

/** Same-origin in `npm run dev` (Vite proxies to port 8741). Override with VITE_API_BASE. */
export const API_BASE = import.meta.env.VITE_API_BASE ?? "";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, init);
  } catch {
    throw new ApiError(0, "api_unreachable", "The API on port 8741 is not responding.");
  }
  if (!response.ok) {
    let code = "http_error";
    let message = "The request could not be processed.";
    try {
      const body = (await response.json()) as { error?: { code?: string; message?: string } };
      code = body.error?.code ?? code;
      message = body.error?.message ?? message;
    } catch {
      // Keep the generic message when the body is not JSON.
    }
    throw new ApiError(response.status, code, message);
  }
  return (await response.json()) as T;
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/health");
}

export function listIncidents(filters: QueueFilters = {}): Promise<IncidentList> {
  const params = new URLSearchParams();
  params.set("limit", "200");
  if (filters.risk_label) params.set("risk_label", filters.risk_label);
  if (filters.confidence_band) params.set("confidence_band", filters.confidence_band);
  const query = params.toString();
  return request<IncidentList>(`/api/v1/incidents${query ? `?${query}` : ""}`);
}

export function getIncident(id: string): Promise<IncidentDetail> {
  return request<IncidentDetail>(`/api/v1/incidents/${id}`);
}

export function getMetrics(): Promise<Metrics> {
  return request<Metrics>("/api/v1/metrics");
}

export function uploadEml(file: File): Promise<{ incident_id: string }> {
  const body = new FormData();
  body.append("file", file, file.name);
  return request<{ incident_id: string }>("/api/v1/incidents", { method: "POST", body });
}

export function uploadBatch(files: File[]): Promise<BatchResult> {
  const body = new FormData();
  for (const file of files) body.append("files", file, file.name);
  return request<BatchResult>("/api/v1/incidents/batch", { method: "POST", body });
}

export function listDemoPack(): Promise<DemoPack> {
  return request<DemoPack>("/api/v1/demo-pack");
}

export function analyzeDemo(name: string): Promise<{ incident_id: string }> {
  return request<{ incident_id: string }>(`/api/v1/demo-pack/${encodeURIComponent(name)}/analyze`, {
    method: "POST",
  });
}

export function getEvaluation(): Promise<EvaluationReport> {
  return request<EvaluationReport>("/api/v1/evaluation");
}

export function postFeedback(
  id: string,
  payload: { verdict: "correct" | "wrong"; reason: string; analyst_id: string; corrected_label?: string },
): Promise<VerdictFeedback> {
  return request<VerdictFeedback>(`/api/v1/incidents/${id}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function postAction(
  id: string,
  payload: { decision: "approve" | "reject"; reason: string; analyst_id: string },
): Promise<ActionResponse> {
  return request<ActionResponse>(`/api/v1/incidents/${id}/actions/response`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
