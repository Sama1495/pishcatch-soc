/** API contract. The backend schemas are the source of truth. */

export type RiskLabel =
  | "likely_malicious"
  | "suspicious"
  | "likely_benign"
  | "inconclusive";

export type CaseStatus = "open" | "in_review" | "closed" | "quarantine_simulated";
export type ConfidenceBand = "high" | "medium" | "low";
export type StepStatus = "done" | "skipped" | "failed" | "waiting";

export interface Indicator {
  id: string;
  type: "email" | "domain" | "url" | "ip" | "attachment" | "header";
  value: string;
  display_value: string;
  context: string | null;
}

export interface Evidence {
  id: string;
  rule_id: string;
  title: string;
  reason: string;
  severity: "info" | "low" | "medium" | "high";
  source: string;
  polarity: string;
  weight: number;
  indicator_value: string | null;
  provenance: {
    producer: string;
    version: string;
    method: string;
    observed_fields: string[];
    notes?: string | null;
  };
}

export interface ConfidenceComponent {
  key: string;
  label: string;
  score: number;
  weight: number;
  weighted_points: number;
  explanation: string;
}

export interface Confidence {
  score: number;
  band: ConfidenceBand;
  formula_version: string;
  ruleset: string;
  raw_score: number;
  cap: number;
  cap_applied: boolean;
  disclaimer: string;
  components: ConfidenceComponent[];
}

export interface PolicyDecision {
  policy_version: string;
  rule_id: string;
  autonomy: string;
  offered_action: string;
  offered_action_label: string;
  requires_human_approval: boolean;
  auto_execute: boolean;
  summary: string;
  calibration_note: string;
  forced_auto_execute_off: boolean;
}

export interface TimelineStep {
  step_id: string;
  title: string;
  status: StepStatus;
  started_at: string;
  finished_at: string | null;
  duration_ms: number;
  provenance: Record<string, unknown>;
}

export interface IncidentSummary {
  incident_id: string;
  created_at: string;
  filename: string;
  sender: string | null;
  sender_address: string | null;
  subject: string | null;
  risk_label: RiskLabel;
  machine_risk_label: RiskLabel;
  risk_score: number;
  label_source: string;
  case_status: CaseStatus;
  processing_time_ms: number;
  enrichment_status: string;
  explainer_status: string;
  confidence_score: number;
  confidence_band: ConfidenceBand;
  offered_action: string | null;
  autonomy: string | null;
}

export interface IncidentList {
  items: IncidentSummary[];
  total: number;
}

export interface UrlOut {
  original: string;
  normalized: string;
  defanged: string;
  host: string | null;
  scheme: string | null;
  is_ip_literal: boolean;
  source: string;
}

export interface AttachmentOut {
  filename: string | null;
  content_type: string | null;
  size_bytes: number;
  extension: string | null;
  sha256: string;
}

export interface IncidentBrief {
  summary: string;
  assessment: {
    risk_label: RiskLabel;
    risk_score: number;
    origin: string;
    rationale: string;
    caveat: string;
  };
  recommended_actions: string[];
  sources_consulted: { name: string; status: string; detail: string }[];
  limitations: string[];
}

export interface VerdictFeedback {
  id: string;
  incident_id: string;
  verdict: string;
  previous_label: string;
  corrected_label: string | null;
  reason: string;
  analyst_id: string;
  ruleset_version: string;
  rules_updated: boolean;
  created_at: string;
}

export interface ActionResponse {
  id: string;
  incident_id: string;
  decision: string;
  offered_action: string;
  reason: string;
  analyst_id: string;
  case_status: string;
  simulated: boolean;
  external_effect: string;
  message: string;
  created_at: string;
}

export interface IncidentDetail {
  incident_id: string;
  created_at: string;
  filename: string;
  sender: string | null;
  sender_address: string | null;
  subject: string | null;
  spf: string | null;
  dkim: string | null;
  dmarc: string | null;
  body_text: string;
  body_excerpt: string;
  urls: UrlOut[];
  attachments: AttachmentOut[];
  evidence: Evidence[];
  indicators: Indicator[];
  risk_label: RiskLabel;
  machine_risk_label: RiskLabel;
  risk_score: number;
  label_source: string;
  caveat: string;
  case_status: CaseStatus;
  processing_time_ms: number;
  enrichment_status: string;
  explainer_status: string;
  ai_summary: string | null;
  confidence: Confidence;
  policy: PolicyDecision;
  timeline: TimelineStep[];
  brief: IncidentBrief;
  verdict_feedback: VerdictFeedback[];
  action_response: ActionResponse | null;
}

export interface Metrics {
  ruleset: string;
  case_count: number;
  cases_by_label: Record<RiskLabel, number>;
  average_processing_time_ms: number | null;
  completed_human_reviews: number;
  average_human_review_ms: number | null;
  agreements: number;
  disagreements: number;
  feedback_total: number;
  raw_agreement_rate: number | null;
  shrunk_agreement_percent: number;
  disclaimer: string;
}

export interface HealthResponse {
  status: string;
  service: string;
  version: string;
  engine: string;
  ruleset: string;
  reputation_enabled: boolean;
  ai_enabled: boolean;
  explainer_provider?: string;
}

export interface BatchItem {
  filename: string;
  incident_id: string | null;
  risk_label: string | null;
  error_code: string | null;
  error_message: string | null;
}

export interface BatchResult {
  accepted: number;
  failed: number;
  items: BatchItem[];
}

export interface DemoPack {
  items: { name: string; filename: string; bytes: number }[];
}

export interface EvaluationReport {
  generated_at: string;
  ruleset: string;
  selection: string;
  note: string;
  failures_handled: number;
  rates: {
    tp: number;
    fp: number;
    fn: number;
    tn: number;
    phishing_inconclusive: number;
    ham_inconclusive: number;
    tpr: number;
    fnr: number;
    fpr: number;
    tnr: number;
    phishing_scored: number;
    phishing_attempted: number;
    ham_scored: number;
    ham_attempted: number;
    inconclusive_rate_phishing: number;
    inconclusive_rate_ham: number;
  };
  latency_ms: { p50: number; p95: number; n: number };
  datasets: { name: string; role: string; attempted: number; license: string }[];
  slices: Record<string, { attempted: number; scored: number; failures: number; labels: Record<string, number> }>;
}

export interface QueueFilters {
  risk_label?: string;
  confidence_band?: string;
}
