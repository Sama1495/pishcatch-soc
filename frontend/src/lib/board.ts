import type { IncidentSummary, RiskLabel } from "../features/incidents";

export type ColumnId = "new" | "decision" | "monitoring" | "resolved";

const RANK: Record<RiskLabel, number> = {
  likely_malicious: 4,
  suspicious: 3,
  inconclusive: 2,
  likely_benign: 1,
};

export function caseCode(id: string): string {
  const hex = id.replace(/[^0-9a-f]/gi, "").slice(0, 6);
  const value = Number.parseInt(hex || "0", 16) % 10000;
  return `PC-${String(value).padStart(4, "0")}`;
}

export function defangDomain(value: string): string {
  return value.replace(/\./g, "[.]");
}

export function defangText(value: string): string {
  return value.replace(/\bhttps?:\/\/[^\s<>"']+/gi, (url) => {
    const secure = url.toLowerCase().startsWith("https");
    const rest = url.replace(/^https?:\/\//i, "").replace(/\./g, "[.]");
    return `${secure ? "hxxps://" : "hxxp://"}${rest}`;
  });
}

export function senderDomain(item: IncidentSummary): string {
  if (item.sender_domain) return defangDomain(item.sender_domain);
  const address = item.sender_address ?? "";
  const at = address.lastIndexOf("@");
  if (at >= 0) return defangDomain(address.slice(at + 1));
  return "unknown sender";
}

export function columnFor(item: IncidentSummary): ColumnId {
  if (item.case_status === "closed" || item.case_status === "quarantine_simulated" || item.action_decision) {
    return "resolved";
  }
  if (item.risk_label === "inconclusive") return "monitoring";
  return "decision";
}

export function byPriority(left: IncidentSummary, right: IncidentSummary): number {
  const score = RANK[right.risk_label] * right.confidence_score - RANK[left.risk_label] * left.confidence_score;
  if (score !== 0) return score;
  return right.created_at.localeCompare(left.created_at);
}

export function authCaption(item: IncidentSummary): string {
  if (item.auth_trust === "trusted") {
    return `SPF ${item.spf ?? "—"}`;
  }
  if (item.auth_trust === "untrusted") return "auth untrusted";
  return "no auth";
}

export function receivedLabel(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
