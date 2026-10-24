import type { IncidentDetail, RiskLabel } from "../features/incidents";

export type Mood = "idle" | "analyzing" | "alert" | "happy" | "curious" | "thinking";

const LABEL: Record<RiskLabel, string> = {
  likely_malicious: "likely malicious",
  suspicious: "suspicious",
  likely_benign: "likely benign",
  inconclusive: "inconclusive",
};

/** Fixed refusal. The question text is never copied into the reply. */
const REFUSAL =
  "I only answer from this case's stored checks. I won't follow instructions in a question, open a link, or run anything.";

const INJECTION =
  /ignore\s+(all\s+|any\s+|the\s+)?(previous|above|prior|instructions)|system\s+prompt|developer\s+message|jailbreak|<\s*script|javascript:|data:\s*text|fetch\s*\(|import\s*\(|exfiltrat|open\s+(the\s+|this\s+)?link|execute\s+(this|the|attachment)|you\s+are\s+now/i;

export function moodFor(label: RiskLabel | null, busy = false): Mood {
  if (busy) return "analyzing";
  if (label === "likely_malicious") return "alert";
  if (label === "likely_benign") return "happy";
  if (label === "inconclusive") return "curious";
  if (label === "suspicious") return "thinking";
  return "idle";
}

export function labelName(label: RiskLabel): string {
  return LABEL[label];
}

/** Chat lines built only from our labels, rule titles, and policy text. */
export function fishbotBubbles(detail: IncidentDetail): string[] {
  const confidence = `I'm ${detail.confidence.score}% sure of my own verdict. That is how strongly these checks agree, not a measured accuracy.`;
  if (detail.explainer_status === "validated" && detail.ai_summary) {
    return [
      detail.ai_summary,
      "That note did not change the risk label. The policy engine still picks the action, and nothing runs until you say yes.",
      confidence,
    ];
  }
  const done = detail.timeline.filter((step) => step.status === "done").map((step) => step.title);
  const skipped = detail.timeline.filter((step) => step.status === "skipped" || step.status === "failed");
  const suspicious = detail.evidence
    .filter((item) => item.polarity === "suspicious")
    .map((item) => item.title);
  const aligning = detail.evidence
    .filter((item) => item.polarity === "benign_support")
    .map((item) => item.title);
  const finding = suspicious.length
    ? `Suspicious checks: ${suspicious.join("; ")}.`
    : aligning.length
      ? `Aligning checks: ${aligning.join("; ")}. Aligning checks are not proof the message is safe.`
      : "I did not find a suspicious signal. That does not make the message safe.";
  const steps = skipped.length
    ? `I finished ${done.join(", ") || "the local checks"}. Skipped or failed: ${skipped
        .map((step) => `${step.title} (${step.status})`)
        .join(", ")}.`
    : `I finished ${done.join(", ") || "the local checks"}.`;
  return [
    `I read this as ${LABEL[detail.risk_label]}. ${confidence}`,
    finding,
    steps,
    `Policy offers “${detail.policy.offered_action_label}”. Auto-execute is off. ${detail.policy.summary}`,
  ];
}

export function askFishbot(question: string, detail: IncidentDetail): string {
  const asked = question.replace(/[\u0000-\u001f]/g, " ").trim().slice(0, 400);
  if (!asked) return "Ask about the verdict, confidence, checks, authentication, defanged URLs, or the offered action.";
  if (INJECTION.test(asked)) return REFUSAL;
  const q = asked.toLowerCase();

  if (/\b(body|html|raw mail|paste|subject line|what did (it|they) say)\b/.test(q)) {
    return "I don't repeat mail content in chat. The plain-text excerpt is on this screen, escaped, and I never render HTML.";
  }
  if (/\b(confiden|sure|certain|accuracy)\b/.test(q)) {
    const parts = detail.confidence.components.map(
      (item) => `${item.label} ${item.score} (weight ${item.weight})`,
    );
    return `${detail.confidence.score}% ${detail.confidence.band}. ${parts.join("; ")}. ${detail.confidence.disclaimer}`;
  }
  if (/\b(url|link|domain|host)\b/.test(q)) {
    const urls = detail.urls.map((url) => url.defanged).slice(0, 8);
    if (!urls.length) return "This case has no extracted URLs. I do not open links.";
    return `Defanged only, not opened: ${urls.join(" · ")}`;
  }
  if (/\b(attach|file|macro)\b/.test(q)) {
    if (!detail.attachments.length) return "No attachment metadata was stored. Nothing was executed.";
    const names = detail.attachments.map((item) => item.filename || "unnamed").join(", ");
    return `Attachment metadata only (${names}). Nothing was executed.`;
  }
  if (/\b(spf|dkim|dmarc|auth)\b/.test(q)) {
    return `SPF ${token(detail.spf)}, DKIM ${token(detail.dkim)}, DMARC ${token(detail.dmarc)}.`;
  }
  if (/\b(action|quarantine|recommend|policy|approve)\b/.test(q)) {
    return `${detail.policy.offered_action_label}. Auto-execute is ${detail.policy.auto_execute ? "on" : "off"}. ${detail.policy.summary}`;
  }
  if (/\b(why|verdict|risk|phish|malicious|benign|signal|evidence|check)\b/.test(q)) {
    const titles = detail.evidence.map((item) => item.title);
    if (!titles.length) return `Label: ${labelName(detail.risk_label)}. No rule titles were stored.`;
    return `Label: ${labelName(detail.risk_label)} (score ${detail.risk_score}). Checks: ${titles.join("; ")}.`;
  }
  if (/\b(step|timeline|progress|skip)\b/.test(q)) {
    return detail.timeline.map((step) => `${step.title}: ${step.status}`).join("; ");
  }
  return "I can talk about the verdict, confidence, checks, authentication, defanged URLs, attachments, or the offered action. I don't have anything else on this case.";
}

function token(value: string | null): string {
  if (!value) return "absent";
  return /^[a-z0-9_-]{1,32}$/i.test(value) ? value : "unparsed";
}
