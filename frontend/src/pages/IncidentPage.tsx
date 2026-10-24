import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { FishBot } from "../components/FishBot";
import { BandBadge, RiskBadge } from "../components/RiskBadge";
import { useToast } from "../components/Toasts";
import type { IncidentDetail, RiskLabel, TimelineStep } from "../features/incidents";
import { useAnalystId } from "../lib/analyst";
import { caseCode, defangDomain, defangText, receivedLabel } from "../lib/board";
import { askFishbot, fishbotBubbles, labelName, moodFor } from "../lib/fishbot";
import { API_BASE, ApiError, getIncident, listIncidents, postAction, postFeedback } from "../services/api";

const DEFAULT_REASON = {
  approve: "Approved the offered action.",
  reject: "Rejected the offered action.",
  correct: "Agent verdict matches the evidence.",
  wrong: "Agent verdict does not match the evidence.",
} as const;

const TABS = [
  ["summary", "Summary"],
  ["evidence", "Evidence"],
  ["timeline", "Timeline"],
  ["email", "Original email"],
  ["indicators", "Indicators"],
  ["audit", "Audit"],
] as const;

type TabId = (typeof TABS)[number][0];

export function IncidentPage() {
  const { incidentId = "" } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const analyst = useAnalystId();
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [neighbors, setNeighbors] = useState<string[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [note, setNote] = useState("");
  const [corrected, setCorrected] = useState("");
  const [chat, setChat] = useState<Array<{ role: "bot" | "me"; text: string }>>([]);
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);
  const [tab, setTab] = useState<TabId>("summary");
  const [shown, setShown] = useState(0);

  const load = useCallback(() => {
    setLoading(true);
    setError("");
    getIncident(incidentId)
      .then((caseFile) => {
        setDetail(caseFile);
        setShown(0);
        setChat(fishbotBubbles(caseFile).map((text) => ({ role: "bot" as const, text })));
      })
      .catch((err: unknown) => {
        setDetail(null);
        setError(err instanceof ApiError ? err.message : "The API on port 8741 is not responding.");
      })
      .finally(() => setLoading(false));
  }, [incidentId]);

  useEffect(() => {
    setTab("summary");
    load();
  }, [load]);

  useEffect(() => {
    listIncidents()
      .then((queue) => setNeighbors(queue.items.map((item) => item.incident_id)))
      .catch(() => setNeighbors([]));
  }, [incidentId]);

  useEffect(() => {
    if (!detail) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setShown(detail.timeline.length);
      return;
    }
    setShown(1);
    const timer = window.setInterval(() => {
      setShown((count) => {
        if (count >= detail.timeline.length) {
          window.clearInterval(timer);
          return count;
        }
        return count + 1;
      });
    }, 280);
    return () => window.clearInterval(timer);
  }, [detail]);

  const reasonFor = useCallback(
    (kind: keyof typeof DEFAULT_REASON) => (note.trim().length >= 3 ? note.trim() : DEFAULT_REASON[kind]),
    [note],
  );

  const advance = useCallback(() => {
    window.dispatchEvent(new Event("phishcatch:queue"));
    listIncidents()
      .then((queue) => {
        const ids = queue.items.map((item) => item.incident_id);
        const index = ids.indexOf(incidentId);
        const next = ids[index + 1] || ids[0];
        if (next && next !== incidentId) navigate(`/incidents/${next}`);
        else load();
      })
      .catch(() => load());
  }, [incidentId, load, navigate]);

  const approve = useCallback(
    (decision: "approve" | "reject") => {
      if (!detail || detail.action_response || busy) {
        if (detail?.action_response) toast("That action was already recorded.");
        return;
      }
      setBusy(true);
      postAction(detail.incident_id, {
        decision,
        reason: reasonFor(decision),
        analyst_id: analyst,
      })
        .then((result) => {
          toast(result.message);
          setNote("");
          advance();
        })
        .catch((err: unknown) => toast(err instanceof ApiError ? err.message : "Could not record the decision."))
        .finally(() => setBusy(false));
    },
    [advance, analyst, busy, detail, reasonFor, toast],
  );

  const verdict = useCallback(
    (value: "correct" | "wrong") => {
      if (!detail || detail.verdict_feedback.length > 0 || busy) {
        if (detail && detail.verdict_feedback.length > 0) toast("A verdict is already recorded.");
        return;
      }
      setBusy(true);
      postFeedback(detail.incident_id, {
        verdict: value,
        reason: reasonFor(value),
        analyst_id: analyst,
        corrected_label: value === "wrong" && corrected ? corrected : undefined,
      })
        .then(() => {
          toast(
            value === "correct"
              ? "Recorded: agent was correct. Rules were not changed."
              : "Recorded: agent was wrong. Rules were not changed.",
          );
          setNote("");
          window.dispatchEvent(new Event("phishcatch:queue"));
          load();
        })
        .catch((err: unknown) => toast(err instanceof ApiError ? err.message : "Could not record the verdict."))
        .finally(() => setBusy(false));
    },
    [analyst, busy, corrected, detail, load, reasonFor, toast],
  );

  const close = useCallback(() => navigate("/"), [navigate]);

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        close();
        return;
      }
      if (isTyping(event) || !detail) return;
      const index = neighbors.indexOf(detail.incident_id);
      if (event.key === "j" && index >= 0 && neighbors[index + 1]) {
        event.preventDefault();
        navigate(`/incidents/${neighbors[index + 1]}`);
      } else if (event.key === "k" && index > 0) {
        event.preventDefault();
        navigate(`/incidents/${neighbors[index - 1]}`);
      } else if (event.key === "y") {
        event.preventDefault();
        approve("approve");
      } else if (event.key === "n") {
        event.preventDefault();
        approve("reject");
      } else if (event.key === "c") {
        event.preventDefault();
        verdict("correct");
      } else if (event.key === "w") {
        event.preventDefault();
        verdict("wrong");
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [approve, close, detail, navigate, neighbors, verdict]);

  const provider = detail?.timeline.find((step) => step.step_id === "ai_explanation")?.provenance.provider;

  return (
    <div className="drawer-root">
      <button type="button" className="drawer-scrim" aria-label="Close case" onClick={close} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label="Case detail">
        {loading && (
          <div className="state">
            <FishBot mood="analyzing" size={88} />
            <p>Reading headers…</p>
          </div>
        )}
        {!loading && (error || !detail) && (
          <div className="state error-state">
            <FishBot mood="alert" size={80} />
            <p>{error || "This case was not found."}</p>
            <button type="button" className="btn" onClick={close}>
              Close
            </button>
          </div>
        )}
        {detail && !loading && (
          <>
            <header className="drawer-head">
              <div className="drawer-title">
                <FishBot mood={moodFor(detail.risk_label)} size={56} />
                <div>
                  <p className="kcode">{caseCode(detail.incident_id)}</p>
                  <h2>{detail.subject || detail.filename}</h2>
                  <p className="muted">{defangDomain(detail.sender_domain || detail.sender_address || "unknown sender")}</p>
                </div>
                <button type="button" className="btn tiny close-x" onClick={close}>
                  Esc
                </button>
              </div>
              <div className="verdict-top">
                <RiskBadge label={detail.risk_label} />
                <BandBadge band={detail.confidence.band} />
                <p className="score">
                  {detail.confidence.score}
                  <span>%</span>
                </p>
                <p className="risk-num">Score {detail.risk_score}</p>
              </div>
              <p className="action-name">{detail.policy.offered_action_label}</p>
              <p className="muted">Auto-execute: off. {detail.policy.summary}</p>
              {detail.action_response ? (
                <p className="result">{detail.action_response.message}</p>
              ) : (
                <div className="actions">
                  <button type="button" className="btn yes big" disabled={busy} onClick={() => approve("approve")}>
                    Yes, do this
                  </button>
                  <button type="button" className="btn no big" disabled={busy} onClick={() => approve("reject")}>
                    No
                  </button>
                </div>
              )}
              {reportReady(detail) && (
                <div className="actions">
                  <a className="btn" href={`${API_BASE}/api/v1/incidents/${detail.incident_id}/report.docx`}>
                    Download report (.docx)
                  </a>
                  <a className="btn" href={`${API_BASE}/api/v1/incidents/${detail.incident_id}/report.xlsx`}>
                    Download report (.xlsx)
                  </a>
                </div>
              )}
            </header>

            <div className="tabs" role="tablist">
              {TABS.map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={tab === id}
                  className={tab === id ? "tab on" : "tab"}
                  onClick={() => setTab(id)}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="drawer-body" role="tabpanel">
              {tab === "summary" && (
                <section className="thread">
                  <p className="caveat">{detail.caveat}</p>
                  {chat.map((line, index) => (
                    <p key={`${line.role}-${index}`} className={line.role === "bot" ? "bubble bot" : "bubble me"}>
                      {line.text}
                    </p>
                  ))}
                  {provider === "gemini" && (
                    <p className="muted gemini-note">
                      Gemini is on. The free tier may use submitted prompts to improve Google products. This demo sends only
                      defanged indicators from synthetic samples or public-corpus mail. The note is requested in English.
                    </p>
                  )}
                  {detail.verdict_feedback.length > 0 ? (
                    <p className="result">Agent was {detail.verdict_feedback[0].verdict}. Rules were not changed.</p>
                  ) : (
                    <div className="actions">
                      <button type="button" className="btn" disabled={busy} onClick={() => verdict("correct")}>
                        Agent was correct
                      </button>
                      <button type="button" className="btn" disabled={busy} onClick={() => verdict("wrong")}>
                        Agent was wrong
                      </button>
                      <label className="note inline">
                        If wrong, optional label
                        <select aria-label="Corrected label" value={corrected} onChange={(event) => setCorrected(event.target.value)}>
                          <option value="">Keep the displayed label</option>
                          {(["likely_malicious", "suspicious", "likely_benign", "inconclusive"] as RiskLabel[]).map((label) => (
                            <option key={label} value={label}>
                              {labelName(label)}
                            </option>
                          ))}
                        </select>
                      </label>
                    </div>
                  )}
                  <form
                    className="ask"
                    onSubmit={(event) => {
                      event.preventDefault();
                      const asked = question.trim().slice(0, 400);
                      const answer = askFishbot(asked, detail);
                      setChat((currentChat) => [...currentChat, { role: "me", text: asked }, { role: "bot", text: answer }]);
                      setQuestion("");
                    }}
                  >
                    <label className="sr-only" htmlFor="ask-fishbot">
                      Ask FishBot
                    </label>
                    <input
                      id="ask-fishbot"
                      value={question}
                      onChange={(event) => setQuestion(event.target.value)}
                      placeholder="Ask about this case only"
                      maxLength={400}
                    />
                    <button type="submit" className="btn">
                      Ask
                    </button>
                  </form>
                  <label className="note">
                    Optional note
                    <textarea
                      value={note}
                      onChange={(event) => setNote(event.target.value)}
                      maxLength={2000}
                      rows={2}
                      placeholder="Leave it blank for a one-click decision."
                    />
                  </label>
                  <p className="muted time-saved">
                    Measured time for this case: {detail.processing_time_ms} ms. {detail.confidence.disclaimer}
                  </p>
                </section>
              )}

              {tab === "evidence" && (
                <ul className="evidence">
                  {detail.evidence.map((item) => (
                    <li key={item.id}>
                      <p>
                        <strong>{item.title}</strong>
                        <span className="muted">
                          {item.rule_id} · {item.polarity} · weight {item.weight}
                        </span>
                      </p>
                      <p>{item.reason}</p>
                    </li>
                  ))}
                </ul>
              )}

              {tab === "timeline" && (
                <ol className="timeline vertical">
                  {detail.timeline.map((step, index) => (
                    <li key={step.step_id} className={`step step-${step.status}${index < shown ? " shown" : ""}`}>
                      <span className="step-mark" aria-hidden="true" />
                      <div>
                        <p className="step-title">
                          {step.title}
                          <span className="step-status">{step.status}</span>
                        </p>
                        <p className="provenance">
                          {receivedLabel(step.started_at)}
                          {step.duration_ms > 0 ? ` · ${step.duration_ms} ms` : ""}
                          {provenanceLine(step) ? ` · ${provenanceLine(step)}` : ""}
                        </p>
                      </div>
                    </li>
                  ))}
                </ol>
              )}

              {tab === "email" && (
                <section className="safe-mail">
                  <p className="muted">Plain text only. HTML is not rendered. Links are defanged and not clickable.</p>
                  <table className="headers">
                    <tbody>
                      <HeaderRow label="From" value={detail.headers.from_header} />
                      <HeaderRow label="Reply-To" value={detail.headers.reply_to} />
                      <HeaderRow label="Return-Path" value={detail.headers.return_path} />
                      <HeaderRow label="To" value={detail.headers.to.join(", ")} />
                      <HeaderRow label="Subject" value={detail.headers.subject} />
                      <HeaderRow label="Date" value={detail.headers.date} />
                      <HeaderRow
                        label="Authentication-Results"
                        value={detail.headers.authentication_results.join("\n") || "None"}
                      />
                      <HeaderRow label="Auth trust" value={detail.headers.auth_trust} />
                    </tbody>
                  </table>
                  <h3>Body</h3>
                  <pre className="mail-text">{defangText(detail.body_text) || "No text body was stored."}</pre>
                  <h3>Attachments</h3>
                  {detail.attachments.length === 0 && <p className="muted">No attachments. Nothing was executed.</p>}
                  <ul className="evidence">
                    {detail.attachments.map((item) => (
                      <li key={item.sha256}>
                        <p>
                          <strong>{item.filename || "Unnamed attachment"}</strong>
                          <span className="muted">
                            {item.content_type} · {item.size_bytes} bytes · {item.extension || "no extension"}
                          </span>
                        </p>
                        <p className="muted">sha256 {item.sha256}</p>
                      </li>
                    ))}
                  </ul>
                </section>
              )}

              {tab === "indicators" && (
                <ul className="urls">
                  {detail.indicators
                    .filter((item) => item.type === "url" || item.type === "domain" || item.type === "ip")
                    .map((item) => {
                      const shownValue = item.type === "url" ? defangText(item.display_value) : defangDomain(item.display_value);
                      return (
                        <li key={item.id}>
                          <code>
                            {item.type}: {shownValue}
                          </code>
                          <button
                            type="button"
                            className="btn tiny"
                            onClick={() => {
                              navigator.clipboard.writeText(shownValue).then(
                                () => toast("Copied the defanged indicator."),
                                () => toast("Could not copy."),
                              );
                            }}
                          >
                            Copy
                          </button>
                        </li>
                      );
                    })}
                  {detail.urls.length === 0 && <li className="muted">No URLs were extracted. Nothing was fetched.</li>}
                </ul>
              )}

              {tab === "audit" && (
                <section>
                  <p className="muted">Decisions recorded for this case. Rules were not changed.</p>
                  <ul className="evidence">
                    {detail.action_response && (
                      <li>
                        <p>
                          <strong>Action {detail.action_response.decision}</strong>
                          <span className="muted">{detail.action_response.analyst_id}</span>
                        </p>
                        <p>{detail.action_response.message}</p>
                      </li>
                    )}
                    {detail.verdict_feedback.map((item) => (
                      <li key={item.id}>
                        <p>
                          <strong>Agent was {item.verdict}</strong>
                          <span className="muted">{item.analyst_id}</span>
                        </p>
                      </li>
                    ))}
                    {(detail.decisions ?? []).map((item) => (
                      <li key={item.id}>
                        <p>
                          <strong>{item.action}</strong>
                          <span className="muted">{item.analyst_id}</span>
                        </p>
                      </li>
                    ))}
                    {(detail.audit_events ?? []).map((item) => (
                      <li key={item.id}>
                        <p>
                          <strong>{item.event_type.replaceAll("_", " ")}</strong>
                          <span className="muted">
                            {item.actor} · {receivedLabel(item.created_at)}
                          </span>
                        </p>
                      </li>
                    ))}
                  </ul>
                </section>
              )}
            </div>
          </>
        )}
      </aside>
    </div>
  );
}

function reportReady(detail: IncidentDetail): boolean {
  return Boolean(
    detail.action_response ||
      detail.verdict_feedback.length > 0 ||
      (detail.decisions ?? []).length > 0 ||
      detail.case_status === "closed" ||
      detail.case_status === "quarantine_simulated",
  );
}

function HeaderRow({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <tr>
      <th>{label}</th>
      <td>{value || "—"}</td>
    </tr>
  );
}

function provenanceLine(step: TimelineStep): string {
  const source = step.provenance;
  const parts: string[] = [];
  if (typeof source.component === "string") parts.push(source.component);
  if (typeof source.tool === "string") parts.push(source.tool);
  for (const key of ["explainer_status", "provider", "reason_code", "risk_label", "offered_action", "hit_count"]) {
    const value = source[key];
    if (typeof value === "string" || typeof value === "number") parts.push(`${key} ${value}`);
  }
  return parts.join(" · ");
}

function isTyping(event: KeyboardEvent): boolean {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return false;
  return Boolean(target.closest("input, textarea, select"));
}
