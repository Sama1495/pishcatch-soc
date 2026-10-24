import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { FishBot } from "../components/FishBot";
import { BandBadge, RiskBadge } from "../components/RiskBadge";
import { useToast } from "../components/Toasts";
import type { IncidentDetail, RiskLabel, TimelineStep } from "../features/incidents";
import { useAnalystId } from "../lib/analyst";
import { askFishbot, fishbotBubbles, labelName, moodFor } from "../lib/fishbot";
import { ApiError, getIncident, listIncidents, postAction, postFeedback } from "../services/api";

const DEFAULT_REASON = {
  approve: "Approved the offered action.",
  reject: "Rejected the offered action.",
  correct: "Agent verdict matches the evidence.",
  wrong: "Agent verdict does not match the evidence.",
} as const;

const PROGRESS: Record<string, string> = {
  reception: "Receiving the file…",
  validation_extraction: "Reading headers…",
  deterministic_rules: "Checking links and rules…",
  enrichment: "Checking reputation…",
  correlation: "Comparing with prior cases…",
  risk: "Scoring the label…",
  ai_explanation: "Writing the explanation…",
  incident_brief: "Building the brief…",
  awaiting_human_decision: "Waiting for your decision…",
};

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
          load();
        })
        .catch((err: unknown) => toast(err instanceof ApiError ? err.message : "Could not record the verdict."))
        .finally(() => setBusy(false));
    },
    [analyst, busy, corrected, detail, load, reasonFor, toast],
  );

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
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
  }, [approve, detail, navigate, neighbors, verdict]);

  if (loading) {
    return (
      <main className="state">
        <FishBot mood="analyzing" size={120} />
        <p>Reading headers…</p>
      </main>
    );
  }
  if (error || !detail) {
    return (
      <main className="state error-state">
        <FishBot mood="alert" size={96} />
        <p>{error || "This case was not found."}</p>
        <Link to="/" className="btn">
          Back
        </Link>
      </main>
    );
  }

  const playing = shown < detail.timeline.length;
  const current = detail.timeline[Math.max(0, shown - 1)];
  const progress = current ? PROGRESS[current.step_id] : undefined;
  const reasons = detail.evidence
    .filter((item) => item.polarity === "suspicious")
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3);
  const provider = detail.timeline.find((step) => step.step_id === "ai_explanation")?.provenance.provider;
  const manualRaw = localStorage.getItem("phishcatch.manualMinutes") ?? "";
  const manualMinutes = Number(manualRaw);
  const manualOk = manualRaw.trim() !== "" && Number.isFinite(manualMinutes) && manualMinutes >= 0;

  return (
    <main className="conversation">
      <section className="thread" aria-label="FishBot">
        <div className="chat-head">
          <FishBot mood={playing ? "analyzing" : moodFor(detail.risk_label)} size={96} />
          <div>
            <p className="who">FishBot</p>
            <p className="muted">
              {playing
                ? progress || current?.title
                : `Explainer: ${detail.explainer_status}. Rules assign the label.`}
            </p>
          </div>
        </div>

        {playing && (
          <p className="bubble bot live">
            {progress || current?.title}{" "}
            <span className="muted">
              {shown}/{detail.timeline.length}
            </span>
          </p>
        )}

        {!playing && (
          <article className="verdict" aria-label="Verdict">
            <div className="verdict-top">
              <RiskBadge label={detail.risk_label} />
              <BandBadge band={detail.confidence.band} />
              <p className="score">
                {detail.confidence.score}
                <span> index</span>
              </p>
            </div>
            <p className="caveat">{detail.caveat}</p>
            <ol className="reasons">
              {reasons.length === 0 && <li>No suspicious signal. That does not declare the message safe.</li>}
              {reasons.map((item) => (
                <li key={item.id}>{item.title}</li>
              ))}
            </ol>
            <p className="action-name">{detail.policy.offered_action_label}</p>
            <p className="muted">Auto-execute: off. {detail.policy.summary}</p>
            {detail.action_response ? (
              <p className="result">{detail.action_response.message}</p>
            ) : (
              <div className="actions">
                <button type="button" className="btn yes" disabled={busy} onClick={() => approve("approve")}>
                  Yes, do this action
                </button>
                <button type="button" className="btn no" disabled={busy} onClick={() => approve("reject")}>
                  No, don't do this action
                </button>
              </div>
            )}
            {detail.verdict_feedback.length > 0 ? (
              <p className="result">
                Agent was {detail.verdict_feedback[0].verdict}. Rules were not changed.
              </p>
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
            <p className="disclaimer">{detail.confidence.disclaimer}</p>
          </article>
        )}

        {!playing &&
          chat.map((line, index) => (
            <p key={`${line.role}-${index}`} className={line.role === "bot" ? "bubble bot" : "bubble me"}>
              {line.text}
            </p>
          ))}

        {provider === "gemini" && (
          <p className="muted gemini-note">
            Gemini is on. The free tier may use submitted prompts to improve Google products. This demo sends only defanged
            indicators from synthetic samples or public-corpus mail. The note is requested in English.
          </p>
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

        <p className="muted time-saved">
          Automated steps: parse, rules, correlation, brief, policy. Measured time for this case: {detail.processing_time_ms} ms.
          {manualOk
            ? ` Your baseline: ${manualMinutes} min (${Math.round(manualMinutes * 60000)} ms). Difference: ${Math.round(manualMinutes * 60000 - detail.processing_time_ms)} ms.`
            : " No manual baseline is stored. Enter one on the home screen if you want a difference."}
        </p>

        <details>
          <summary>Timeline</summary>
          <ol className="timeline">
            {detail.timeline.map((step) => (
              <li key={step.step_id} className={`step step-${step.status}`}>
                <span className="step-mark" aria-hidden="true" />
                <div>
                  <p className="step-title">
                    {step.title}
                    <span className="step-status">{step.status}</span>
                    <span className="muted">{step.duration_ms > 0 ? `${step.duration_ms} ms` : ""}</span>
                  </p>
                  <p className="provenance">{provenanceLine(step)}</p>
                </div>
              </li>
            ))}
          </ol>
        </details>
        <details>
          <summary>Evidence</summary>
          <ul className="evidence">
            {detail.evidence.map((item) => (
              <li key={item.id}>
                <p>
                  <strong>{item.title}</strong>
                  <span className="muted">
                    {item.source} · {item.polarity} · {item.weight}
                  </span>
                </p>
                <p>{item.reason}</p>
              </li>
            ))}
          </ul>
        </details>
        <details>
          <summary>Defanged URLs</summary>
          {detail.urls.length === 0 && <p className="muted">No URLs extracted. Nothing was fetched.</p>}
          <ul className="urls">
            {detail.urls.map((url) => (
              <li key={url.defanged}>
                <code>{url.defanged}</code>
                <button
                  type="button"
                  className="btn tiny"
                  onClick={() => {
                    navigator.clipboard.writeText(url.defanged).then(
                      () => toast("Copied the defanged URL."),
                      () => toast("Could not copy."),
                    );
                  }}
                >
                  Copy
                </button>
              </li>
            ))}
          </ul>
        </details>
        <details>
          <summary>Incident Brief</summary>
          <p>{detail.brief.summary}</p>
          <p className="muted">{detail.brief.assessment.rationale}</p>
          <ul>
            {detail.brief.recommended_actions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ul>
        </details>
        <details>
          <summary>Plain text only. HTML is not rendered.</summary>
          <pre className="mail-text">{detail.body_text || "No text body was stored."}</pre>
        </details>
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
      </section>
    </main>
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
