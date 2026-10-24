import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { FishBot } from "../components/FishBot";
import { RiskBadge } from "../components/RiskBadge";
import { useUpload } from "../components/UploadContext";
import { IncidentPage } from "./IncidentPage";
import type { DemoPack, EvaluationReport, IncidentSummary, Metrics } from "../features/incidents";
import { authCaption, byPriority, caseCode, columnFor, receivedLabel, senderDomain, type ColumnId } from "../lib/board";
import { analyzeDemo, getEvaluation, getMetrics, listDemoPack, listIncidents } from "../services/api";

const DEMO_ORDER = [
  "corpus_phish_1",
  "corpus_phish_2",
  "corpus_ham_1",
  "certification_lure_clean_auth",
  "certification_lure",
  "certification_benign",
];

const DEMO_LABEL: Record<string, string> = {
  corpus_phish_1: "Real phishing 1",
  corpus_phish_2: "Real phishing 2",
  corpus_ham_1: "Real ham",
  certification_lure_clean_auth: "LinkedIn forged auth",
  certification_lure: "LinkedIn lure",
  certification_benign: "LinkedIn notice",
};

const COLUMNS: Array<{ id: ColumnId; title: string; hint: string }> = [
  { id: "new", title: "New / Analyzing", hint: "Just arrived" },
  { id: "decision", title: "Needs decision", hint: "Waiting for yes or no" },
  { id: "monitoring", title: "Monitoring / Inconclusive", hint: "Not declared safe" },
  { id: "resolved", title: "Resolved", hint: "A person decided" },
];

export function QueuePage() {
  const upload = useUpload();
  const navigate = useNavigate();
  const { incidentId } = useParams();
  const [items, setItems] = useState<IncidentSummary[]>([]);
  const [error, setError] = useState("");
  const [pack, setPack] = useState<DemoPack | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [evaluation, setEvaluation] = useState<EvaluationReport | null>(null);
  const [query, setQuery] = useState("");
  const [risk, setRisk] = useState("");
  const [band, setBand] = useState("");
  const [selected, setSelected] = useState(0);
  const [manual, setManual] = useState(localStorage.getItem("phishcatch.manualMinutes") ?? "");

  const load = useCallback(() => {
    listIncidents()
      .then((queue) => {
        setItems(queue.items);
        setError("");
      })
      .catch(() => setError("The queue is not responding."));
  }, []);

  useEffect(() => {
    load();
    listDemoPack()
      .then(setPack)
      .catch(() => setPack({ items: [] }));
    getMetrics()
      .then(setMetrics)
      .catch(() => setMetrics(null));
    getEvaluation()
      .then(setEvaluation)
      .catch(() => setEvaluation(null));
  }, [load]);

  useEffect(() => {
    load();
  }, [load, incidentId, upload.busy]);

  useEffect(() => {
    function onRefresh() {
      load();
    }
    window.addEventListener("phishcatch:queue", onRefresh);
    return () => window.removeEventListener("phishcatch:queue", onRefresh);
  }, [load]);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return items
      .filter((item) => (risk ? item.risk_label === risk : true))
      .filter((item) => (band ? item.confidence_band === band : true))
      .filter((item) => {
        if (!needle) return true;
        const hay = [item.subject, item.sender, item.sender_domain, item.sender_address, item.filename, caseCode(item.incident_id), item.risk_label]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return hay.includes(needle);
      })
      .sort(byPriority);
  }, [band, items, query, risk]);

  const grouped = useMemo(() => {
    const buckets: Record<ColumnId, IncidentSummary[]> = { new: [], decision: [], monitoring: [], resolved: [] };
    for (const item of visible) buckets[columnFor(item)].push(item);
    return buckets;
  }, [visible]);

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (incidentId || isTyping(event) || !visible.length) return;
      if (event.key === "j") {
        event.preventDefault();
        setSelected((index) => Math.min(visible.length - 1, index + 1));
      } else if (event.key === "k") {
        event.preventDefault();
        setSelected((index) => Math.max(0, index - 1));
      } else if (event.key === "Enter") {
        event.preventDefault();
        const row = visible[selected];
        if (row) navigate(`/incidents/${row.incident_id}`);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [incidentId, navigate, selected, visible]);

  const names = new Map((pack?.items ?? []).map((item) => [item.name, item]));
  const buttons = DEMO_ORDER.filter((name) => names.has(name));
  const flatIndex = new Map(visible.map((item, index) => [item.incident_id, index]));

  return (
    <>
      <div className="board-page">
        <div className="board-tools">
          <FishBot mood={upload.busy ? "analyzing" : "idle"} size={42} />
          <input
            className="search"
            aria-label="Search cases"
            placeholder="Search subject, sender, or PC id"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          <select aria-label="Filter by risk" value={risk} onChange={(event) => setRisk(event.target.value)}>
            <option value="">All risk</option>
            <option value="likely_malicious">Likely malicious</option>
            <option value="suspicious">Suspicious</option>
            <option value="likely_benign">Likely benign</option>
            <option value="inconclusive">Inconclusive</option>
          </select>
          <select aria-label="Filter by confidence" value={band} onChange={(event) => setBand(event.target.value)}>
            <option value="">All confidence</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <button type="button" className="btn primary" onClick={upload.openPicker}>
            Upload mail
          </button>
        </div>

        <div className="board-meta">
          <div className="chips">
            {buttons.map((name) => (
              <button
                key={name}
                type="button"
                className="btn"
                onClick={() => {
                  analyzeDemo(name)
                    .then((created) => navigate(`/incidents/${created.incident_id}`))
                    .catch(() => setError("That demo sample could not be analyzed."));
                }}
              >
                {DEMO_LABEL[name] ?? name}
              </button>
            ))}
          </div>
          <p className="muted eval-line">
            {evaluation
              ? `Measured ${evaluation.ruleset}: TP ${evaluation.rates.tp} · FP ${evaluation.rates.fp} · FN ${evaluation.rates.fn} · TN ${evaluation.rates.tn}`
              : "Measured evaluation is not loaded."}
            {metrics && metrics.feedback_total > 0 && metrics.raw_agreement_rate !== null
              ? ` · Agreement ${String(metrics.raw_agreement_rate)}`
              : " · No verdict feedback yet"}
          </p>
          <label className="manual inline-manual">
            Hand minutes
            <input
              aria-label="Minutes this takes you by hand"
              inputMode="decimal"
              value={manual}
              onChange={(event) => {
                setManual(event.target.value);
                localStorage.setItem("phishcatch.manualMinutes", event.target.value);
              }}
            />
          </label>
        </div>

        {error && <p className="muted">{error}</p>}

        <div className="board" aria-label="Case board">
          {COLUMNS.map((column) => {
            const cards = grouped[column.id];
            return (
              <section key={column.id} className={`column column-${column.id}`} aria-label={column.title}>
                <header className="column-head">
                  <div>
                    <h2>{column.title}</h2>
                    <p>{column.hint}</p>
                  </div>
                  <span className="count">{column.id === "new" && upload.busy ? cards.length + 1 : cards.length}</span>
                </header>
                <div className="column-list">
                  {column.id === "new" && upload.busy && (
                    <article className="kcard analyzing">
                      <p className="kcode">Reading…</p>
                      <p className="ksubject">FishBot is building the case.</p>
                    </article>
                  )}
                  {cards.map((item) => {
                    const index = flatIndex.get(item.incident_id) ?? 0;
                    const active = item.incident_id === incidentId || (!incidentId && index === selected);
                    return (
                      <button
                        key={item.incident_id}
                        type="button"
                        className={`kcard tone-${item.risk_label}${active ? " active" : ""}`}
                        onClick={() => {
                          setSelected(index);
                          navigate(`/incidents/${item.incident_id}`);
                        }}
                      >
                        <span className="kcode">{caseCode(item.incident_id)}</span>
                        <span className="ksubject">{item.subject || item.filename}</span>
                        <span className="kdomain">{senderDomain(item)}</span>
                        <span className="krow">
                          <RiskBadge label={item.risk_label} />
                          <span className={`conf conf-${item.confidence_band}`}>
                            {item.confidence_score}% {item.confidence_band}
                          </span>
                        </span>
                        {item.risk_label === "likely_benign" && <span className="kcaveat">Not proof the message is safe</span>}
                        <span className="kicons">
                          <span title="Attachments">{item.attachment_count} files</span>
                          <span title="URLs">{item.url_count} URLs</span>
                          <span title="Authentication">{authCaption(item)}</span>
                        </span>
                        <span className="ktime">{receivedLabel(item.created_at)}</span>
                        {column.id === "resolved" && (
                          <span className="kdecision">
                            {item.action_decision === "approve"
                              ? "Action confirmed"
                              : item.action_decision === "reject"
                                ? "Action declined"
                                : item.case_status.replaceAll("_", " ")}
                            {item.verdict ? ` · agent ${item.verdict}` : ""}
                          </span>
                        )}
                      </button>
                    );
                  })}
                  {!cards.length && !(column.id === "new" && upload.busy) && <p className="muted empty-col">No cases</p>}
                </div>
              </section>
            );
          })}
        </div>
      </div>
      {incidentId && <IncidentPage />}
    </>
  );
}

function isTyping(event: KeyboardEvent): boolean {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return false;
  return Boolean(target.closest("input, textarea, select"));
}
