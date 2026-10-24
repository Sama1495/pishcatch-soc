import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { FishBot } from "../components/FishBot";
import { useUpload } from "../components/UploadContext";
import type { DemoPack, EvaluationReport, Metrics } from "../features/incidents";
import { analyzeDemo, getEvaluation, getMetrics, listDemoPack } from "../services/api";

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

export function QueuePage() {
  const upload = useUpload();
  const navigate = useNavigate();
  const [pack, setPack] = useState<DemoPack | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [evaluation, setEvaluation] = useState<EvaluationReport | null>(null);
  const [evalError, setEvalError] = useState("");
  const [manual, setManual] = useState(localStorage.getItem("phishcatch.manualMinutes") ?? "");

  useEffect(() => {
    listDemoPack()
      .then(setPack)
      .catch(() => setPack({ items: [] }));
    getMetrics()
      .then(setMetrics)
      .catch(() => setMetrics(null));
    getEvaluation()
      .then(setEvaluation)
      .catch(() => setEvalError("Evaluation has not been stored."));
  }, []);

  const names = new Map((pack?.items ?? []).map((item) => [item.name, item]));
  const buttons = DEMO_ORDER.filter((name) => names.has(name));

  return (
    <main className="home">
      <section className="hero">
        <FishBot mood={upload.busy ? "analyzing" : "idle"} size={120} />
        <div>
          <h1>Drop the message. I build the case.</h1>
          <p className="lede">
            I read headers, links, and pretext. I do not open URLs or run attachments. Quarantine does not run until you say yes.
          </p>
        </div>
      </section>

      <button type="button" className="drop-zone" onClick={upload.openPicker}>
        <strong>Drop zone</strong>
        <span>One .eml, several, or an .mbox. You can also drop them anywhere.</span>
      </button>

      <section className="demo-row" aria-label="Demo pack">
        <p className="who">One-click pack</p>
        <div className="chips">
          {buttons.map((name) => (
            <button
              key={name}
              type="button"
              className="btn"
              onClick={() => {
                analyzeDemo(name)
                  .then((created) => navigate(`/incidents/${created.incident_id}`))
                  .catch(() => setEvalError("That demo sample could not be analyzed."));
              }}
            >
              {DEMO_LABEL[name] ?? name}
            </button>
          ))}
        </div>
        <p className="muted">
          {buttons.some((name) => name.startsWith("corpus_"))
            ? "The corpus buttons are real public-corpus mail. Do not open their links."
            : "Corpus buttons are hidden until those files are on disk. The buttons above are synthetic samples. Do not open their links."}
        </p>
      </section>

      <section className="metrics" aria-label="Measured evaluation">
        <article className="metric">
          <p className="metric-label">Measured evaluation</p>
          {evaluation ? (
            <>
              <p className="metric-value">
                TP {evaluation.rates.tp} · FP {evaluation.rates.fp} · FN {evaluation.rates.fn} · TN {evaluation.rates.tn}
              </p>
              <p className="metric-note">
                {evaluation.ruleset} · {evaluation.generated_at} · n {evaluation.latency_ms.n} · p50 {evaluation.latency_ms.p50} ms · p95{" "}
                {evaluation.latency_ms.p95} ms · failures {evaluation.failures_handled}
              </p>
              <p className="metric-note">
                Phishing inconclusive {evaluation.rates.phishing_inconclusive} · ham {evaluation.rates.ham_inconclusive}. TPR{" "}
                {String(evaluation.rates.tpr)} · FPR {String(evaluation.rates.fpr)} · FNR {String(evaluation.rates.fnr)}. {evaluation.note}
              </p>
            </>
          ) : (
            <p className="metric-note">{evalError || "Loading figures."}</p>
          )}
        </article>
        <article className="metric">
          <p className="metric-label">Agent–analyst agreement</p>
          <p className="metric-value">
            {metrics && metrics.feedback_total > 0 && metrics.raw_agreement_rate !== null
              ? String(metrics.raw_agreement_rate)
              : "No verdict feedback yet"}
          </p>
          <p className="metric-note">
            {metrics
              ? `Formula prior ${metrics.shrunk_agreement_percent}%. ${metrics.disclaimer}`
              : "Not a measured accuracy."}
          </p>
        </article>
        <article className="metric">
          <p className="metric-label">Processing time</p>
          <p className="metric-value">
            {metrics?.average_processing_time_ms != null ? `${metrics.average_processing_time_ms} ms` : "—"}
          </p>
          <p className="metric-note">
            Local average of stored cases. Automated steps: parse, rules, correlation, brief, and policy.
          </p>
          <p className="metric-note">
            Human review wall time (analysis finished to decision, including queue wait):{" "}
            {metrics?.completed_human_reviews
              ? `${metrics.average_human_review_ms} ms across ${metrics.completed_human_reviews} decisions`
              : "No completed decision yet. This is not a time-saved claim."}
          </p>
          <label className="manual">
            Minutes this takes you by hand (optional)
            <input
              inputMode="decimal"
              value={manual}
              onChange={(event) => {
                setManual(event.target.value);
                localStorage.setItem("phishcatch.manualMinutes", event.target.value);
              }}
            />
          </label>
        </article>
      </section>
    </main>
  );
}
