import { useCallback, useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import type { IncidentSummary, RiskLabel } from "../features/incidents";
import { labelName } from "../lib/fishbot";
import { listIncidents } from "../services/api";
import { RiskBadge } from "./RiskBadge";

const LABELS: Array<RiskLabel | ""> = ["", "likely_malicious", "suspicious", "likely_benign", "inconclusive"];

export function Inbox() {
  const navigate = useNavigate();
  const location = useLocation();
  const [items, setItems] = useState<IncidentSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [risk, setRisk] = useState("");
  const [selected, setSelected] = useState(0);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    listIncidents({ risk_label: risk || undefined })
      .then((queue) => {
        setItems(queue.items);
        setTotal(queue.total);
        setError("");
      })
      .catch(() => setError("The queue is not responding."));
  }, [risk]);

  useEffect(() => {
    load();
  }, [load, location.pathname]);

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (location.pathname !== "/" || isTyping(event) || !items.length) return;
      if (event.key === "j") {
        event.preventDefault();
        setSelected((index) => Math.min(items.length - 1, index + 1));
      } else if (event.key === "k") {
        event.preventDefault();
        setSelected((index) => Math.max(0, index - 1));
      } else if (event.key === "Enter") {
        event.preventDefault();
        const row = items[selected];
        if (row) navigate(`/incidents/${row.incident_id}`);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [items, location.pathname, navigate, selected]);

  const counts = LABELS.filter(Boolean).map((label) => ({
    label: label as RiskLabel,
    count: items.filter((item) => item.risk_label === label).length,
  }));

  return (
    <aside className="inbox" aria-label="Inbox">
      <div className="inbox-head">
        <p className="who">Inbox</p>
        <p className="muted">{total} cases</p>
      </div>
      <div className="count-row">
        {counts.map((item) => (
          <button
            key={item.label}
            type="button"
            className={risk === item.label ? "chip on" : "chip"}
            onClick={() => setRisk(risk === item.label ? "" : item.label)}
          >
            {item.count} {labelName(item.label)}
          </button>
        ))}
      </div>
      {error && <p className="muted">{error}</p>}
      <ol className="inbox-list">
        {items.map((item, index) => {
          const active = location.pathname.endsWith(item.incident_id) || (location.pathname === "/" && index === selected);
          return (
            <li key={item.incident_id}>
              <button
                type="button"
                className={active ? "inbox-item active" : "inbox-item"}
                onClick={() => {
                  setSelected(index);
                  navigate(`/incidents/${item.incident_id}`);
                }}
              >
                <RiskBadge label={item.risk_label} />
                <span className="inbox-subject">{item.subject || item.filename}</span>
                <span className="muted">
                  {item.confidence_score}% · {item.case_status.replaceAll("_", " ")}
                </span>
              </button>
            </li>
          );
        })}
      </ol>
      {!items.length && !error && <p className="muted pad">The inbox is empty.</p>}
    </aside>
  );
}

function isTyping(event: KeyboardEvent): boolean {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return false;
  return Boolean(target.closest("input, textarea, select"));
}
