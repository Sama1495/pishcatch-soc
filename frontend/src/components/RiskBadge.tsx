import type { ConfidenceBand, RiskLabel } from "../features/incidents";
import { labelName } from "../lib/fishbot";

export function RiskBadge({ label }: { label: RiskLabel }) {
  return (
    <span className={`badge risk-${label}`}>
      <RiskIcon label={label} />
      <span>{labelName(label)}</span>
    </span>
  );
}

export function BandBadge({ band }: { band: ConfidenceBand }) {
  return <span className={`badge band-${band}`}>{band} confidence index</span>;
}

function RiskIcon({ label }: { label: RiskLabel }) {
  if (label === "likely_malicious") {
    return (
      <svg viewBox="0 0 16 16" aria-hidden="true">
        <path d="M8 1.5 L15 14 H1 Z" />
        <path d="M8 6 v4 M8 12.2 v.6" className="icon-mark" />
      </svg>
    );
  }
  if (label === "suspicious") {
    return (
      <svg viewBox="0 0 16 16" aria-hidden="true">
        <rect x="3" y="3" width="10" height="10" transform="rotate(45 8 8)" />
      </svg>
    );
  }
  if (label === "likely_benign") {
    return (
      <svg viewBox="0 0 16 16" aria-hidden="true">
        <circle cx="8" cy="8" r="6.2" />
        <path d="M5 8.2 l2 2 l4-4.4" className="icon-mark" />
      </svg>
    );
  }
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true">
      <circle cx="8" cy="8" r="6.2" />
      <path d="M8 4.5 v4.2 M8 11.2 v.6" className="icon-mark" />
    </svg>
  );
}
