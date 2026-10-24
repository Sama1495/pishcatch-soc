# Architecture

PhishCatch SOC is a local phishing-triage copilot for a SOC hackathon (Alaris Security).
The analyst gets one case file: extracted indicators, explainable evidence, a risk label,
recommended next steps, and an audit trail. The deterministic engine is the source of
the risk label. Reputation lookups stay off. The AI explainer is a deterministic
template unless `AI_EXPLAINER_PROVIDER=gemini` and `GEMINI_API_KEY` are set. It is off
by default. A Gemini note, when configured, is requested in English and cannot
mark a message safe on its own.

## What this repository implements

| Area | Status |
| --- | --- |
| `.eml` validation, parsing, rules, risk label, Incident Brief | Implemented |
| SQLite incidents, indicators, evidence, decisions, audit, timing | Implemented |
| Simulated quarantine | Implemented (no mailbox is changed) |
| VirusTotal / URLhaus | Stub interfaces, disabled by default, no live HTTP |
| AI explainer | Template by default. Optional Gemini Flash, schema-validated, cannot set the label |
| React dashboard | Queue, incident detail, FishBot, decisions (`frontend/`) |
| Confidence, timeline, trust policy | Implemented. Nothing auto-executes. See `docs/trust-policy.md`. |

## Flow

The orchestrator in `backend/app/agent/orchestrator.py` always runs the same tools,
in this order:

1. Parse the `.eml` (headers, text, URL strings, attachment metadata).
2. Normalize indicators. URL display values are defanged.
3. Evaluate the deterministic ruleset (`backend/app/services/rules.py`, version 1.2.0).
4. Ask the reputation adapter. With the default settings it records `disabled` and sends nothing.
5. Compare indicators with cases already in SQLite.
6. Classify: `likely_malicious`, `suspicious`, `likely_benign`, or `inconclusive`.
7. Ask the explainer. With the default settings it records `disabled`.
8. Build the Incident Brief from the evidence already collected.
9. Persist the case, the processing time, and an `analysis_completed` audit event.

A later analyst decision (`confirm` or `correct`) is stored with the analyst id and
does not change the ruleset. `machine_risk_label` stays as the engine left it.
The brief is the original machine product and is not rewritten.

## Risk labels

Score = sum of unique suspicious rule weights, capped at 100. Thresholds live in
`backend/app/services/risk.py`.

| Condition | Label |
| --- | --- |
| Suspicious score ≥ 55 | `likely_malicious` |
| Any suspicious hit below that score | `suspicious` |
| No suspicious hit, and at least two aligning signals (for example SPF and DKIM pass) | `likely_benign`, with an explicit caveat |
| No suspicious hit and fewer than two aligning signals | `inconclusive` |

A message with no signals is not declared safe. `likely_benign` is also not a clearance:
the caveat says the absence of detections is not proof of safety.

## Ruleset 1.2.0

Version 1.2.0 keeps the 1.1.0 phrase lists, including the Spanish ones, and
tightens three pretext gates. A bare `usd` amount is not a payment request.
A certification or badge word fires only together with a sign-in, payment, or
claim phrase, and only when From is not an issuer. Brand alignment uses that
same call to act, so the certification word alone is not one. Weights are
unchanged. See `docs/evaluation.md`.

## Ruleset 1.1.0

Version 1.1.0 adds pretext checks (credential or payment requests, badge lures,
brand mismatch with a call to act, and related signals) and only scores
Authentication-Results from `PHISHCATCH_TRUSTED_AUTHSERV_IDS`. Mailing-list
messages skip Reply-To and Return-Path mismatch. See `docs/evaluation.md` for
the measured before and after.

## Ruleset 1.0.0

Suspicious rules contribute to the score once each, even if several indicators match.

| Rule | Weight | What it explains |
| --- | --- | --- |
| `display_name_domain_mismatch` | 25 | Display name contains another mailbox or a protected brand |
| `reply_to_mismatch` | 15 | Reply-To organization differs from From |
| `return_path_mismatch` | 10 | Return-Path domain differs from From |
| `spf_fail` / `spf_softfail` | 20 / 10 | SPF fail, permerror, or softfail |
| `dkim_fail` | 20 | DKIM fail or permerror |
| `dmarc_fail` | 25 | DMARC fail or permerror |
| `lookalike_domain` | 30 | Host resembles a protected brand and is not that brand's domain |
| `url_text_href_mismatch` | 35 | Anchor text host differs from the href host |
| `ip_literal_url` | 30 | URL host is an IP address (not opened) |
| `url_shortener` | 15 | Known shortener (not expanded) |
| `urgency_credential_lure` | 20 | English or Spanish lure phrase in subject or body |
| `risky_attachment_extension` | 35 | Executable, script, disk image, HTML, or double extension |
| `punycode_domain` | 20 | Host contains `xn--` |
| `dangerous_url_scheme` | 40 | `javascript`, `data`, `vbscript`, or `file` |
| `url_embedded_credentials` | 25 | URL userinfo was present and was stripped before storage |
| `related_indicator_in_prior_case` | 10 | Same URL, domain, IP, or mailbox on a prior suspicious case |

Aligning signals have weight 0: `spf_pass`, `dkim_pass`, `dmarc_pass`, `reply_to_aligned`.
Informational markers: `no_suspicious_signals`, `related_indicator_seen_before`.

Protected brands and shortener hosts are listed next to the checks in `rules.py`.
Official brand domains are not flagged as lookalikes.

## Modules

```text
backend/app/api            HTTP routes, upload limits, uniform errors
backend/app/core           settings, redacting logs, AppError
backend/app/schemas        Pydantic contracts
backend/app/services       parser, URLs, rules, risk, brief, confidence
backend/app/policy         trust policy document and the decision engine
backend/app/agent          orchestrator and the tool allowlist
backend/app/integrations   reputation stub, Gemini explainer, optional RDAP, SSRF guard, timeouts
backend/app/db             SQLAlchemy models and SQLite session
frontend/src               React dashboard (queue, FishBot, decisions)
samples                    synthetic .eml fixtures
```

## Confidence, timeline, and the human gate

Each analysis stores a confidence score that is separate from the risk score,
an 11-step operations timeline, and the action chosen by `trust_policy.json`.
The formula, the bands, and the autonomy table are in `docs/trust-policy.md`.
The policy engine forces `auto_execute` off. Yes/no and “agent was correct /
agent was wrong” are audited. A wrong verdict feeds the agreement prior and
does not edit rules.

The queue is ordered by risk rank (malicious 4, suspicious 3, inconclusive 2,
benign 1) times the confidence score.

## Persistence

SQLite via SQLAlchemy. Tables: `incidents`, `indicators`, `evidence`,
`analyst_decisions`, `audit_events`, `operation_steps`, `verdict_feedback`,
`action_responses`. The incident row stores sender, subject,
selected headers, defanged URL records, attachment metadata, body text (for the
case file), the brief JSON, both risk labels, case status, and `processing_time_ms`.

The list endpoint does not return the body. Logs do not include the body, addresses,
URL values, secrets, or analyst free text.

## Explicit non-goals for this scaffold

No SIEM, EDR, ticketing, real quarantine, automatic rule learning, or public demo
exposure. Do not put the API on the internet until authentication, rate limits, and
the threat-model controls for a shared deployment are in place.
