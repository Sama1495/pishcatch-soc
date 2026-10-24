# Threat model

PhishCatch handles untrusted `.eml` content on an analyst workstation. The scaffold
is for local and hackathon use. It is not ready to expose on the public internet.
Mail content is untrusted. Do not publish this build without authentication,
request limits, and a data review.

## Assets

- Case records: headers, body text, indicators, evidence, decisions, audit events.
- Analyst notes entered as a decision or quarantine reason.
- Optional API keys for VirusTotal, URLhaus, or a future model (environment only).
- The ruleset. A single analyst correction must not change it.

## Trust boundaries

| Boundary | Assumption |
| --- | --- |
| Uploaded `.eml` | Hostile. May contain prompt injection, HTML, scripts, or tricky URLs. |
| Analyst | Trusted for this local build. `analyst_id` is a label, not an authenticated identity. |
| Reputation providers | Untrusted networks. Disabled. The stub does not call them. |
| Model output | Untrusted. Validated against a schema and dropped if it cites unknown rules. |
| SQLite file | Local. It contains message content and must not be committed. |

## Abuse cases and controls

| Threat | Control in this build |
| --- | --- |
| Oversized upload | Read stops at `PHISHCATCH_MAX_UPLOAD_BYTES` (default 1 MiB) and returns `file_too_large`. |
| Wrong file type | The stored name must end in `.eml`. `invoice.eml.exe` is rejected. |
| Empty or non-mail bytes | Empty files return `empty_file`. Bytes without a real header section return `invalid_content`. |
| Attachment execution | Only filename, content type, size, extension, and SHA-256 are kept. Bytes are not written to disk and no handler is invoked. |
| Automatic URL visits | The parser, rules, and stubs never call `urlopen` or an HTTP client. Shorteners are not expanded. |
| SSRF or metadata fetch, if a live lookup is added later | `backend/app/integrations/ssrf.py` rejects loopback, private, link-local, reserved, and metadata hosts (`169.254.169.254`, localhost, `.local`, `.internal`). The stub still sends nothing. |
| Secrets in the repo | Keys are environment variables. `.env` is gitignored. `.env.example` has empty values. URL userinfo is stripped and is not stored. |
| Sensitive logs | Log lines carry ids, labels, counts, and statuses. A filter redacts emails, URLs, and `key=value` secrets, and truncates long lines. |
| Prompt injection in the mail | The explainer stub does not receive the body. A future prompt must treat the mail as data. Model JSON with extra fields or unknown rule ids is discarded. |
| Model sets the verdict | The risk label is computed before the explainer runs and is not replaced by it. |
| Real response actions | Quarantine only writes `quarantine_simulated` and an audit event. There is no mail client. |
| One correction retrains production rules | Decisions store `rules_updated: false`. The next upload is scored by the same ruleset. |
| Error oracles | Failures use one JSON shape: `error.code`, `error.message`, `error.details`. Messages do not echo file contents or tracebacks. |
| Clicking an indicator in a future UI | API URL fields include a defanged `display_value` (`hxxp`, `[.]`). |

## Residual risk

- There is no authentication, authorization, or rate limit. Do not tunnel this process to the internet as-is.
- `analyst_id` can be any short label. Audit answers "which label was submitted", not "which person proved their identity".
- The body is stored so the case file is reviewable. Anyone with the SQLite file can read it.
- Rules miss unknown phish and can flag benign mail. Labels are heuristics.
- A disabled or empty reputation result is easy to misread as "clean". The brief states that it is not.
- The SSRF guard is not a live client. It does not make the current build an outbound proxy, because this build does not connect.

## Authentication-Results

An uploaded message can forge `Authentication-Results`. PhishCatch scores SPF,
DKIM, and DMARC only when the authserv-id is listed in
`PHISHCATCH_TRUSTED_AUTHSERV_IDS`. The default list is empty. `Received-SPF` is
stored and is not a score. When results are present but untrusted, the case
caveat says so.

## Gemini explainer

`GEMINI_API_KEY` is read only from the environment, on the backend. It is not
returned by the API, not written to the frontend, and not logged. The request
sends rule ids, rule titles, the risk label, and defanged URL, domain, IP, or
attachment markers. It does not send the raw body, the subject, or mailbox
addresses. Email-derived strings are wrapped as untrusted data. Output must
match the explainer schema. A timeout, HTTP 429, transport error, or invalid
JSON becomes `explainer_status: fallback`. The timeline step is `failed` and
the deterministic template is what the analyst sees. The risk label does not
change.

The Gemini free tier may use submitted prompts to improve Google products.
The demo must send only synthetic samples and public-corpus mail. The in-process
limiter allows 8 calls per 60 seconds and caches a successful response by hash
of the structured payload.

## Out of scope

Public demo hardening, SSO, real quarantine, attachment detonation, and fetching URLs.
Those need a separate design before they are turned on.
