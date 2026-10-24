# PhishCatch SOC

## Quick start

From the repository root. The script creates the virtualenv, installs
dependencies, seeds the queue when it is empty, and starts the API at
<http://127.0.0.1:8741> and the dashboard at <http://127.0.0.1:8742>.

```bash
./scripts/run.sh
```

Windows 10 (PowerShell, from the repository root; needs `py -3.12` and Node 24):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\run.ps1
```

For the measured evaluation, download the corpora (they are not committed) and
run the scorer from `backend/`:

```bash
python3 scripts/fetch_datasets.py
cd backend && .venv/bin/python -m app.evaluate
```

The counts land in `docs/evaluation.md` and `GET /api/v1/evaluation`.
Gemini is optional: copy `.env.example` to `.env`, leave `GEMINI_API_KEY` empty
or paste an AI Studio key, and set `AI_EXPLAINER_PROVIDER=gemini`. The key
never leaves the backend. The free tier may use submitted prompts to improve
Google products. The demo sends only synthetic samples and public-corpus mail,
and the explainer is asked to answer in English.

AI-assisted phishing triage for a SOC analyst. The risk label comes from
deterministic rules (ruleset 1.1.0). VirusTotal and URLhaus stay off. The
explainer is the deterministic template unless Gemini is configured.

PhishCatch turns a suspicious message into a case file: sender, defanged URLs,
evidence with a reason, a risk label, the agent's confidence, and the next
step. A message with no signals is not marked safe. Quarantine is simulated
and never runs on its own. FishBot presents the case. A person approves or
rejects the action.

Tagline: Catch the threat. Explain the risk. Guide the response.

## What works in this scaffold

- `GET /health`
- `POST /api/v1/incidents` with a `.eml` upload (size, extension, and real content checks)
- Deterministic parse, rules, risk label, and Incident Brief
- SQLite history, `GET` list and detail, analyst confirm/correct, simulated quarantine
- Agent confidence (separate from the risk score), an operations timeline, and a trust policy that never auto-executes
- Human yes/no on the offered action, plus “agent was correct / agent was wrong”
- React dashboard: queue, FishBot, timeline, confidence, and the decision controls
- `pytest` for validation, parsing, rules, confidence, policy, the timeline, and the human loop

Live reputation and a live model stay off. See `docs/architecture.md`,
`docs/trust-policy.md`, `docs/threat-model.md`, and `docs/demo-plan.md`.
The Alaris readiness audit is in Spanish at `docs/alaris-readiness-audit.md`.

## Repository layout

```text
backend/app/api            routes and upload checks
backend/app/core           settings, logging, errors
backend/app/schemas        incident, indicator, evidence, analysis, decision
backend/app/services       parser, rules, risk, brief
backend/app/agent          orchestrator and tool allowlist
backend/app/integrations   reputation stub, Gemini explainer, optional RDAP
backend/app/db             SQLAlchemy models
backend/tests              pytest
frontend/src/components    FishBot, queue chrome, upload
frontend/src/pages         alert queue and incident detail
frontend/src/features      incident contract for the UI
frontend/src/services      API client
samples/                   synthetic mail; real corpus excerpts stay gitignored
docs/                      architecture, trust policy, threat model, demo
```

## Prerequisites

- Windows 10: Python 3.12 with the `py` launcher (`py -3.12`) and Node.js 24 (`node` and `npm.cmd` on PATH)
- Linux or macOS: Python 3.11 or 3.12, and Node.js 20 or newer for the dashboard
- VS Code and PowerShell on Windows; any shell on Linux or macOS

No API key is required. Gemini is optional; see `.env.example`.

## Run the dashboard and the API

From the repository root. The script creates the virtualenv, installs
dependencies, seeds the sample queue when the database is empty, and starts
both processes. The API listens on <http://127.0.0.1:8741> and the dashboard
on <http://127.0.0.1:8742>.

Windows 10 (PowerShell, from the repository root). The script creates the
virtualenv with `py -3.12`, installs dependencies, seeds an empty database,
waits until the API answers, then starts the dashboard with `npm.cmd`:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\run.ps1
```

Linux or macOS:

```bash
./scripts/run.sh
```

Stop the script with Ctrl+C. It stops the API as well.

## Windows (VS Code + PowerShell), API only

From the repository root:

```powershell
cd backend
py -3.12 -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item ..\.env.example ..\.env
uvicorn app.main:app --host 127.0.0.1 --port 8741
```

In VS Code, choose the interpreter at `backend\.venv\Scripts\python.exe`
(Command Palette → "Python: Select Interpreter"). Open a terminal in the
`backend` folder and use the same `uvicorn` command. `curl` in PowerShell is
an alias of `Invoke-WebRequest`; use `curl.exe` for the examples below.

Run tests:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pytest
```

## Linux and macOS

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp ../.env.example ../.env
uvicorn app.main:app --host 127.0.0.1 --port 8741
```

Tests:

```bash
cd backend
source .venv/bin/activate
pytest
```

The process creates `backend/data/phishcatch.db` on first startup. That file is
gitignored. Run `uvicorn` from `backend/` so the `app` package imports.

Interactive API docs: <http://127.0.0.1:8741/docs>

Health check: <http://127.0.0.1:8741/health>

## Try a sample

Linux or macOS, from the repository root, with the API already running:

```bash
curl -s -F "file=@samples/clearly_phishing.eml;type=message/rfc822" \
  http://127.0.0.1:8741/api/v1/incidents
```

Windows PowerShell, from the repository root:

```powershell
curl.exe -s -F "file=@samples/clearly_phishing.eml;type=message/rfc822" http://127.0.0.1:8741/api/v1/incidents
```

Other fixtures:

| File | Expected label |
| --- | --- |
| `samples/clearly_phishing.eml` | `likely_malicious` |
| `samples/ambiguous.eml` | `suspicious` |
| `samples/clearly_benign.eml` | `inconclusive` while `PHISHCATCH_TRUSTED_AUTHSERV_IDS` is empty. `likely_benign` only if that authserv is trusted, and still with a caveat, not a clearance |
| `samples/no_signals.eml` | `inconclusive` (not safe) |
| `samples/malformed.eml` | HTTP 400 `invalid_content` |
| `samples/empty.eml` | HTTP 400 `empty_file` |

Samples are fictional and use `.example` domains. See `samples/README.md`.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Process is up. Reports whether reputation and AI are enabled. |
| `POST` | `/api/v1/incidents` | Multipart field `file`. Analyzes a `.eml` and stores the case. |
| `GET` | `/api/v1/incidents` | Queue, ordered by risk rank × confidence. Optional `risk_label`, `case_status`, `confidence_band`, `limit`, `offset`. No body text. |
| `GET` | `/api/v1/incidents/{id}` | Case file, confidence, policy, timeline, brief, decisions, audit. |
| `GET` | `/api/v1/metrics` | Agreement tally, cases by agent label, average analysis time, and average human-review wall time when a decision closed the wait. Not a measured accuracy and not a time-saved claim. |
| `POST` | `/api/v1/incidents/{id}/decisions` | JSON `action` of `confirm` or `correct`, plus `reason`. `correct` also needs `corrected_label`. |
| `POST` | `/api/v1/incidents/{id}/feedback` | `verdict` of `correct` or `wrong`, plus `reason`. Does not change rules. |
| `POST` | `/api/v1/incidents/{id}/actions/response` | `decision` of `approve` or `reject` for the action the policy offered. |
| `POST` | `/api/v1/incidents/{id}/actions/quarantine` | Simulated only, and only when the policy offered quarantine. A refusal is audited as `action_denied`. Body: `analyst_id`, `reason`. |

Errors always look like:

```json
{"error": {"code": "invalid_content", "message": "The file does not contain a recognizable email header section.", "details": null}}
```

## Configuration

Copy `.env.example` to `.env`. Every variable is prefixed with `PHISHCATCH_`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PHISHCATCH_MAX_UPLOAD_BYTES` | `1048576` | Upload cap |
| `PHISHCATCH_DATABASE_URL` | `sqlite:///./data/phishcatch.db` | Local database |
| `PHISHCATCH_REPUTATION_ENABLED` | `false` | Keep false unless you are extending the stub |
| `PHISHCATCH_VT_API_KEY` | empty | Not read from the repo |
| `PHISHCATCH_URLHAUS_AUTH_KEY` | empty | Not read from the repo |
| `PHISHCATCH_AI_ENABLED` | `false` | Explainer off |
| `PHISHCATCH_AI_API_KEY` | empty | Not read from the repo |
| `PHISHCATCH_AI_TIMEOUT_SECONDS` | `5` | Explainer timeout |
| `PHISHCATCH_REPUTATION_TIMEOUT_SECONDS` | `3` | Reputation timeout |
| `PHISHCATCH_LOG_LEVEL` | `INFO` | Log verbosity |

Leaving the two feature flags false is the supported demo mode. A skipped
reputation lookup is not a clean verdict. The explainer cannot change the label.
Details are in `docs/architecture.md` and `docs/threat-model.md`.

## Dashboard

`scripts/run.ps1` and `scripts/run.sh` start this with the API. To run it
alone, with the API already on port 8741:

```bash
cd frontend
npm install
npm run dev
```

Vite listens on <http://127.0.0.1:8742> and proxies `/api` and `/health` to
the API, so the page does not need a baked-in secret or a wide CORS list.
Set `VITE_API_BASE` only if you are not using that proxy.

FishBot’s chat is a deterministic template over the stored checks. Asking
FishBot does not call a model, open a URL, or execute an attachment. Confidence
is documented in `docs/trust-policy.md` and is not a measured accuracy.

## Rules

The implemented rules, weights, and the "no signal is not safe" policy are
documented in `docs/architecture.md` and in `backend/app/services/rules.py`.

## Safety notes

- Do not commit `.env`, `.venv`, `node_modules`, or `*.db`.
- Do not upload real customer mail. Use `samples/`.
- Do not expose this API publicly. There is no authentication yet.
- Quarantine does not talk to a mail system.
