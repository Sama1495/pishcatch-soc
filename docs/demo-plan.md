# Two to three minute demo

The clock covers four things: it works on real data, it removes analyst work,
the automation is ours, and the story is clear. Nothing runs by itself.
Confidence is not a measured accuracy. The product UI is English. The certification samples are English too. The
rules still match Spanish phishing phrases when a message uses them.

Open the dashboard at `http://127.0.0.1:8742` (`scripts/run.sh` or
`scripts/run.ps1`). The one-click pack is on the home screen.

## Before the clock

- API on port 8741 and the UI on port 8742.
- `GET /health`: `reputation_enabled` is false. Gemini runs only when
  `AI_EXPLAINER_PROVIDER=gemini` and `GEMINI_API_KEY` are set. Otherwise
  FishBot uses the deterministic template.
- Do not open or request any URL that came out of a message.

## Script

| Time | Criterion | What to show |
| --- | --- | --- |
| 0:00–0:25 | Impact | Today an analyst opens the message, reads headers, compares the visible link with the href, checks the pretext, and writes the report. PhishCatch does those steps and leaves the decision. |
| 0:25–1:05 | Viability, real data | One click on a Nazario phishing message (`Real phishing 1` or `Real phishing 2`). FishBot reads the case and shows the card: label, confidence, three reasons, yes/no. URLs are defanged and are not fetched. |
| 1:05–1:40 | Innovation | The LinkedIn case `LinkedIn forged auth`. The message carries SPF/DKIM/DMARC pass, but the authserv is not on the trusted list, so those results are not scored. Pretext rules (credential request, USD 49 payment, badge, brand, OSINT, deadline) still mark it likely malicious. The LinkedIn Learning notice does not fire payment, credential, or badge. |
| 1:40–2:15 | Impact and the person | Yes to simulated quarantine. `external_effect: none`. Mark “Agent was correct”. The next case opens on its own. Read the measured p50 and p95 from the panel. Do not invent a time saving. |
| 2:15–2:40 | Viability | Show the evaluation panel: ruleset 1.2.0, 500 messages, TP 113, FP 42, FN 0, TN 0, and the inconclusive counts. Say inconclusive is not “safe”. If time remains, drop a file that is not mail, or a zip renamed to `.eml`: a controlled error, and the process keeps running. |

## If Gemini is on

Say out loud that the Google free tier may use submitted prompts to improve
Google products, and that this demo sends only synthetic samples and
public-corpus mail. The request asks for an English note. If the call fails,
the timeline says `failed` and FishBot returns to the template. The label does
not change.

## Lines not to say

- "It catches 100%."
- "The message is safe."
- "Confidence is the probability of being right."
- A time-saved percent that nobody measured by hand.
