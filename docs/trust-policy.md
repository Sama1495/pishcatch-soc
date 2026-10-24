# Trust policy

These thresholds are an initial proposal. Calibrate them with labeled samples
and analyst feedback before raising autonomy. Confidence is not a measured
accuracy.

The machine-readable copy the API loads is `backend/app/policy/trust_policy.json`.
The policy engine in `backend/app/policy/engine.py` chooses the offered action.
The AI explainer does not.

## Confidence formula

Confidence is separate from the risk score. Risk says how suspicious the message
looks. Confidence says how strongly this ruleset supports its own label.

```text
raw = 0.40 * evidence_agreement
    + 0.25 * coverage
    + 0.15 * conflict_clarity
    + 0.20 * historical_agreement

score = round_half_up(min(raw, label_cap))
```

`round_half_up` is `int(value + 0.5)`.

| Component | What it measures |
| --- | --- |
| Evidence agreement (0.40) | For `likely_malicious` and `suspicious`, the risk score, capped at 55 for one suspicious rule and 75 for two. For `likely_benign`, 20 points per aligning signal, capped at 80. For `inconclusive` with no signals, 10. |
| Coverage (0.25) | Parser 25, rules 30, correlation 15, reputation 20, explainer 10. A step that is done earns its weight. Skipped, disabled, or failed earns 0. With reputation and AI off, coverage is 70. |
| Conflict clarity (0.15) | 100 when the evidence points one way. When suspicious and aligning signals both exist: `max(15, 100 - 18*aligning - 4*suspicious)`. When neither exists: 40. |
| Historical agreement (0.20) | Confirm/correct decisions and “agent was correct / agent was wrong” for this ruleset, shrunk toward 50 with 4 pseudo-cases: `(agreements + 4*0.5) / (total + 4)`. With no feedback this term is 50. It is a prior, not a measured accuracy. |

Label caps, so a thin or benign verdict cannot look certain:

| Label | Cap |
| --- | --- |
| `inconclusive` | 40 |
| `likely_benign` | 70 |
| `suspicious` | 100 |
| `likely_malicious` | 100 |

Bands: high ≥ 75, medium ≥ 40, otherwise low.

The product shows this sentence with every score:

> Confidence is a deterministic score for how strongly this ruleset supports its own verdict. It is not a measured accuracy and it is not a probability that the label is correct.

## What the policy offers

Nothing auto-executes in this MVP. `auto_execute` in the JSON is ignored if it is ever set to true. Every offered action waits for an explicit human yes.

| Risk label | Confidence | Offered action |
| --- | --- | --- |
| `likely_malicious` | high | Simulate quarantine, one-click human approval |
| `likely_malicious` | medium | Analyst review |
| `likely_malicious` | low | Manual investigation |
| `suspicious` | high or medium | Analyst review. Quarantine is not offered. |
| `suspicious` | low | Manual investigation |
| `likely_benign` | high or medium | Close with no containment, still a human yes |
| `likely_benign` | low | Manual investigation |
| `inconclusive` | any | Manual investigation |

The offered action is stored with the case. A later label correction does not silently change what the human is asked to approve.

## How trust should grow

Count agent-versus-analyst agreement for the ruleset version: confirm counts as agreement, correct as disagreement, and the newer “agent was correct / agent was wrong” verdicts count the same way. A wrong verdict updates that tally only.

One correction never edits a rule or a threshold. The running engine never edits `trust_policy.json`. Raise autonomy only after a reviewed evaluation on labeled samples, then change the policy file on purpose. Until that evaluation exists, keep auto-execute off.
