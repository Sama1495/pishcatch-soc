# Measured evaluation

Numbers below are counts from `python -m app.evaluate`. They are not estimates
and they were not rounded up. Positive prediction means `likely_malicious` or
`suspicious`. A phishing message scored `likely_benign` is a false negative.
Ham scored positive is a false positive. `inconclusive` is neither a true
positive nor a true negative. Rates divide by scored messages. Failures are
counted and do not stop the run.

Selection, both runs: first 200 messages in mailbox order from Nazario
`phishing-2023` (419 messages in the file); first 200 SpamAssassin
`20030228_easy_ham` files and first 100 `20030228_hard_ham` files by sorted
path. 500 messages, 0 parse failures. Not a random sample and not retuned
after looking at errors. No URL inside a message was fetched.

## Baseline, ruleset 1.0.0

Generated 2026-10-24T18:08:28+00:00. Saved in
`backend/app/evaluation/baseline-1.0.0.json`. Authentication-Results were
trusted from any authserv-id. Reply-To and Return-Path mismatches fired on
mailing lists.

| | Count |
| --- | --- |
| True positive | 153 |
| False positive | 206 |
| False negative | 29 |
| True negative | 0 |
| Phishing inconclusive | 18 |
| Ham inconclusive | 94 |
| Phishing scored / attempted | 200 / 200 |
| Ham scored / attempted | 300 / 300 |

Rates: TPR 0.765, FNR 0.145, FPR 0.6866666666666666, TNR 0.0,
inconclusive phishing 0.09, inconclusive ham 0.31333333333333335.

Latency over 500 scored messages: p50 2.974 ms, p95 14.639 ms.

Label slices: phishing likely_malicious 10, suspicious 143, likely_benign 29,
inconclusive 18. easy_ham suspicious 174, inconclusive 26, benign 0, malicious 0.
hard_ham malicious 2, suspicious 30, inconclusive 68, benign 0.

The easy_ham false positives were mostly `return_path_mismatch` (136 of 200)
and `reply_to_mismatch` (81 of 200), which is normal for mailing-list envelopes.

## After, ruleset 1.1.0

Generated 2026-10-24T18:20:26+00:00. Saved in
`backend/app/evaluation/latest.json`. This is not a pretext-only comparison.
The same run also changes two other behaviors:

- Authentication-Results are scored only when the authserv-id is in
  `PHISHCATCH_TRUSTED_AUTHSERV_IDS`. The default is empty, so SPF, DKIM, and
  DMARC in the corpora were not scored. Received-SPF is stored and not scored.
- `reply_to_mismatch` and `return_path_mismatch` are skipped when the message
  has a list marker (`List-Id`, `Mailing-List`, `List-Unsubscribe`, or
  Precedence `list`/`bulk`). The header values are not stored.

Pretext rules (credential and payment requests, badge lures, brand mismatch
with a call to act, and the others in ruleset 1.1.0) are included.

| | Count |
| --- | --- |
| True positive | 113 |
| False positive | 44 |
| False negative | 0 |
| True negative | 0 |
| Phishing inconclusive | 87 |
| Ham inconclusive | 256 |
| Phishing scored / attempted | 200 / 200 |
| Ham scored / attempted | 300 / 300 |

Rates: TPR 0.565, FNR 0.0, FPR 0.14666666666666667, TNR 0.0,
inconclusive phishing 0.435, inconclusive ham 0.8533333333333334.

Latency over 500 scored messages: p50 5.446 ms, p95 31.113 ms.

Label slices: phishing likely_malicious 5, suspicious 108, likely_benign 0,
inconclusive 87. easy_ham suspicious 8, inconclusive 192, benign 0, malicious 0.
hard_ham malicious 3, suspicious 33, inconclusive 64, benign 0.

Read this as: forged or untrusted authentication no longer creates a benign
label (false negatives went from 29 to 0), and mailing-list envelope mismatches
no longer dominate easy_ham (false positives went from 206 to 44). More mail
is `inconclusive`, which this product does not treat as safe and does not treat
as a detection. True negatives stayed 0 because a likely_benign label still
requires two aligning signals, and untrusted authentication is not one of them.

`GET /api/v1/evaluation` serves `latest.json`. The dashboard prints these
counts as stored.

Precision on this slice is TP / (TP + FP). For 1.1.0 that is 113 / 157 =
0.7197452229299363. Recall is the TPR above, 0.565. FPR is 0.14666666666666667.

## After, ruleset 1.2.0, same 500 messages

Generated 2026-10-24T20:20:57+00:00. Saved in
`backend/app/evaluation/latest.json`. Weights did not change. Three phrase
gates did:

- A bare currency token (`usd` followed by an amount) is no longer a payment
  request. Spanish and English fee phrases stay (`paga la`, `tarifa de`,
  `pay the`, `verification fee`).
- `certification_badge_lure` still matches `insignia`, `badge`,
  `certificacion`, `certification`, and `credencial`, and still ignores
  issuer From domains. It now also requires a sign-in, payment, or
  claim/verify phrase.
- Brand alignment uses that same call to act. A certification word alone is
  not a call to act.

| | Count |
| --- | --- |
| True positive | 113 |
| False positive | 42 |
| False negative | 0 |
| True negative | 0 |
| Phishing inconclusive | 87 |
| Ham inconclusive | 258 |
| Phishing scored / attempted | 200 / 200 |
| Ham scored / attempted | 300 / 300 |

Rates: TPR 0.565, FNR 0.0, FPR 0.14, TNR 0.0,
inconclusive phishing 0.435, inconclusive ham 0.86.
Precision 113 / 155 = 0.7290322580645161. Recall 0.565.

Latency over 500 scored messages: p50 5.052 ms, p95 29.168 ms.

Label slices: phishing likely_malicious 5, suspicious 108, likely_benign 0,
inconclusive 87. easy_ham suspicious 7, inconclusive 193, benign 0, malicious 0.
hard_ham malicious 3, suspicious 32, inconclusive 65, benign 0.

On this fixed slice, recall is unchanged and false positives fell from 44 to
42. This slice overlaps the split below, so it is not the number that decided
the ruleset bump.

## Held-out split, full Nazario phishing-2023 and all easy_ham

Decision metric for 1.2.0. hard_ham is not in this split. Within the phishing
mailbox order, and separately within sorted easy_ham paths, index `% 10 >= 7`
is holdout (30%) and the rest is tune (70%). The phrase gates were chosen
from tune aggregates only, then measured once on holdout. No message text is
stored here.

Tune scored 294 phishing and 1750 ham. One ham message on the tune side was a
parse rejection and is not in the 1750. Holdout scored 125 phishing and 750
ham, with no parse failures.

| | 1.1.0 tune | 1.2.0 tune | 1.1.0 holdout | 1.2.0 holdout |
| --- | --- | --- | --- | --- |
| True positive | 173 | 173 | 69 | 69 |
| False positive | 18 | 14 | 3 | 1 |
| False negative | 0 | 0 | 0 | 0 |
| Precision | 0.9057591623036649 | 0.9251336898395722 | 0.9583333333333334 | 0.9857142857142858 |
| Recall | 0.5884353741496599 | 0.5884353741496599 | 0.552 | 0.552 |
| FPR | 0.010285714285714285 | 0.008 | 0.004 | 0.0013333333333333333 |

Holdout recall stayed 69/125 = 0.552. Holdout FPR fell from 3/750 = 0.004 to
1/750 = 0.0013333333333333333. Holdout precision rose from 69/72 =
0.9583333333333334 to 69/70 = 0.9857142857142858. That is the clear
improvement that bumped the ruleset to 1.2.0. True negatives stayed 0 on both
splits: likely_benign still needs two aligning signals, and untrusted
authentication is not one of them. Ham that is not flagged is inconclusive,
not cleared.
