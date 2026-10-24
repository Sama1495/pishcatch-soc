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
