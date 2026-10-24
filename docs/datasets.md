# Public datasets

The evaluation and the demo pack use two public corpora. The mailboxes are not
committed. `scripts/fetch_datasets.py` (and `scripts/fetch_datasets.ps1`) download
them into `data/corpora/`, which is gitignored.

| Corpus | Role | URL | License |
| --- | --- | --- | --- |
| Jose Nazario phishing corpus, mailbox `phishing-2023` | Phishing. The evaluator uses the first 200 messages in mailbox order. | https://monkey.org/~jose/phishing/phishing-2023 | CC-BY-4.0. Attribute Jose Nazario. Later mailboxes are not anonymized and may contain errors. |
| SpamAssassin public corpus `20030228_easy_ham` | Ham. First 200 files by sorted path. | https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2 | Public corpus. Copyright remains with the original senders. Headers were partly obfuscated to `spamassassin.taint.org`. Do not inject the mail into a live system. |
| SpamAssassin public corpus `20030228_hard_ham` | Ham. First 100 files by sorted path. | https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2 | Same terms as easy_ham. |

The script also saves Nazario's `LICENSE.txt` and `README.txt` next to the mailbox.
It does not crawl links inside messages. PhishCatch never fetches a URL extracted
from a message and never opens attachments.

Checked reachable on 2026-10-24. If a URL moves, edit the script; do not replace
the measured sample with a different selection after seeing errors.

No corpus message is committed. `samples/demo-pack/` documents an optional
local allowlist; those `.eml` files are gitignored. The measured run is the
fixed sample described in `docs/evaluation.md`.
