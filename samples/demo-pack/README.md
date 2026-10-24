# Demo pack

This folder does not contain mail in git. Real messages from public corpora
stay on the machine that downloaded them. Do not commit `*.eml` files here.

The one-click names `corpus_phish_1`, `corpus_phish_2`, `corpus_ham_1`, and
`corpus_ham_2` are an allowlist only. PhishCatch lists a name when the matching
file is present under this directory, and returns 404 when it is not. The
synthetic samples in `samples/` are the ones that ship with the repository.

If you need those four buttons locally, copy short messages yourself out of
`data/corpora/` after `scripts/fetch_datasets.py`. Keep them gitignored.

- Phishing excerpts would come from Jose Nazario's phishing corpus, mailbox
  `phishing-2023`, CC-BY-4.0. Source: <https://monkey.org/~jose/phishing/>.
  Attribute Jose Nazario. Later Nazario mailboxes are not anonymized.
- Ham excerpts would come from the SpamAssassin public corpus
  `20030228_easy_ham`. Copyright in the messages stays with the senders.
  Source: <https://spamassassin.apache.org/old/publiccorpus/>.
  Do not inject these files into a live mail system.

Do not open, click, or fetch any URL or attachment inside a message.
PhishCatch defangs URLs and does not retrieve them.
