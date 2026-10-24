# Synthetic samples

These `.eml` files are fictional. Domains use the `.example` suffix from RFC 2606.
They do not contain real mailboxes, customer data, or malware. Attachment bytes in
`clearly_phishing.eml` are a harmless HTML snippet stored only so the parser can
record metadata. Nothing in this folder should be opened in a mail client as if it
were a live threat, and the API never fetches the URLs inside the messages.

| File | Intent |
| --- | --- |
| `clearly_phishing.eml` | Credential lure, lookalike host, auth failures, mismatched link, IP URL, HTML attachment |
| `clearly_benign.eml` | Aligned internal note with SPF, DKIM, and DMARC pass. With the default empty trusted-authserv list those results are not scored, so the label is `inconclusive`, not a clearance |
| `no_signals.eml` | Ordinary note with no auth results and no suspicious signals |
| `ambiguous.eml` | External update that uses a URL shortener and otherwise looks ordinary |
| `malformed.eml` | Not an email; the API should reject it |
| `empty.eml` | Zero-byte file; the API should reject it |
| `certification_lure.eml` | LinkedIn display name, freemail reply-to, href mismatch, fee and corporate login |
| `certification_lure_clean_auth.eml` | Same pretext with forged SPF/DKIM/DMARC pass on an untrusted authserv |
| `certification_benign.eml` | LinkedIn Learning notice that denies payment and password requests |
| `demo-pack/` | Optional local excerpts. Not committed. See that README. |
| `audit/` | Synthetic audit fixtures. Not a public corpus. See that README. |
