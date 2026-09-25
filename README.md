# Wellbridge "Internship" Fee Scam — Email Triage

Static, offline triage of a fake internship offer that demands a "confirmation fee." Two emails and one PDF attachment were received, analyzed without clicking any links or opening any attachment in a viewer, and written up as an incident report.

**Verdict:** advance-fee ("pay-to-intern") fraud. No malware found in the PDF.

## Why this exists

I received these emails myself and used them as a case study to practice email/phishing triage: header and authentication analysis, static attachment analysis, URL extraction, domain/DNS intelligence, and IOC + ATT&CK reporting.

## Contents

| Path | What it is |
|---|---|
| [`reports/report.md`](reports/report.md) | Full triage report: header analysis, PDF static analysis, domain intelligence (WHOIS/RDAP/DNS), IOCs, MITRE ATT&CK mapping, recommendations |
| [`iocs/iocs.csv`](iocs/iocs.csv) | Machine-readable indicators (domains, IPs, URLs, hashes) |
| [`tools/eml_triage.py`](tools/eml_triage.py) | Standalone script: parses a `.eml` offline, prints headers, auth results, Reply-To/From mismatches, extracted URLs (defanged) and attachment hashes. No network calls. |
| [`samples/`](samples/) | Redacted, defanged plaintext copies of the two email bodies (recipient name/email removed, links defanged). Raw `.eml` files and the PDF attachment are **not** included — see below. |
| [`screenshots/`](screenshots/) | Redacted renders of the "Welcome Letter" PDF pages, embedded in the report; see [`screenshots/SCREENSHOTS.md`](screenshots/SCREENSHOTS.md) |

## Key findings (summary)

- Both emails pass SPF/DKIM/DMARC for `wellbridge.in` — expected, since the actor controls that domain; it doesn't establish legitimacy.
- The fee demand (₹1,551) is only in the PDF attachment, not the email text, which would evade simple text-based filtering.
- `wellbridge.in` was registered **~45 days before** the first email was sent.
- The PDF links to two other "brand" domains (`wiremetrics.in`, `axoraedge.in`) and a fourth domain appears in Reply-To (`intigrityfactor.in`), which shares mail infrastructure with `wellbridge.in`.
- PDF has no JavaScript, launch actions, embedded files, or forms — the social-engineering ask, not malware, is the payload.
- Page 2 of the PDF has five **invisible link annotations** tiled over the body text, all pointing to a different domain (`wiremetrics.in`) than the one visible hyperlink on the same page (`wellbridge.in`).
- Gmail flagged the first email as suspicious on its own, before any manual analysis.
- VirusTotal's 0/68 score for `wellbridge.in` is misleading — it's a cached record from a different IP, ~10 years old, predating the domain's current registration.

Full details, methodology, every command run (with output), and screenshots are in [`reports/report.md`](reports/report.md).

## Usage

```bash
python3 tools/eml_triage.py path/to/sample.eml --redact your@email.com
```

## What's deliberately excluded

- The original `.eml` files and PDF attachment (contain personal data / could be misused as a ready-made scam template).
- Any live, un-defanged links.

## Disclaimer

This is a personal analysis of a suspected fraudulent email for educational and portfolio purposes. Company/domain names are reported factually based on observed technical indicators; see the report's methodology and confidence notes. If you received a similar email, do not pay any fee and report it via India's National Cyber Crime Reporting Portal (cybercrime.gov.in) or helpline 1930.
