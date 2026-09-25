# Screenshots

All screenshots below are embedded in [`report.md`](report.md) at the relevant section. PII (recipient name, email address, account avatar) has been blacked out before saving.

| File | Shows | Redacted |
|---|---|---|
| `inbox-view-gmail-suspicious-banner.png` | Email 1 as it appeared in Gmail — note Gmail's own "This message appears suspicious" banner and hidden-images warning | Recipient name (2x), account avatar |
| `eml-raw-headers-1.png` | Raw source view, part 1: `Delivered-To`, `ARC-Seal`, `Authentication-Results`, `Return-Path`, `Received` chain | Recipient email (2x) |
| `eml-raw-headers-2.png` | Raw source view, part 2: `DKIM-Signature`, `From`, `Subject`, `Reply-To`, `To`, `Feedback-ID` | Recipient name, recipient email |
| `pdf-page1-welcome-redacted.png` | Welcome Letter, page 1 — letterhead, batch code | Recipient name |
| `pdf-page2-fee-demand.png` | Welcome Letter, page 2 — the ₹1,551 fee demand, fake "APPROVED" stamp | — |
| `pdf-page3-salary-annexureA.png` | Welcome Letter, page 3 — salary table, second fee-demand paragraph | — |
| `pdf-page4-terms-annexureB.png` | Welcome Letter, page 4 — terms of service | — |
| `dns-lookup-terminal-1.png` | Terminal: `dig` MX/TXT/NS/A records, RDAP registration dates, start of `whois` on the hosting range | — (Linux username visible, not treated as sensitive here) |
| `dns-lookup-terminal-2.png` | Terminal: RDAP dates continued, full RIPE `whois` result for the hosting range | — |
| `virustotal-wellbridge.png` | VirusTotal community score for `wellbridge.in` — 0/68, but the cached record is from a **different IP, last analyzed ~10 years ago** (see report §5) | — |

All screenshots are present and embedded in the report.
