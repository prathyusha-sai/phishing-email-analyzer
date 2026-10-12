# Phishing Email Analyzer

A beginner-friendly SOC project: a Python script that reads a suspicious `.eml`
file and produces a triage verdict report -header anomalies, spoofed domains,
lookalike URLs, risky attachments, and urgency language. It automates the same
checks a Tier 1 SOC analyst runs by hand.

**Why this project:** you already do this analysis manually from your
cybersecurity lab work (phishing email review, BEC lifecycle analysis).
Turning it into a working tool is exactly the kind of proof SOC hiring
managers look for on GitHub and LinkedIn.

## Run it

No installs — pure Python standard library:

```bash
python3 analyzer.py sample_suspicious.eml
```

Try it on any real suspicious email too: in Gmail, open the message →
⋮ menu → "Show original" → Download. Then `python3 analyzer.py <file.eml>`.

## What it checks

| Check | What it catches |
|---|---|
| From vs Return-Path / Reply-To | Spoofed senders, reply hijacking |
| Authentication-Results | Missing SPF/DKIM/DMARC signal |
| Link display-text vs href | Masked malicious links |
| Lookalike domains | Typosquatting (e.g. `paypa1.com` for `paypal.com`) |
| Raw IP links | Phishing-kit hallmark |
| Attachment extensions | `.exe`, `.js`, `.vbs`, `.zip` risk |
| Urgency language | Manufactured panic: "suspended", "last chance" |

Each finding is weighted; the total becomes a LOW / MEDIUM / HIGH verdict
with a recommended action.

## Stretch goals (pick one next)

1. **VirusTotal URL check** — query the free VT API for each extracted link
   and add its reputation score to the report.
2. **Header forensics** — parse the `Received:` chain to reconstruct the true
   sending IP path, the way analysts do during incident response.
3. **JSON report output** — emit `--json` so results feed into a SIEM or dashboard.
4. **Attachment detonation notes** — document a safe sandbox workflow
   (any.run / isolated VM) for the archives you flag.

## Files

- `analyzer.py` — the analyzer (heavily commented so you can explain it in interviews)
- `sample_suspicious.eml` — synthetic phishing email with every tell baked in
- `requirements.txt` — intentionally empty (stdlib only)
