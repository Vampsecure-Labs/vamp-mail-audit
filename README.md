<h1 align="center">vamp-mail-audit</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
</p>

## Overview

`vamp-mail-audit` is an email security auditor that evaluates SPF, DKIM, DMARC, MX, and active SMTP posture for one or more domains. It performs DNS-level analysis (lookup counts, policy strictness, record conflicts) plus optional live SMTP probing for STARTTLS availability, open relay conditions, and banner version disclosure. It is the email security counterpart in the VampSecure Labs toolkit, built for both point-in-time assessments and ongoing CI/CD monitoring of domain email hygiene.

## Features

- SPF analysis: presence check (HIGH if absent), duplicate TXT record detection (RFC 7208 §3.2 violation, HIGH), permissive `+all`/`?all` mechanisms (CRITICAL), softfail `~all` (MEDIUM), `-all` pass (INFO), excessive DNS lookup count > 10 (MEDIUM)
- DMARC analysis: presence check (HIGH if absent), `p=none` reporting-only policy (HIGH), `p=quarantine` (MEDIUM), `p=reject` (INFO), partial deployment `pct < 100` (LOW), missing `rua` reporting address (LOW)
- DKIM selector probing across 15 common selectors: `default`, `google`, `mail`, `dkim`, `k1`, `k2`, `s1`, `s2`, `selector1`, `selector2`, `mandrill`, `mailjet`, `sendgrid`, `amazonses`, `smtp`; key size analysis (< 1024 HIGH, 1024–2047 MEDIUM, ≥ 2048 INFO); revoked selector detection (`p=` empty)
- MX record presence check (HIGH if absent)
- Active SMTP probing (optional): STARTTLS detection, open relay test (MAIL FROM + RCPT TO external address), banner version disclosure (LOW)
- Multi-domain batch scanning: `-d/--domain` repeatable, or a domain list file (`-f/--file`)
- SMTP-free mode (`--no-smtp`) for pure DNS assessment in restricted environments
- Export to Console (Rich), JSON, and HTML (dark-theme standalone)

## Requirements

- Python 3.9 or later
- `dnspython >= 2.4`
- `rich >= 13.7.0`
- Optional: `fpdf2 >= 2.7` for `--report-pdf`

## Installation

```bash
git clone https://github.com/belky-me/vamp-mail-audit.git
cd vamp-mail-audit
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```
python3 vamp_mail_audit.py --help
```

```
usage: vamp_mail_audit.py [-h] [-d DOMINIO] [-f FICHERO]
                           [--mx-timeout SEG] [--no-smtp]
                           [--json FICHERO] [--html FICHERO]
                           [--client CLIENT] [--engagement ENGAGEMENT]
                           [--auditor AUDITOR] [--report-scope SCOPE]
                           [--report-html FILE] [--report-pdf FILE]

vamp-mail-audit — Email Security Auditor (VampSecure Labs)
```

## Examples

```bash
# Audit a single domain
python3 vamp_mail_audit.py -d example.com

# Audit multiple domains in one command
python3 vamp_mail_audit.py -d example.com -d mail.example.org -d partner.io

# Audit a list of domains from file
python3 vamp_mail_audit.py -f domains.txt

# DNS-only mode (skip live SMTP probing)
python3 vamp_mail_audit.py -d example.com --no-smtp

# Custom SMTP timeout for slow MX servers
python3 vamp_mail_audit.py -d example.com --mx-timeout 30

# Export findings to JSON and HTML
python3 vamp_mail_audit.py -d example.com --json results.json --html report.html

# Generate client-ready engagement report
python3 vamp_mail_audit.py -f domains.txt \
    --client "Acme Corp" --engagement "Email Security Review Q3 2026" \
    --auditor "J. Smith" --report-html client_report.html --report-pdf client_report.pdf
```

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-d / --domain DOMAIN` | — | Domain to audit (repeatable for batch scans) |
| `-f / --file FILE` | — | Text file with one domain per line (lines starting with `#` ignored) |
| `--mx-timeout N` | 10 | SMTP connection timeout in seconds |
| `--no-smtp` | off | Skip active SMTP probes (DNS analysis only) |
| `--json FILE` | — | Export results to JSON |
| `--html FILE` | — | Export dark-theme HTML report |
| `--client TEXT` | — | Client name for VSL engagement report |
| `--engagement TEXT` | — | Engagement title for VSL engagement report |
| `--auditor TEXT` | — | Auditor name for VSL engagement report |
| `--report-scope TEXT` | — | Scope description for VSL engagement report |
| `--report-html FILE` | — | Export unified VSL client report (HTML) |
| `--report-pdf FILE` | — | Export unified VSL client report (PDF, requires fpdf2) |

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console | (default) | Rich-colored per-domain panels with SPF/DKIM/DMARC/SMTP findings |
| JSON | `--json FILE` | Machine-readable full result set |
| HTML | `--html FILE` | Dark-theme standalone report |
| Client HTML | `--report-html FILE` | Unified VampSecure Labs engagement report |
| Client PDF | `--report-pdf FILE` | PDF version of the VSL client report |

## Exit Codes

| Code | Meaning | CI/CD Behavior |
|------|---------|----------------|
| `0` | No critical or high findings | Pipeline passes |
| `1` | High-severity findings detected | Pipeline fails — review required |
| `2` | Critical-severity findings detected | Pipeline fails — immediate action required |

## Legal Notice

Use exclusively on systems you own or for which you hold explicit written authorization from the domain owner. Active SMTP probing (`--no-smtp` off) performs live connections to target mail servers. VampSecure Studios assumes no liability for unauthorized use.

## Part of VampSecure Labs Toolkit

`vamp-mail-audit` is one tool in the VampSecure Labs security research toolkit. For the full toolkit including the orchestrator that runs all tools in sequence and aggregates findings into a single engagement report, see:

- Portfolio: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division
