# IOC Threat Intelligence Engine

A threat intelligence enrichment tool. Give it an IP, domain, URL, or
file hash and it checks it against 5 independent threat sources, scores
it, and maps the findings to MITRE ATT&CK.

```
Input: single IOC or a file of IOCs
  -> Detection: automatic type identification (IPv4, IPv6, domain, URL, hash)
  -> Enrichment: query 5 threat feeds
     - VirusTotal (AV engine aggregator)
     - AbuseIPDB (IP reputation)
     - AlienVault OTX (threat pulses)
     - Feodo Tracker (botnet C2 tracker)
     - URLhaus (malware URL database)
  -> Scoring: composite risk score (0-100)
  -> Mapping: MITRE ATT&CK technique and tactic
  -> Report: markdown or JSON output
```

---

## What it does

**Multiple IOC types.** IPv4, IPv6, domains, URLs, and file hashes
(MD5, SHA1, SHA256, SHA512).

**Five independent sources.**

- VirusTotal: multi-engine AV scan results
- AbuseIPDB: IP reputation and abuse reports
- AlienVault OTX: threat pulses, crowdsourced intel
- Feodo Tracker: botnet C2 blocklist
- URLhaus: malware URL database

**Automatic type detection.** Validation and classification with no
configuration.

**Composite risk scoring.** Weighted signals from all sources, 0-100
scale with 5 severity levels.

**MITRE ATT&CK mapping.** Automatic technique and tactic mapping for
every detection.

**Bulk processing.** 10, 100, or 1000 IOCs in one command.

**Reports.** Markdown output with summary statistics, risk breakdown,
and recommendations.

**Failure handling.** Rate limiting, error handling, and graceful
degradation when a source fails.

---

## Installation

Prerequisites: Python 3.8+ and pip.

```bash
cd ioc-threat-intel
pip install -r requirements.txt
cp .env.example .env

# Edit .env with your credentials.
# Required: VT_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY
# Optional: SHODAN_API_KEY
```

### API keys

| Service | Key | Free Tier |
|---------|-----|-----------|
| VirusTotal | VT_API_KEY | Yes (limits apply) |
| AbuseIPDB | ABUSEIPDB_API_KEY | Yes (limits apply) |
| AlienVault OTX | OTX_API_KEY | Yes |
| Shodan | SHODAN_API_KEY | Yes |
| Feodo Tracker | Not required | Yes (no auth) |
| URLhaus | Not required | Yes (no auth) |

---

## Usage

### Single IOC analysis

```bash
python main.py --ioc 8.8.8.8

# Output:
# Type: ipv4
# Risk Score: 10/100 - CLEAN
# VirusTotal: 0 malicious, 0 suspicious
# AbuseIPDB: Confidence 0%, 0 reports
# Feodo Tracker: Not listed
# MITRE: T1071 - Application Layer Protocol (Command and Control)
# Verdict: CLEAN - No immediate action recommended
```

### Bulk file processing

```bash
python main.py --file iocs.txt --output report.md

# Input file format, one per line:
# 8.8.8.8
# malware.example.com
# d41d8cd98f00b204e9800998ecf8427e
# https://evil-site.net/malware
```

### Suppress console output

```bash
python main.py --file iocs.txt --output report.md --quiet
```

---

## Example output

### Console

```
[1] IOC: 185.220.101.1
    Type: IPv4 Address
    Risk Score: 95/100 - CRITICAL

    Threat Intelligence:
      VirusTotal: 45 malicious, 3 suspicious
      AbuseIPDB: Confidence 94%, 312 reports
      Feodo Tracker: LISTED - Known Botnet C2 (Emotet)
      AlienVault OTX: 7 pulses

    MITRE ATT&CK:
      Primary: T1071.001 - Web Protocols
      Tactic: Command and Control
      Confidence: 95%
      Additional Techniques:
        - T1090 - Proxy
        - T1583 - Acquire Infrastructure

    Verdict: MALICIOUS - Recommend immediate block
```

### Markdown report

```markdown
# IOC Threat Intelligence Report
Generated: 2026-03-16 14:32:11 UTC

## [1] IOC: 185.220.101.1

Type: ipv4
Risk Score: 95/100 - CRITICAL

### Threat Intelligence

**VirusTotal:**
- Malicious: 45/72
- Suspicious: 3/72
- Categories: Trojan.Generic, Botnet, C2

**AbuseIPDB:**
- Confidence Score: 94%
- Total Reports: 312
- ISP: Hosting Provider X

**Feodo Tracker:**
- LISTED - Known Botnet C2
- Malware: Emotet/Trickbot variant
- Status: Active

---

# Summary
Total IOCs Analyzed: 3
Critical: 1 | High: 1 | Medium: 0 | Low: 0 | Clean: 1

## Recommendations
IMMEDIATE ACTION REQUIRED
- Block detected malicious IOCs at perimeter
- Alert security team for incident response
- Isolate affected endpoints
```

---

## Project structure

```
ioc-threat-intel/
├── main.py
├── ioc_intel/
│   ├── __init__.py
│   ├── validator.py        # IOC type detection and validation
│   ├── enricher.py         # API integration, all 5 sources
│   ├── scorer.py           # Risk scoring algorithm
│   ├── mitre_mapper.py     # MITRE ATT&CK mapping
│   └── reporter.py         # Report generation
├── tests/
│   ├── test_validator.py
│   ├── test_scorer.py
│   └── test_mitre_mapper.py
├── docs/
│   └── case-study.md       # Investigation scenario
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

---

## How scoring works

Risk scores are calculated from weighted signals:

| Signal | Weight | Max Points |
|--------|--------|------------|
| VirusTotal malicious detections (>=5) | 80 | 80 |
| VirusTotal suspicious detections | 2 | 20 |
| AbuseIPDB confidence score | 0.8 | 80 |
| AbuseIPDB total reports | 0.5 | 20 |
| Feodo Tracker listed | +30 | 30 |
| URLhaus listed | +25 | 25 |
| OTX pulse count | 5 | 30 |
| Shodan vulnerabilities | 10 | 25 |
| | | **Max: 100** |

### Severity levels

| Level | Score | Action |
|-------|-------|--------|
| CRITICAL | 80-100 | Block immediately, investigate |
| HIGH | 60-79 | Escalate, block if possible |
| MEDIUM | 40-59 | Monitor, investigate |
| LOW | 15-39 | Log, monitor |
| CLEAN | 0-14 | Approved for use |

---

## MITRE ATT&CK coverage

24+ techniques across 9 tactics, mapped dynamically from threat feed
tags with confidence scoring.

### Coverage by tactic

| Tactic | Techniques | Trigger Keywords |
|--------|---|---|
| Command and Control | T1071, T1071.001, T1071.004, T1090, T1219 | c2, botnet, c&c, c2_ip, proxy, tor, rat |
| Initial Access | T1566, T1566.002, T1189, T1190 | phishing, spearphishing, driveby, exploit |
| Execution | T1204, T1059 | trojan, malware, script, execution |
| Credential Access | T1555, T1056.001 | stealer, infostealer, keylogger |
| Persistence | T1543, T1219 | backdoor, rat, persistence |
| Defense Evasion | T1027, T1027.002 | obfuscated, packer, obfuscation |
| Collection and Exfil | T1041, T1020 | exfiltration, exfil, data-theft |
| Impact | T1486, T1498, T1485 | ransomware, ddos, wiper, impact |
| Resource Development | T1583, T1583.004, T1105 | infrastructure, botnet, malware-distribution |

### Full technique reference

```
Command and Control (5):
  T1071 - Application Layer Protocol
  T1071.001 - Web Protocols (HTTP/HTTPS)
  T1071.004 - DNS (DNS Tunneling)
  T1090 - Proxy (Tor, VPN, anonymization)
  T1219 - Remote Access Software (RAT)

Initial Access (4):
  T1566 - Phishing
  T1566.002 - Spearphishing Link
  T1189 - Drive-by Compromise
  T1190 - Exploit Public-Facing Application

Execution (2):
  T1204 - User Execution
  T1059 - Command and Scripting Interpreter

Credential Access (2):
  T1555 - Credentials from Password Stores
  T1056.001 - Keylogging

Persistence (2):
  T1543 - Create or Modify System Process
  T1219 - Remote Access Software

Defense Evasion (2):
  T1027 - Obfuscated Files or Information
  T1027.002 - Software Packing

Collection and Exfiltration (2):
  T1041 - Exfiltration Over C2 Channel
  T1020 - Automated Exfiltration

Impact (3):
  T1486 - Data Encrypted for Impact (Ransomware)
  T1498 - Network Denial of Service (DDoS)
  T1485 - Data Destruction (Wiper)

Resource Development (3):
  T1583 - Acquire Infrastructure
  T1583.004 - Server - Botnet
  T1105 - Ingress Tool Transfer
```

### Confidence scoring

- 65%+ baseline (no external tags)
- +10% per confirmed threat feed tag
- Up to 100% with multiple sources

### How the mapping works

The engine extracts tags from all feeds (URLhaus, OTX, VirusTotal,
Feodo), normalizes them (phishing, Phishing, phishing-domain become one
tag), maps tags to techniques, and returns a primary technique plus
additional ones, each with a confidence score.

---

## Testing

```bash
pip install pytest
pytest tests/ -v
pytest tests/test_mitre_mapper.py -v
pytest tests/ --cov=ioc_intel
```

Current status: 53 tests passing.

- 20 MITRE mapper tests (technique coverage, tag normalization,
  multi-source mapping)
- 20 risk scorer tests (composite scoring, severity levels)
- 13 IOC validator tests (type detection, format validation)

---

## Case study

See [docs/case-study.md](docs/case-study.md) for an investigation
scenario showing the tool in action: C2 callback detection, multi-source
validation, MITRE mapping, containment in 8 minutes.

---

## Performance

- Single IOC: ~2-3 seconds (API dependent)
- Bulk of 10 IOCs: ~15-30 seconds (rate-limited)
- Report generation: <1 second

---

## Error handling

- Missing API keys: source skipped, others continue
- Network timeouts: partial results with available data
- Invalid IOCs: marked unknown, the rest processed
- Rate limits: automatic retry with backoff
- File not found: clear error message, exit

---

## Security notes

- Never commit `.env` with real API keys
- `.env` is in `.gitignore`
- Use `.env.example` as the template with placeholder values
- Rotate API keys periodically

---

## Author

Boluwaji Oluwaseyi Adepoju

---

## Roadmap

- More feed integrations (URLScan, Censys, AbuseIPDB API v2)
- Custom risk scoring rules and thresholds
- Slack/Teams integration for automated alerts
- Historical tracking and trend analysis
- Bulk API optimization

---

## License

This tool is provided as-is for education and security research.
