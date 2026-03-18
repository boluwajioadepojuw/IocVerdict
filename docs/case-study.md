# Case Study: Investigating a Suspected C2 Callback

## Scenario

**Incident date and time:** 16/03/2026, 02:14 UTC
**Detection method:** SIEM egress traffic alert
**Severity:** CRITICAL

A SOC analyst got an alert from the SIEM: an internal endpoint
(192.168.1.105) was making repeated outbound connections to an unknown
external IP. The alert triggered on the traffic pattern over a
10-minute window.

### Initial alert details

- Source IP: 192.168.1.105 (internal workstation, Sales department)
- Destination IP: 185.220.101.1 (external, unknown)
- Protocol: TCP over HTTPS (443)
- Volume: 47 outbound connections over 10 minutes
- Pattern: regular callbacks every 13 seconds. A botnet C2 heartbeat.

The analyst extracted the indicators from the alert logs:

### Extracted IOCs

1. IP: 185.220.101.1 (suspicious external IP)
2. Domain: update-service.xyz (SNI hostname from the encrypted traffic)
3. File hash (MD5): 5d41402abc4b2a76b9719d911017c592 (from a dropped
   file)

---

## Investigation with the IOC Threat Intelligence Engine

### Step 1: run the bulk analysis

```bash
cat > incident_iocs.txt << 'EOF'
# C2 Investigation - Incident #2326-001
185.220.101.1
update-service.xyz
5d41402abc4b2a76b9719d911017c592
EOF

python main.py --file incident_iocs.txt --output incident_report.md
```

### Step 2: review the enrichment results

**For IP 185.220.101.1:**

- VirusTotal: 45 out of 72 vendors flagged the IP
  - Categories: Trojan.Generic, Botnet, C2 Server
- AbuseIPDB: 94% confidence of malicious activity
  - 312 reports in the last 90 days
  - Last reported 2 hours before the alert (fresh)
  - ISP: Hosting Provider X (known for zero-tolerance abuse)
- Feodo Tracker: LISTED as active botnet C2 infrastructure
  - Malware family: Emotet/Trickbot variant
  - First seen: 15/11/2025
  - Last observed online: 16/03/2026 02:10 UTC

**For domain update-service.xyz:**

- VirusTotal: 18 vendors flagged the domain
  - Categories: C2, Phishing, Malware Distribution
- URLhaus: domain LISTED
  - 23 malicious URLs hosted on it
  - Tags: phishing, trojan, c2
  - Status: active

**For hash 5d41402abc4b2a76b9719d911017c592:**

- VirusTotal: 52 vendors detected the file as malicious
  - File type: PE32 executable
  - Common names: Win32.Trojan.Emotet, HackTool.Generic
  - First submission: 01/03/2026
  - Last analysis: 16/03/2026

### Step 3: MITRE ATT&CK mapping

| IOC | Detected Threat | Mapped Technique | Tactic |
|-----|-----------------|------------------|--------|
| 185.220.101.1 | Botnet C2 Server | T1071.001 - Web Protocols | Command and Control |
| update-service.xyz | C2/Phishing Domain | T1566 - Phishing | Initial Access |
| 5d41402abc4b2a76b9719d911017c592 | Trojan Malware | T1204 - User Execution | Execution |

Raw mapping:

```
185.220.101.1 (Feodo listed IP)
  Technique: T1071.001 (Web Protocols)
  Tactic: Command and Control
  Description: C2 communication over web protocols

update-service.xyz (C2 domain)
  Technique: T1566 (Phishing)
  Tactic: Initial Access
  Description: Domain used for payload delivery and C2

File hash (Trojan)
  Technique: T1204 (User Execution)
  Tactic: Execution
  Description: Malicious file requiring user execution
```

### Step 4: risk scoring

| IOC | Risk Score | Level | Justification |
|-----|-----------|-------|---------------|
| 185.220.101.1 | 95/100 | CRITICAL | Feodo listed (30) + VT 45/72 (75) + AbuseIPDB 94% (56), capped at 95 |
| update-service.xyz | 77/100 | HIGH | URLhaus listed (25) + VT 18 vendors (52) |
| 5d41402abc4b2a76b9719d911017c592 | 88/100 | CRITICAL | VT 52 vendors (88) + Trojan classification |

### Step 5: verdict and actions

**VERDICT: ALL THREE IOCs CONFIRMED MALICIOUS**

Immediate actions:

1. **Network isolation:** isolate 192.168.1.105 from the network
2. **IP blocking:** block 185.220.101.1 at firewall/proxy
3. **DNS blocking:** add update-service.xyz to the blocklist
4. **Endpoint cleanup:** scan 192.168.1.105 with updated signatures
5. **Credential rotation:** force password reset for the Sales
   department (possible lateral movement)
6. **Log review:** search the SIEM for other connections to the same C2
7. **Alert rule:** new IDS signature for Emotet callbacks

Evidence preservation: pcap of the C2 traffic, dropped sample submitted
to the AV lab, full SIEM logs exported for the IR team.

---

## Outcome

**Status: incident confirmed and contained**

Within 8 minutes of the alert the tool had identified 3 confirmed
malicious indicators, mapped them to MITRE ATT&CK, and produced the
recommendations with confidence scores.

Result:

- Endpoint isolated before any lateral movement
- No data exfiltration in the log review
- C2 communication blocked at the firewall
- Malware removed from the endpoint

Post-incident:

- Feodo Tracker confirmed the IP was active Emotet C2
- 47 other organizations reported connections to the same IP in the
  previous 24 hours
- The endpoint had outdated Windows patches
- The Sales department got phishing awareness training

---

## What this case shows

1. **Speed:** what would take 30+ minutes of manual lookups per source
   took seconds in one command.
2. **Confidence:** multiple independent sources agreed at >90%.
3. **Context:** MITRE mapping connected the findings to documented
   attack techniques immediately.
4. **Prioritization:** risk scoring put the most critical indicators
   first.
5. **Automation:** bulk processing of several IOCs in one run.

Without automated enrichment this incident would likely have progressed
further into the attack chain. Multi-source validation and automated
MITRE mapping turned a potential breach into a contained incident.
