# Case Study: Verdict on a Suspected C2 Callback

## The alert

16/03/2026, 02:14 UTC. The SIEM raised an egress alert: workstation
WS-042 (192.168.1.105) made repeated short outbound connections to a single
external IP over ten minutes, port 443, with a fixed User-Agent. First
hypothesis: beaconing.

## What I did

1. Pulled the destination IP from the alert (say 185.220.101.34).
2. Ran it through IocVerdict:

   - VirusTotal: 12/92 engines flagged the IP as malicious, 4 suspicious.
   - AbuseIPDB: confidence 100, 2,400+ reports in 90 days.
   - Feodo Tracker: listed as a botnet C2.
   - URLhaus: n/a (IP indicator).
   - OTX: 11 pulses tie the IP to a known loader campaign.
   - Shodan: no exposed services (typical for C2 infra).

3. Score: 100/100. MITRE mapping: T1071 (Application Layer Protocol) for
   the beacon channel, T1583.001 (Acquire Infrastructure) for the hosting.

## The verdict

The IP is a known botnet C2 with a long report history; the endpoint's
traffic pattern matches beaconing. Escalated: host isolated, destination
blocked at the gateway, and the workstation re-imaged after confirming no
data staging on disk.

## What I learned

- Free sources disagree in volume, not in direction: the score comes from
  the overlap, not any single feed.
- A clean Shodan result is itself a signal - legitimate services usually
  expose something.
