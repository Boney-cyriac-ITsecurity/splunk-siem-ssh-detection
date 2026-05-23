# Project 6 — Splunk SIEM: SSH Brute Force Detection & Alerting

## Objective
Ingest real SSH brute force attack logs into Splunk, build detection queries, 
create a monitoring dashboard, and configure automated alerting.

## Lab Environment
- SIEM: Splunk Enterprise 9.2.1 (Ubuntu 22.04)
- Attacker: Kali Linux 192.168.1.43
- Target/SIEM: Ubuntu 22.04 192.168.1.42
- Data Source: auth.log from real Hydra SSH brute force attack (Project 5)

## Attack Summary
- Tool used: Hydra with rockyou.txt wordlist
- Target: SSH port 22
- Total failed attempts: 123
- Peak rate: 64 attempts/minute at 11:50 AM
- Attacker IP: 192.168.1.43

## SPL Detection Queries

### Query 1 — Identify Attackers
index=main sourcetype=linux_secure "Failed password"
| rex "from (?P<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by attacker_ip
| sort -count

### Query 2 — Threshold Detection
index=main sourcetype=linux_secure "Failed password"
| rex "from (?P<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by attacker_ip
| where count > 10
| eval status="BRUTE FORCE DETECTED"
| table attacker_ip, count, status

### Query 3 — Attack Timeline
index=main sourcetype=linux_secure "Failed password"
| rex "from (?P<attacker_ip>\d+\.\d+\.\d+\.\d+)"
| where attacker_ip="192.168.1.43"
| timechart span=1m count as "Failed Attempts"

## Dashboard
Built "SSH Brute Force Detection" dashboard with 3 panels:
- Detected Attackers (statistics table)
- Attack Timeline (column chart)
- Total Failed Attempts (single value: 123)

## Alert Configuration
- Name: SSH Brute Force Detected
- Type: Scheduled, runs every hour
- Trigger: Number of results > 0
- Action: Add to Triggered Alerts (Medium severity)

## False Positive Analysis
This alert could fire for:
- Automated SSH monitoring tools
- Misconfigured backup scripts
- Admin running repeated SSH tests

Mitigation: Whitelist known admin IPs, raise threshold to 20,
add time-window correlation (10+ failures within 60 seconds).

## Analyst Conclusion
192.168.1.43 conducted a credential brute force attack against SSH 
on 2026-05-21. Attack lasted ~3 minutes with peak intensity of 64 
attempts/minute. No successful authentication detected. Recommended 
action: block IP at firewall, review SSH hardening (fail2ban, 
key-only auth, non-standard port).

## Skills Demonstrated
- Splunk installation and configuration
- Log ingestion and sourcetype configuration
- SPL query writing and field extraction
- Custom regex extraction (rex command)
- Dashboard creation
- Alert engineering
- False positive analysis
- Analyst investigation workflow