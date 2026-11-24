# sec-log-triage

A lightweight, zero-dependency Python CLI tool for **security log schema validation, multi-event correlation, and automated forensic incident triage**.

`sec-log-triage` normalizes mixed JSONL and ISO-timestamped syslog/auth log streams into a unified event model, flags malformed or incomplete records in a dedicated validation log, and executes stateful and stateless detection rules to surface actionable security findings.

## Features

- **Schema & Format Validation:** Parses JSONL and syslog/auth lines while recording malformed JSON, missing keys, or bad timestamps under `validation_warnings`.
- **Brute-Force Burst Detection (`SEC-001`):** Tracks failed authentication attempts per source IP across a sliding time window (`120s` default, `5+` failures) and differentiates external vs. internal IPs.
- **Privilege Escalation & Sensitive Access (`SEC-002`):** Flags high-risk `sudo` commands, group/permission changes, and access to sensitive system files (`/etc/shadow`, `/etc/sudoers`).
- **Sensitive Endpoint & Path Probing (`SEC-003`):** Detects probing and traversal attempts targeting exposed files (`/.env`, `/.git/config`) and injection patterns.
- **Post-Brute-Force Compromise Correlation (`SEC-004`):** Elevates successful authentication events from an IP that recently triggered brute-force activity to `CRITICAL`.
- **Dual Output & CI Exit Codes:** Exports both a structured JSON audit trail (`triage_report.json`) and a Markdown incident summary (`triage_summary.md`), exiting with code `1` when `HIGH` or `CRITICAL` findings are detected.

## Quickstart

Requires **Python 3.10+** (standard library only—no `pip install` required).

```bash
git clone [https://github.com/B5IVE/sec-log-triage.git](https://github.com/B5IVE/sec-log-triage.git)
cd sec-log-triage

python3 triage.py sample_logs.jsonl
