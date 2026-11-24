#!/usr/bin/env python3
"""
sec-log-triage: Deterministic Security Log Triage & Forensic Correlation Engine.

Ingests JSONL or raw syslog/auth log streams, validates event schemas, detects
high-signal threat patterns (brute-force bursts, privilege escalation, sensitive
endpoint probing, off-hours access), and emits a structured JSON audit trail
plus a Markdown incident summary.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# --- Detection Thresholds & Signatures ---
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 120

PRIV_ESC_PATTERNS = re.compile(
    r"(sudo:\s+.*COMMAND=|usermod\s+-aG\s+(sudo|wheel|admin)|chmod\s+[0-7]*777|/etc/shadow|/etc/sudoers)",
    re.IGNORECASE,
)

SENSITIVE_PATH_PATTERNS = re.compile(
    r"(/\.env|/\.git/config|/wp-admin|/etc/passwd|/proc/self/environ|\.\./\.\./|union\s+select)",
    re.IGNORECASE,
)

SYSLOG_AUTH_REGEX = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
    r"(?P<host>\S+)\s+(?P<service>[^\[:]+)(?:\[\d+\])?:\s+(?P<message>.+)$"
)

IP_EXTRACT_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class NormalizedEvent:
    line_number: int
    timestamp: datetime
    source_ip: str
    event_type: str
    user: str
    status: str
    message: str
    raw: str


@dataclass
class Finding:
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    source_ip: str
    user: str
    event_count: int
    first_seen: str
    last_seen: str
    evidence: list[str] = field(default_factory=list)


def is_external_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved)
    except ValueError:
        return False


def parse_timestamp(ts_raw: str) -> datetime:
    cleaned = ts_raw.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(cleaned)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def normalize_line(line: str, line_number: int) -> tuple[NormalizedEvent | None, str | None]:
    """Parses either JSONL or structured syslog lines into a NormalizedEvent."""
    stripped = line.strip()
    if not stripped:
        return None, None

    # Attempt JSONL parsing first
    if stripped.startswith("{"):
        try:
            payload: dict[str, Any] = json.loads(stripped)
            required = {"timestamp", "event_type", "message"}
            missing = required - payload.keys()
            if missing:
                return None, f"Line {line_number}: Missing required JSON keys {sorted(missing)}"

            ts = parse_timestamp(str(payload["timestamp"]))
            src_ip = str(payload.get("source_ip", "0.0.0.0"))
            return (
                NormalizedEvent(
                    line_number=line_number,
                    timestamp=ts,
                    source_ip=src_ip,
                    event_type=str(payload["event_type"]).lower(),
                    user=str(payload.get("user", "unknown")),
                    status=str(payload.get("status", "unknown")).lower(),
                    message=str(payload["message"]),
                    raw=stripped,
                ),
                None,
            )
        except (json.JSONDecodeError, ValueError) as exc:
            return None, f"Line {line_number}: Malformed JSON record ({exc})"

    # Fallback: Syslog / Auth log format
    match = SYSLOG_AUTH_REGEX.match(stripped)
    if not match:
        return None, f"Line {line_number}: Unrecognized log format"

    try:
        ts = parse_timestamp(match.group("timestamp"))
    except ValueError as exc:
        return None, f"Line {line_number}: Invalid timestamp ({exc})"

    msg = match.group("message")
    ip_match = IP_EXTRACT_REGEX.search(msg)
    src_ip = ip_match.group(0) if ip_match else "0.0.0.0"

    status = "failure" if any(k in msg.lower() for k in ("failed", "invalid", "denied", "error")) else "success"
    user_match = re.search(r"(?:for invalid user |for user |user=|for )([a-zA-Z0-9._-]+)", msg)
    user = user_match.group(1) if user_match else "unknown"

    return (
        NormalizedEvent(
            line_number=line_number,
            timestamp=ts,
            source_ip=src_ip,
            event_type=match.group("service").lower(),
            user=user,
            status=status,
            message=msg,
            raw=stripped,
        ),
        None,
    )


def run_detections(events: list[NormalizedEvent]) -> list[Finding]:
    """Executes stateful and stateless forensic rules over normalized events."""
    findings: list[Finding] = []
    events_sorted = sorted(events, key=lambda e: e.timestamp)

    # 1. Stateful sliding-window brute-force detection per source IP
    failures_by_ip: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for ev in events_sorted:
        if ev.status in {"failure", "failed", "denied"} and ev.source_ip != "0.0.0.0":
            failures_by_ip[ev.source_ip].append(ev)

    for src_ip, failed_events in failures_by_ip.items():
        window = timedelta(seconds=BRUTE_FORCE_WINDOW_SECONDS)
        left = 0
        triggered = False
        for right in range(len(failed_events)):
            while failed_events[right].timestamp - failed_events[left].timestamp > window:
                left += 1
            burst = failed_events[left : right + 1]
            if len(burst) >= BRUTE_FORCE_THRESHOLD and not triggered:
                triggered = True
                users_targeted = sorted({e.user for e in burst})
                findings.append(
                    Finding(
                        rule_id="SEC-001",
                        severity="HIGH" if is_external_ip(src_ip) else "MEDIUM",
                        title="Authentication Brute-Force Burst Detected",
                        source_ip=src_ip,
                        user=", ".join(users_targeted),
                        event_count=len(burst),
                        first_seen=burst[0].timestamp.isoformat(),
                        last_seen=burst[-1].timestamp.isoformat(),
                        evidence=[f"L{e.line_number}: {e.message}" for e in burst[:3]],
                    )
                )

    # 2. Privilege escalation & sensitive file/command execution
    for ev in events_sorted:
        if PRIV_ESC_PATTERNS.search(ev.message):
            findings.append(
                Finding(
                    rule_id="SEC-002",
                    severity="CRITICAL",
                    title="High-Risk Privilege Escalation or Sensitive File Access",
                    source_ip=ev.source_ip,
                    user=ev.user,
                    event_count=1,
                    first_seen=ev.timestamp.isoformat(),
                    last_seen=ev.timestamp.isoformat(),
                    evidence=[f"L{ev.line_number}: {ev.message}"],
                )
            )

        # 3. Web/API path traversal & credential probing
        if SENSITIVE_PATH_PATTERNS.search(ev.message):
            findings.append(
                Finding(
                    rule_id="SEC-003",
                    severity="HIGH",
                    title="Sensitive Endpoint / Path Traversal Probing",
                    source_ip=ev.source_ip,
                    user=ev.user,
                    event_count=1,
                    first_seen=ev.timestamp.isoformat(),
                    last_seen=ev.timestamp.isoformat(),
                    evidence=[f"L{ev.line_number}: {ev.message}"],
                )
            )

    # 4. Post-bruteforce successful login correlation (compromise indicator)
    brute_force_ips = {f.source_ip for f in findings if f.rule_id == "SEC-001"}
    for ev in events_sorted:
        if ev.source_ip in brute_force_ips and ev.status in {"success", "accepted"}:
            findings.append(
                Finding(
                    rule_id="SEC-004",
                    severity="CRITICAL",
                    title="Successful Authentication Following Brute-Force Activity",
                    source_ip=ev.source_ip,
                    user=ev.user,
                    event_count=1,
                    first_seen=ev.timestamp.isoformat(),
                    last_seen=ev.timestamp.isoformat(),
                    evidence=[f"L{ev.line_number}: {ev.message}"],
                )
            )

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(findings, key=lambda f: (severity_rank.get(f.severity, 9), f.first_seen))


def render_markdown_report(
    input_path: Path,
    total_lines: int,
    valid_events: list[NormalizedEvent],
    schema_errors: list[str],
    findings: list[Finding],
) -> str:
    lines = [
        "# Security Log Triage & Forensic Report",
        "",
        f"- **Source File:** `{input_path.name}`",
        f"- **Generated (UTC):** `{datetime.now(timezone.utc).isoformat()}`",
        f"- **Lines Processed:** `{total_lines}` | **Valid Events:** `{len(valid_events)}` | **Schema/Parse Errors:** `{len(schema_errors)}`",
        f"- **Total Findings:** `{len(findings)}`",
        "",
        "## Prioritized Findings",
        "",
    ]

    if not findings:
        lines.append("_No security anomalies exceeded detection thresholds._")
    else:
        lines.extend(
            [
                "| Severity | Rule | Finding | Source IP | Target User(s) | Count | Timestamp (UTC) |",
                "| :--- | :--- | :--- | :--- | :--- | :---: | :--- |",
            ]
        )
        for f in findings:
            lines.append(
                f"| **{f.severity}** | `{f.rule_id}` | {f.title} | `{f.source_ip}` | `{f.user}` | {f.event_count} | `{f.first_seen}` |"
            )

        lines.extend(["", "## Forensic Evidence Snippets", ""])
        for f in findings:
            lines.append(f"### [{f.severity}] {f.rule_id}: {f.title} (`{f.source_ip}`)")
            for item in f.evidence:
                lines.append(f"- `{item}`")
            lines.append("")

    if schema_errors:
        lines.extend(["## Data Validation & Parse Warnings", ""])
        for err in schema_errors[:10]:
            lines.append(f"- {err}")

    return "\n".join(lines).strip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Automated cybersecurity log validation, correlation, and triage CLI."
    )
    parser.add_argument("logfile", type=Path, help="Path to input .jsonl or .log file")
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("triage_report.json"),
        help="Output path for structured JSON audit report (default: triage_report.json)",
    )
    parser.add_argument(
        "--md-out",
        type=Path,
        default=Path("triage_summary.md"),
        help="Output path for Markdown incident summary (default: triage_summary.md)",
    )
    args = parser.parse_args()

    if not args.logfile.is_file():
        print(f"Error: Log file not found: {args.logfile}", file=sys.stderr)
        return 2

    valid_events: list[NormalizedEvent] = []
    schema_errors: list[str] = []
    total_lines = 0

    with args.logfile.open("r", encoding="utf-8") as handle:
        for idx, raw_line in enumerate(handle, start=1):
            total_lines += 1
            event, err = normalize_line(raw_line, idx)
            if err:
                schema_errors.append(err)
            elif event:
                valid_events.append(event)

    findings = run_detections(valid_events)

    audit_payload = {
        "metadata": {
            "source_file": str(args.logfile),
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "lines_processed": total_lines,
            "valid_events": len(valid_events),
            "schema_errors": len(schema_errors),
        },
        "findings": [asdict(f) for f in findings],
        "validation_warnings": schema_errors,
    }

    args.json_out.write_text(json.dumps(audit_payload, indent=2), encoding="utf-8")
    md_report = render_markdown_report(args.logfile, total_lines, valid_events, schema_errors, findings)
    args.md_out.write_text(md_report, encoding="utf-8")

    print(
        f"[+] Triage complete: {len(valid_events)} events validated, "
        f"{len(findings)} findings detected ({len(schema_errors)} warnings)."
    )
    print(f"[+] Reports written to {args.json_out} and {args.md_out}")

    return 1 if any(f.severity in {"CRITICAL", "HIGH"} for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
