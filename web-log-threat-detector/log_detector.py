#!/usr/bin/env python3
"""
Real-time Web Log Analyzer & Threat Detector
Author: Your Name
Description: Parses web server access logs and detects malicious activity using signature rules.
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()

# Nginx/Apache Combined Log Regex
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) (?P<bytes>\d+)'
)

# Threat Signatures
THREAT_RULES = {
    "SQL Injection (SQLi)": re.compile(r"(?i)(union|select|insert|delete|drop|or\s+1=1|'|--|#)"),
    "Cross-Site Scripting (XSS)": re.compile(r"(?i)(<script>|javascript:|onload=|onerror=)"),
    "Path Traversal": re.compile(r"(\.\./|\.\.\\)"),
    "Sensitive File Access": re.compile(r"(?i)(/etc/passwd|\.env|\.git/|wp-config\.php)")
}

def analyze_log_line(line: str) -> dict | None:
    match = LOG_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()
    detected_threats = []

    # Rule Check
    for threat_name, rule_regex in THREAT_RULES.items():
        if rule_regex.search(data["url"]):
            detected_threats.append(threat_name)

    if detected_threats:
        return {
            "ip": data["ip"],
            "time": data["time"],
            "method": data["method"],
            "url": data["url"],
            "status": data["status"],
            "threats": ", ".join(detected_threats)
        }
    return None

def detect_brute_force(log_file_path: str, threshold: int = 5) -> list:
    """Detects IPs exceeding failed login thresholds."""
    failed_logins = defaultdict(int)
    suspicious_ips = []

    with open(log_file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = LOG_PATTERN.match(line)
            if match:
                data = match.groupdict()
                if "login" in data["url"].lower() and data["status"] in ["401", "200"]:
                    failed_logins[data["ip"]] += 1

    for ip, count in failed_logins.items():
        if count >= threshold:
            suspicious_ips.append({"ip": ip, "count": count, "threat": "Potential Brute Force"})

    return suspicious_ips

def main():
    parser = argparse.ArgumentParser(description="Web Log Threat Detector & Analyzer")
    parser.add_argument("logfile", help="Path to web server log file (e.g., access.log)")
    parser.add_argument("-oJ", "--json", help="Export threats to JSON file")
    args = parser.parse_args()

    try:
        with open(args.logfile, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        console.print(f"[bold red][-] Error:[/] File '{args.logfile}' not found.")
        sys.exit(1)

    console.print(f"\n[bold blue][*] Analyzing Log File:[/] {args.logfile}")
    console.print(f"[bold blue][*] Total Lines Processed:[/] {len(lines)}\n")

    threat_results = []
    for line in lines:
        res = analyze_log_line(line)
        if res:
            threat_results.append(res)

    # Brute Force Check
    brute_force_results = detect_brute_force(args.logfile)

    # Table Output
    table = Table(title="Detected Security Threats")
    table.add_column("IP Address", style="cyan")
    table.add_column("Timestamp", style="magenta")
    table.add_column("Method", style="yellow")
    table.add_column("Threat Type", style="bold red")
    table.add_column("Target URL / Payload", style="white")

    for item in threat_results:
        table.add_row(item["ip"], item["time"], item["method"], item["threats"], item["url"])

    for item in brute_force_results:
        table.add_row(item["ip"], "Multiple Attempts", "POST", item["threat"], f"{item['count']} Failed Attempts")

    console.print(table)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"threats": threat_results, "brute_force": brute_force_results}, f, indent=4)
        console.print(f"\n[bold green][+] Findings exported to {args.json}[/]")

if __name__ == "__main__":
    main()