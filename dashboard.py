#!/usr/bin/env python3
"""
Live dashboard — tail the NIDS alert log and display a summary table.
Run this in a second terminal while nids.py is running:

    python3 dashboard.py
    python3 dashboard.py --log nids_alerts.log
"""

import argparse
import json
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime

_CLEAR  = "\033[2J\033[H"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"

SEV_COLOR = {
    "CRITICAL": _RED + _BOLD,
    "HIGH":     _RED,
    "MEDIUM":   _YELLOW,
    "LOW":      _CYAN,
}


def parse_args():
    p = argparse.ArgumentParser(description="NIDS alert dashboard")
    p.add_argument("--log", default="nids_alerts.log", help="Alert log file to watch")
    p.add_argument("--refresh", type=float, default=2.0, help="Refresh interval (seconds)")
    p.add_argument("--top", type=int, default=10, help="Show top N offenders")
    return p.parse_args()


def load_alerts(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return records


def render(records: list[dict], top: int, log_path: str):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(records)

    by_severity: Counter = Counter(r.get("severity", "?") for r in records)
    by_type:     Counter = Counter(r.get("alert_type", "?") for r in records)
    by_src:      Counter = Counter(r.get("src_ip", "?") for r in records)

    recent = records[-20:]

    print(_CLEAR, end="")
    print(f"{_BOLD}{_CYAN}╔══════════════════════════════════════════════════════════════╗")
    print(f"║          Project 1984 — NIDS Dashboard   {now}  ║")
    print(f"╚══════════════════════════════════════════════════════════════╝{_RESET}")
    print(f"  Log: {log_path}   Total alerts: {_BOLD}{total}{_RESET}\n")

    # Severity summary
    print(f"{_BOLD}  Severity Breakdown:{_RESET}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = by_severity.get(sev, 0)
        bar = "█" * min(count, 40)
        c = SEV_COLOR.get(sev, "")
        print(f"    {c}{sev:8s}{_RESET}  {bar} {count}")

    print()

    # Top alert types
    print(f"{_BOLD}  Top Alert Types:{_RESET}")
    for alert_type, count in by_type.most_common(top):
        print(f"    {count:5d}  {alert_type}")

    print()

    # Top offending IPs
    print(f"{_BOLD}  Top Offending Source IPs:{_RESET}")
    for ip, count in by_src.most_common(top):
        print(f"    {count:5d}  {ip}")

    print()

    # Recent alerts
    print(f"{_BOLD}  Recent Alerts (last 20):{_RESET}")
    print(f"  {'Time':8s}  {'Severity':8s}  {'Type':30s}  {'Src IP':16s}  Details")
    print(f"  {'─'*8}  {'─'*8}  {'─'*30}  {'─'*16}  {'─'*30}")
    for r in reversed(recent):
        ts = r.get("timestamp", "")
        if ts:
            ts = ts[11:19]  # HH:MM:SS
        sev   = r.get("severity", "?")
        atype = r.get("alert_type", "?")[:30]
        src   = r.get("src_ip", "?")[:16]
        det   = " ".join(f"{k}={v}" for k, v in r.get("details", {}).items())[:50]
        c = SEV_COLOR.get(sev, "")
        print(f"  {ts:8s}  {c}{sev:8s}{_RESET}  {atype:30s}  {src:16s}  {det}")

    print(f"\n  Refreshing every {args.refresh}s — Ctrl+C to quit.")


def main():
    global args
    args = parse_args()

    print(f"Watching {args.log} — press Ctrl+C to quit.")
    try:
        while True:
            records = load_alerts(args.log)
            render(records, args.top, args.log)
            time.sleep(args.refresh)
    except KeyboardInterrupt:
        print("\nDashboard stopped.")


if __name__ == "__main__":
    main()
