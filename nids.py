#!/usr/bin/env python3
"""
Project 1984 — Simple NIDS
Usage:
    sudo python3 nids.py
    sudo python3 nids.py --iface eth0
    sudo python3 nids.py --iface en0 --blocklist my_ips.txt --filter "tcp"
"""

import argparse
import signal
import sys
import time
from pathlib import Path

# Scapy import — suppress its IPv6 warnings
import logging as _logging
_logging.getLogger("scapy.runtime").setLevel(_logging.ERROR)

from scapy.all import sniff, conf as scapy_conf

import config
import alerts
import rules


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

_stats = {"packets": 0, "alerts": 0, "start": time.time()}


def _packet_handler(pkt):
    _stats["packets"] += 1
    rules.dispatch(pkt)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Project 1984 Simple NIDS — sniff and detect intrusions"
    )
    p.add_argument(
        "--iface", "-i",
        default=None,
        help="Network interface to sniff (default: system default)",
    )
    p.add_argument(
        "--filter", "-f",
        default="ip",
        help='BPF filter string, e.g. "tcp" or "port 80" (default: ip)',
    )
    p.add_argument(
        "--blocklist", "-b",
        default=None,
        help="Path to a plain-text file with one malicious IP per line",
    )
    p.add_argument(
        "--count", "-c",
        type=int,
        default=0,
        help="Stop after capturing this many packets (0 = run forever)",
    )
    p.add_argument(
        "--log", "-l",
        default=config.LOG_FILE,
        help=f"Alert log file (default: {config.LOG_FILE})",
    )
    p.add_argument(
        "--timeout", "-t",
        type=int,
        default=None,
        help="Stop sniffing after N seconds",
    )
    return p.parse_args()


def load_blocklist(path: str):
    p = Path(path)
    if not p.exists():
        print(f"[WARN] Blocklist file not found: {path}")
        return
    added = 0
    for line in p.read_text().splitlines():
        ip = line.strip()
        if ip and not ip.startswith("#"):
            config.MALICIOUS_IPS.add(ip)
            added += 1
    print(f"  Loaded {added} IPs from {path}")


def _on_exit(sig, frame):
    elapsed = time.time() - _stats["start"]
    print(f"\n\n  Captured {_stats['packets']} packets in {elapsed:.1f}s")
    print(f"  Alerts written to: {config.LOG_FILE}")
    sys.exit(0)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    # Apply CLI overrides to config
    if args.iface:
        config.INTERFACE = args.iface
    if args.log:
        config.LOG_FILE = args.log
    if args.blocklist:
        load_blocklist(args.blocklist)

    alerts.print_banner()

    # Require root/admin
    import os
    if os.geteuid() != 0:
        print("[ERROR] Packet sniffing requires root. Run with: sudo python3 nids.py")
        sys.exit(1)

    signal.signal(signal.SIGINT, _on_exit)
    signal.signal(signal.SIGTERM, _on_exit)

    iface_label = config.INTERFACE or scapy_conf.iface
    print(f"  Sniffing on interface: {iface_label}")
    print(f"  BPF filter:            {args.filter!r}")
    print(f"  Press Ctrl+C to stop.\n")

    sniff(
        iface=config.INTERFACE,
        filter=args.filter,
        prn=_packet_handler,
        store=False,           # don't accumulate packets in RAM
        count=args.count or 0,
        timeout=args.timeout,
    )

    _on_exit(None, None)


if __name__ == "__main__":
    main()
