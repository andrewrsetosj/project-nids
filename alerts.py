"""
Alert logging: structured JSON lines to file + colored console output.
"""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

import config

# ANSI colors for terminal
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_RESET  = "\033[0m"
_BOLD   = "\033[1m"

SEVERITY_COLOR = {
    "CRITICAL": _RED + _BOLD,
    "HIGH":     _RED,
    "MEDIUM":   _YELLOW,
    "LOW":      _CYAN,
}

# File logger — one JSON object per line
_file_logger = logging.getLogger("nids.file")
_file_logger.setLevel(logging.DEBUG)
_file_logger.propagate = False

def _setup_file_logger():
    path = Path(config.LOG_FILE)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    _file_logger.addHandler(handler)

_setup_file_logger()

# Cooldown tracker: (src_ip, alert_type) -> last alert timestamp
_cooldowns: dict[tuple, float] = defaultdict(float)


def emit(
    alert_type: str,
    severity: str,
    src_ip: str,
    details: dict,
    dst_ip: str = "",
    dst_port: int = 0,
    proto: str = "",
):
    """
    Emit one alert. Respects cooldown to avoid log spam.
    Returns True if the alert was emitted, False if suppressed.
    """
    now = time.time()
    key = (src_ip, alert_type)
    if now - _cooldowns[key] < config.ALERT_COOLDOWN_SEC:
        return False
    _cooldowns[key] = now

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "alert_type": alert_type,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto": proto,
        "details": details,
    }

    # Write JSON line to file
    _file_logger.info(json.dumps(record))

    # Pretty-print to console
    color = SEVERITY_COLOR.get(severity, "")
    ts = datetime.now().strftime("%H:%M:%S")
    detail_str = "  ".join(f"{k}={v}" for k, v in details.items())
    print(
        f"{color}[{ts}] [{severity:8s}] {alert_type:30s}  "
        f"src={src_ip:<16s} "
        + (f"dst={dst_ip}:{dst_port} " if dst_ip else "")
        + (f"proto={proto} " if proto else "")
        + f"{detail_str}{_RESET}"
    )
    return True


def print_banner():
    print(f"{_BOLD}{_CYAN}")
    print("╔══════════════════════════════════════════════════╗")
    print("║        Project 1984 — Simple NIDS  v1.0         ║")
    print("║     Network Intrusion Detection System           ║")
    print("╚══════════════════════════════════════════════════╝")
    print(f"{_RESET}")
    print(f"  Alerts logged to: {config.LOG_FILE}")
    print(f"  Port-scan window: {config.PORT_SCAN_THRESHOLD} ports / {config.PORT_SCAN_WINDOW_SEC}s")
    print(f"  Blocklist size:   {len(config.MALICIOUS_IPS)} IPs")
    print()
