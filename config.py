"""
NIDS Configuration — thresholds, blocklists, and network settings.
"""

# --- Network context ---
# IPs considered "internal" (your LAN). Adjust to your subnet.
INTERNAL_SUBNETS = [
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
]

# Network interface to sniff on. None = Scapy picks the default.
INTERFACE = None

# --- Port scan detection ---
# Flag a source IP if it hits more than this many unique dst ports within the window.
PORT_SCAN_THRESHOLD = 15       # unique destination ports
PORT_SCAN_WINDOW_SEC = 10      # rolling time window (seconds)

# --- Connection rate limiting ---
# Flag if a single src IP opens more than N new TCP connections per window.
CONN_RATE_THRESHOLD = 50       # new SYN packets
CONN_RATE_WINDOW_SEC = 5

# --- ICMP flood detection ---
ICMP_FLOOD_THRESHOLD = 100     # ICMP packets per window
ICMP_FLOOD_WINDOW_SEC = 5

# --- Unusual outbound ports ---
# Alert on outbound TCP/UDP connections to these destination ports.
SUSPICIOUS_OUTBOUND_PORTS = {
    6667, 6668, 6669, 6697,    # IRC (often C2)
    4444, 5555, 1337, 31337,   # common reverse-shell ports
    9001, 9030,                 # Tor
    8545, 8546,                 # Ethereum RPC
    3389,                       # RDP outbound
    5900, 5901,                 # VNC outbound
}

# --- Known malicious IPs (blocklist) ---
# Seed list — extend with threat-intel feeds at runtime via --blocklist flag.
MALICIOUS_IPS = {
    # Example entries — replace/extend with real threat intel
    "198.51.100.1",    # TEST-NET (RFC 5737) — safe placeholder
    "203.0.113.99",    # TEST-NET-3 — safe placeholder
}

# --- DNS exfiltration heuristics ---
DNS_QUERY_THRESHOLD = 30       # queries per window from one host
DNS_QUERY_WINDOW_SEC = 10
LONG_SUBDOMAIN_LEN = 50        # flag subdomains longer than this (tunneling)

# --- Logging ---
LOG_FILE = "nids_alerts.log"
LOG_LEVEL = "INFO"

# --- Alert suppression ---
# Don't re-alert on the same (src, alert_type) pair within this many seconds.
ALERT_COOLDOWN_SEC = 30
