"""
Detection rules — each rule inspects a parsed packet and calls alerts.emit()
when suspicious behavior is detected.

State is kept in module-level structures (rolling windows, counters).
"""

import time
import ipaddress
from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR

import alerts
import config

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_internal(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in ipaddress.ip_network(n) for n in config.INTERNAL_SUBNETS)
    except ValueError:
        return False


class _RollingWindow:
    """Tracks a set of values seen within a rolling time window."""

    def __init__(self, window_sec: float):
        self.window = window_sec
        # {key: [(timestamp, value), ...]}
        self._data: dict = defaultdict(list)

    def add(self, key, value):
        now = time.time()
        self._data[key].append((now, value))
        self._prune(key, now)

    def unique_count(self, key) -> int:
        self._prune(key, time.time())
        return len({v for _, v in self._data[key]})

    def total_count(self, key) -> int:
        self._prune(key, time.time())
        return len(self._data[key])

    def _prune(self, key, now):
        cutoff = now - self.window
        self._data[key] = [(t, v) for t, v in self._data[key] if t >= cutoff]


# ---------------------------------------------------------------------------
# Rule state
# ---------------------------------------------------------------------------

_port_scan_window   = _RollingWindow(config.PORT_SCAN_WINDOW_SEC)
_conn_rate_window   = _RollingWindow(config.CONN_RATE_WINDOW_SEC)
_icmp_flood_window  = _RollingWindow(config.ICMP_FLOOD_WINDOW_SEC)
_dns_query_window   = _RollingWindow(config.DNS_QUERY_WINDOW_SEC)

# Track which (src, dst_port) pairs we've already seen to detect SYN-only scans
_seen_syn: dict = defaultdict(set)


# ---------------------------------------------------------------------------
# Rule: Blocklisted IP
# ---------------------------------------------------------------------------

def rule_blocklist(pkt):
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    if src in config.MALICIOUS_IPS:
        alerts.emit(
            alert_type="BLOCKLISTED_IP_INBOUND",
            severity="CRITICAL",
            src_ip=src,
            dst_ip=dst,
            details={"reason": "source IP on blocklist"},
        )
    if dst in config.MALICIOUS_IPS:
        alerts.emit(
            alert_type="BLOCKLISTED_IP_OUTBOUND",
            severity="HIGH",
            src_ip=src,
            dst_ip=dst,
            details={"reason": "destination IP on blocklist"},
        )


# ---------------------------------------------------------------------------
# Rule: Port scan (SYN to many distinct ports from one source)
# ---------------------------------------------------------------------------

def rule_port_scan(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    tcp = pkt[TCP]
    # SYN only (flags == 0x02), not SYN-ACK
    if tcp.flags != 0x02:
        return
    src = pkt[IP].src
    dst_port = tcp.dport
    _port_scan_window.add(src, dst_port)
    unique = _port_scan_window.unique_count(src)
    if unique >= config.PORT_SCAN_THRESHOLD:
        alerts.emit(
            alert_type="PORT_SCAN",
            severity="HIGH",
            src_ip=src,
            dst_ip=pkt[IP].dst,
            proto="TCP",
            details={
                "unique_ports_in_window": unique,
                "window_sec": config.PORT_SCAN_WINDOW_SEC,
                "last_port": dst_port,
            },
        )


# ---------------------------------------------------------------------------
# Rule: TCP connection rate (SYN flood / rapid scanning)
# ---------------------------------------------------------------------------

def rule_syn_flood(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    tcp = pkt[TCP]
    if tcp.flags != 0x02:
        return
    src = pkt[IP].src
    _conn_rate_window.add(src, time.time())  # value = timestamp (all unique)
    count = _conn_rate_window.total_count(src)
    if count >= config.CONN_RATE_THRESHOLD:
        alerts.emit(
            alert_type="SYN_FLOOD",
            severity="CRITICAL",
            src_ip=src,
            dst_ip=pkt[IP].dst,
            proto="TCP",
            details={
                "syn_count_in_window": count,
                "window_sec": config.CONN_RATE_WINDOW_SEC,
            },
        )


# ---------------------------------------------------------------------------
# Rule: Unusual outbound connections
# ---------------------------------------------------------------------------

def rule_suspicious_outbound(pkt):
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    if not _is_internal(src):
        return  # only care about outbound from internal hosts
    if _is_internal(dst):
        return  # lateral movement is a different rule

    port = None
    proto = ""
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        if tcp.flags != 0x02:
            return  # only check new connections
        port = tcp.dport
        proto = "TCP"
    elif pkt.haslayer(UDP):
        port = pkt[UDP].dport
        proto = "UDP"

    if port and port in config.SUSPICIOUS_OUTBOUND_PORTS:
        alerts.emit(
            alert_type="SUSPICIOUS_OUTBOUND_PORT",
            severity="MEDIUM",
            src_ip=src,
            dst_ip=dst,
            dst_port=port,
            proto=proto,
            details={"note": "connection to known C2/backdoor port"},
        )


# ---------------------------------------------------------------------------
# Rule: ICMP flood
# ---------------------------------------------------------------------------

def rule_icmp_flood(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
        return
    src = pkt[IP].src
    _icmp_flood_window.add(src, time.time())
    count = _icmp_flood_window.total_count(src)
    if count >= config.ICMP_FLOOD_THRESHOLD:
        alerts.emit(
            alert_type="ICMP_FLOOD",
            severity="MEDIUM",
            src_ip=src,
            dst_ip=pkt[IP].dst,
            proto="ICMP",
            details={
                "icmp_count_in_window": count,
                "window_sec": config.ICMP_FLOOD_WINDOW_SEC,
            },
        )


# ---------------------------------------------------------------------------
# Rule: DNS exfiltration heuristics
# ---------------------------------------------------------------------------

def rule_dns_exfil(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
        return
    src = pkt[IP].src
    qname = pkt[DNSQR].qname
    if isinstance(qname, bytes):
        qname = qname.decode(errors="replace").rstrip(".")

    # High query rate
    _dns_query_window.add(src, qname)
    count = _dns_query_window.total_count(src)
    if count >= config.DNS_QUERY_THRESHOLD:
        alerts.emit(
            alert_type="DNS_HIGH_QUERY_RATE",
            severity="MEDIUM",
            src_ip=src,
            proto="DNS",
            details={
                "queries_in_window": count,
                "window_sec": config.DNS_QUERY_WINDOW_SEC,
            },
        )

    # Long subdomain (DNS tunneling indicator)
    subdomain = qname.split(".")[0] if "." in qname else qname
    if len(subdomain) > config.LONG_SUBDOMAIN_LEN:
        alerts.emit(
            alert_type="DNS_LONG_SUBDOMAIN",
            severity="HIGH",
            src_ip=src,
            proto="DNS",
            details={
                "subdomain_len": len(subdomain),
                "query": qname[:80],
                "note": "possible DNS tunneling",
            },
        )


# ---------------------------------------------------------------------------
# Rule: Lateral movement (internal → internal on admin ports)
# ---------------------------------------------------------------------------

_ADMIN_PORTS = {22, 23, 135, 139, 445, 3389, 5985, 5986}

def rule_lateral_movement(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    tcp = pkt[TCP]
    if tcp.flags != 0x02:
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    if not (_is_internal(src) and _is_internal(dst)):
        return
    if tcp.dport in _ADMIN_PORTS:
        alerts.emit(
            alert_type="LATERAL_MOVEMENT",
            severity="HIGH",
            src_ip=src,
            dst_ip=dst,
            dst_port=tcp.dport,
            proto="TCP",
            details={"note": "internal host connecting to admin port on another internal host"},
        )


# ---------------------------------------------------------------------------
# Master dispatcher
# ---------------------------------------------------------------------------

ALL_RULES = [
    rule_blocklist,
    rule_port_scan,
    rule_syn_flood,
    rule_suspicious_outbound,
    rule_icmp_flood,
    rule_dns_exfil,
    rule_lateral_movement,
]

def dispatch(pkt):
    """Run all rules against one packet. Exceptions in one rule don't kill others."""
    for rule in ALL_RULES:
        try:
            rule(pkt)
        except Exception as e:
            # Log rule errors quietly — don't crash the sniffer
            alerts._file_logger.warning(f'{{"rule_error": "{rule.__name__}", "error": "{e}"}}')
