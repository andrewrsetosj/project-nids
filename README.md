# Project NIDS

A Network Intrusion Detection System (NIDS) built with Python and Scapy. Sniffs live network traffic and flags suspicious behavior in real time — a stripped-down Snort built from scratch. Originally made in Fall of 2025 for ITP 325 Ethical Hacking and Systems Defense as the final project.

## Features

| Detection Rule | Trigger |
|---|---|
| Port scan | >15 unique destination ports from one IP within 10 seconds |
| SYN flood | >50 SYN packets from one IP within 5 seconds |
| Blocklisted IP | Any traffic to/from known-bad IPs |
| Suspicious outbound | Internal host connects to IRC, C2, Tor, VNC, or reverse-shell ports |
| ICMP flood | >100 ICMP packets from one IP within 5 seconds |
| DNS exfiltration | High query rate or unusually long subdomains (tunneling indicator) |
| Lateral movement | Internal → internal SYN on admin ports (SSH, RDP, SMB, WinRM) |

All thresholds are configurable in `config.py`.

## Requirements

- Python 3.10+
- [Scapy](https://scapy.net/) 2.5+
- Root / Administrator privileges (required for raw packet capture)

```bash
pip install -r requirements.txt
```

> **macOS:** Scapy uses `/dev/bpf*` devices — no extra drivers needed.  
> **Linux:** Uses raw sockets — run with `sudo`.  
> **Windows:** Install [Npcap](https://npcap.com/) and run as Administrator.

## Quickstart

```bash
# Run with default settings (sniffs on the system default interface)
sudo python3 nids.py

# Specify an interface and BPF filter
sudo python3 nids.py --iface en0 --filter "tcp"

# Load additional malicious IPs from a threat-intel file (one IP per line)
sudo python3 nids.py --blocklist threat_intel.txt

# Stop automatically after 60 seconds
sudo python3 nids.py --timeout 60

# Capture only 500 packets then exit
sudo python3 nids.py --count 500
```

## Live Dashboard

Open a second terminal while `nids.py` is running:

```bash
python3 dashboard.py
```

The dashboard tails `nids_alerts.log` and displays:

- Severity breakdown (CRITICAL / HIGH / MEDIUM / LOW)
- Top alert types by frequency
- Top offending source IPs
- Rolling feed of the 20 most recent alerts

Refresh interval defaults to 2 seconds (`--refresh 5` to slow it down).

## CLI Reference

### nids.py

```
sudo python3 nids.py [OPTIONS]

Options:
  -i, --iface IFACE       Network interface to sniff (default: system default)
  -f, --filter FILTER     BPF filter string, e.g. "tcp" or "port 80" (default: ip)
  -b, --blocklist FILE    Plain-text file with one malicious IP per line
  -l, --log FILE          Alert log output path (default: nids_alerts.log)
  -c, --count N           Stop after N packets (default: run forever)
  -t, --timeout N         Stop after N seconds
```

### dashboard.py

```
python3 dashboard.py [OPTIONS]

Options:
  --log FILE        Alert log file to watch (default: nids_alerts.log)
  --refresh SECS    Refresh interval in seconds (default: 2.0)
  --top N           Number of top offenders to display (default: 10)
```

## File Structure

```
Project 1984/
├── nids.py          # Entry point — CLI, sniffer loop
├── rules.py         # All detection rules and rolling-window state
├── alerts.py        # Alert emission: colored console + JSON log
├── config.py        # Thresholds, blocklist seeds, network settings
├── dashboard.py     # Live tail dashboard
├── requirements.txt
└── nids_alerts.log  # Created at runtime
```

## Alert Log Format

Alerts are written as newline-delimited JSON (`nids_alerts.log`). Each line is one alert:

```json
{
  "timestamp": "2026-06-02T14:32:01.123456+00:00",
  "alert_type": "PORT_SCAN",
  "severity": "HIGH",
  "src_ip": "10.0.0.42",
  "dst_ip": "10.0.0.1",
  "dst_port": 22,
  "proto": "TCP",
  "details": {
    "unique_ports_in_window": 17,
    "window_sec": 10,
    "last_port": 8080
  }
}
```

This format is easy to pipe into `jq`, import into Splunk/Elastic, or process with any JSON tooling.

```bash
# Watch alerts live with jq
tail -f nids_alerts.log | jq .

# Show only CRITICAL alerts
cat nids_alerts.log | jq 'select(.severity == "CRITICAL")'

# Count alerts by type
cat nids_alerts.log | jq -r .alert_type | sort | uniq -c | sort -rn
```

## Configuration

Edit `config.py` to tune behavior without touching detection logic:

```python
# How many unique ports from one IP triggers a port-scan alert
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW_SEC = 10

# Add your own known-bad IPs
MALICIOUS_IPS = {
    "1.2.3.4",
    "5.6.7.8",
}

# Ports that should never receive outbound connections from internal hosts
SUSPICIOUS_OUTBOUND_PORTS = {4444, 5555, 6667, ...}
```

## Suppression / Alert Cooldown

The same `(source IP, alert type)` pair is suppressed for 30 seconds after firing to avoid log spam during sustained attacks. Adjust `ALERT_COOLDOWN_SEC` in `config.py`.

## Limitations

- Passive detection only — no active blocking or packet injection.
- Does not reassemble TCP streams; payload-level inspection (e.g. signatures inside HTTP) is not implemented.
- Encrypted traffic (TLS, QUIC) is detected by metadata only (IP, port, rate), not content.
- Designed for a single host/interface; distributed deployments would need a shared log backend.

## Legal Notice

Only run this tool on networks you own or have explicit written permission to monitor. Unauthorized packet capture may violate local laws (e.g. CFAA, ECPA, GDPR). This tool is intended for defensive security, education, and authorized penetration testing only.
