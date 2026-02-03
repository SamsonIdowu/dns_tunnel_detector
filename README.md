# dns_tunnel_detector
This program detects DNS tunnelling

## Overview
This project is a DNS tunneling detection tool written in Python. It passively monitors DNS traffic on a network interface, learns what normal DNS behavior looks like, and then detects suspicious DNS queries commonly associated with DNS tunneling attacks.

Instead of sending logs directly to a SIEM, the program writes structured JSON logs to a local file (`dns_alerts.json`) which can later be ingested by security platforms or analyzed manually.

The detector focuses on statistical and behavioral indicators, as opposed to signatures, making it effective against custom and unknown DNS tunneling tools.

### How the Detector Works

The program operates in three logical layers:

#### 1. DNS Packet Capture
Uses scapy to sniff DNS packets (UDP/53)
Extracts:
- Source IP
- Query name (qname)
- Query type (A, AAAA, TXT, etc.)

#### 2. Feature Extraction (Per Query)
For each DNS query, the detector calculates:
- Shannon entropy of each DNS label
- Longest label length
- Base64 character ratio
- Total query length
- Queries per minute (QPM) per source IP
These values are strong indicators of tunneling behavior.

#### 3. Detection Logic
A DNS query is flagged when multiple indicators align, for example:
- High entropy label
- High base64-like character ratio
- Unusually long subdomain
- Increasing query frequency
Each detection generates structured JSON logs with full context.

## Working Modes
The detector works in two modes:
#### Learning Mode
- Builds a baseline of normal DNS behavior
- Learns typical entropy and label lengths
- Stored locally (no external dependencies)

#### Detection Mode
- Compares new DNS queries against learned behavior
- Triggers alerts when thresholds are exceeded

## Installation
### Requirements
- Linux (tested on Ubuntu)
- Python 3.9+
- Root privileges (required for packet capture)

### Dependencies
> _Install the following dependencies_
```
sudo apt update
sudo apt install -y python3-pip tcpdump
pip3 install scapy psutil
```

## Running the Program
### learning mode (Used to create a baseline for your normal DNS behaviour)
```
sudo python3 dns_tunnel_detector.py --iface <INTERFACE> --learn
```

### Basic run (alerts only when there is a suspicious DNS query)
```
sudo python3 dns_tunnel_detector.py --iface <INTERFACE>
```

### Log all DNS queries (includes non-suspicious DNS queries)
```
sudo python3 dns_tunnel_detector.py --iface <INTERFACE> --log-all
```

### Specify a custom log file
```
sudo python3 dns_tunnel_detector.py --iface eth0 --log-file ./dns_alerts.json
```

### Output Files

| File              | Purpose                    |
| ----------------- | -------------------------- |
| `dns_alerts.json` | Structured SIEM-ready JSON |
| `dns_alerts.log`  | Human-readable analyst log |
| `baseline.json`   | Learned DNS behavior       |

Logs are written line-by-line in JSON and log formats, making them easy to ingest into other tools.

#### Log Format:
Each log entry is written in human-readable text.
**For example:**
```
timestamp=2026-02-03T10:30:12Z event_type=dns_query_seen src_ip=192.168.186.129 dst_ip=8.8.8.8 qname=google.com entropy_label=google max_entropy=1.918 base64_ratio=1.0 max_label_length=6 qname_length=10 qtype=A qpm=2 process=None
```

#### JSON Format:
Each log entry is a single JSON object per line.
**For example:**
```
{
  "timestamp": "2026-02-03T10:30:12Z",
  "event_type": "dns_query_seen",
  "data": {
    "src_ip": "192.168.186.129",
    "dst_ip": "8.8.8.8",
    "qname": "google.com",
    "entropy_label": "google",
    "max_entropy": 1.918,
    "base64_ratio": 1.0,
    "max_label_length": 6,
    "qname_length": 10,
    "qtype": "A",
    "qpm": 2,
    "process": null
  }
}

```


## Log Fields Explained

### Top-Level Fields
| Field        | Description                               |
| ------------ | ----------------------------------------- |
| `timestamp`  | UTC timestamp when the event was recorded |
| `event_type` | Type of detection or observation          |
| `data`       | Detailed event metadata                   |


### `event_type` Values
| Event Type                      | Meaning                                 |
| ------------------------------- | --------------------------------------- |
| `dns_query_seen`                | A DNS query was observed                |
| `dns_tunnel_high_entropy_label` | High-entropy subdomain detected         |
| `dns_tunnel_entropy_base64`     | High entropy + base64-like encoding     |
| `dns_tunnel_suspected`          | Multiple tunneling indicators triggered |

### `data` Fields
| Field              | Description                                    |
| ------------------ | ---------------------------------------------- |
| `src_ip`           | Source IP that generated the DNS query         |
| `qname`            | Full DNS query name                            |
| `entropy_label`    | DNS label with the highest entropy             |
| `max_entropy`      | Shannon entropy score of that label            |
| `base64_ratio`     | Percentage of characters matching base64 set   |
| `max_label_length` | Length of the longest DNS label                |
| `qname_length`     | Total length of the DNS query                  |
| `qtype`            | DNS record type (`A`, `AAAA`, `TXT`, etc.)     |
| `qpm`              | Queries per minute from this source IP         |
| `process`          | Process that initiated the query (best-effort) |

## About Entropy
Entropy measures randomness.
- Normal DNS names have low entropy. For example: `google`, `mail`, `cdn`, etc
- Encoded data has high entropy. For example: `fmhu1aemqwp0hrawaynh65rwu`

Typical values include:
- Normal DNS: `1.5 – 2.8`
- Suspicious: `3.3 – 4.5`
- Strong tunneling signal: `≥ 4.0`


