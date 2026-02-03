#!/usr/bin/env python3

import argparse
import json
import math
import os
import time
import socket
from datetime import datetime
from collections import defaultdict, deque

from scapy.all import sniff, DNS, DNSQR, IP, IPv6
import dns.resolver

# =========================
# Configuration
# =========================

BASELINE_FILE = "baseline.json"
JSON_LOG_FILE = "dns_alerts.json"
TEXT_LOG_FILE = "dns_alerts.log"

ENTROPY_ALERT_THRESHOLD = 3.6
BASE64_RATIO_THRESHOLD = 0.85
LABEL_LENGTH_THRESHOLD = 15
QPM_THRESHOLD = 10
NXDOMAIN_THRESHOLD = 5
WINDOW_SECONDS = 60

BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

QTYPE_MAP = {
    1: "A", 28: "AAAA", 16: "TXT", 10: "NULL",
    15: "MX", 5: "CNAME", 2: "NS"
}

# =========================
# State
# =========================

query_times = defaultdict(lambda: deque(maxlen=1000))
nxdomain_counts = defaultdict(lambda: deque(maxlen=100))
ns_cache = {}
baseline = {"entropy_avg": 0.0, "label_length_avg": 0.0, "samples": 0}

# =========================
# Utilities
# =========================

def utc_now():
    return datetime.utcnow().isoformat() + "Z"

def shannon_entropy(s):
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    return round(-sum((v/len(s))*math.log2(v/len(s)) for v in freq.values()), 3)

def base64_ratio(s):
    return round(sum(1 for c in s if c in BASE64_CHARS) / max(len(s), 1), 3)

def ensure_files():
    for f in (JSON_LOG_FILE, TEXT_LOG_FILE):
        if not os.path.exists(f):
            open(f, "w").close()

def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return baseline
    try:
        with open(BASELINE_FILE) as f:
            return json.load(f)
    except Exception:
        return baseline

def save_baseline():
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

# =========================
# Authoritative NS Resolver (FIXED)
# =========================

def get_authoritative_ns(domain):
    if domain in ns_cache:
        return ns_cache[domain]

    result = {"ns": [], "ip": []}
    labels = domain.split(".")

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2

    # Walk up domain hierarchy
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        try:
            answers = resolver.resolve(candidate, "NS")
            for r in answers:
                ns = str(r.target).rstrip(".")
                if ns not in result["ns"]:
                    result["ns"].append(ns)
                    try:
                        ip = socket.gethostbyname(ns)
                        result["ip"].append(ip)
                    except Exception:
                        pass
            if result["ns"]:
                break
        except Exception:
            continue

    ns_cache[domain] = result
    return result

# =========================
# Logging
# =========================

def write_logs(event):
    with open(JSON_LOG_FILE, "a") as jf:
        jf.write(json.dumps(event) + "\n")
        jf.flush()
        os.fsync(jf.fileno())

    flat = {"timestamp": event["timestamp"], "event_type": event["event_type"], **event["data"]}
    line = " ".join(f"{k}={v}" for k, v in flat.items())

    with open(TEXT_LOG_FILE, "a") as tf:
        tf.write(line + "\n")
        tf.flush()
        os.fsync(tf.fileno())

# =========================
# DNS Processing
# =========================

def process_dns(pkt):
    if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
        return

    dns = pkt[DNS]
    q = dns.qd

    qname = q.qname.decode(errors="ignore").rstrip(".")
    labels = qname.split(".")
    longest_label = max(labels, key=len)

    entropy = shannon_entropy(longest_label)
    b64 = base64_ratio(longest_label)

    src_ip = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
    dest_ip = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst

    qtype = QTYPE_MAP.get(q.qtype, str(q.qtype))
    rcode = dns.rcode

    domain = ".".join(labels[-2:]) if len(labels) >= 2 else qname
    auth_ns = get_authoritative_ns(domain)

    now = time.time()
    query_times[src_ip].append(now)
    qpm = sum(1 for t in query_times[src_ip] if now - t <= WINDOW_SECONDS)

    event = {
        "timestamp": utc_now(),
        "event_type": "dns_query",
        "data": {
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "qname": qname,
            "domain": domain,
            "authoritative_ns": auth_ns,
            "entropy_label": longest_label,
            "max_entropy": entropy,
            "base64_ratio": b64,
            "max_label_length": len(longest_label),
            "qname_length": len(qname),
            "qtype": qtype,
            "qpm": qpm,
            "rcode": rcode,
            "process": None
        }
    }

    if ARGS.learn:
        baseline["samples"] += 1
        baseline["entropy_avg"] += (entropy - baseline["entropy_avg"]) / baseline["samples"]
        baseline["label_length_avg"] += (len(longest_label) - baseline["label_length_avg"]) / baseline["samples"]
        save_baseline()
        return

    if ARGS.log_all:
        write_logs(event)

    signals = sum([
        entropy >= ENTROPY_ALERT_THRESHOLD,
        b64 >= BASE64_RATIO_THRESHOLD,
        len(longest_label) >= LABEL_LENGTH_THRESHOLD,
        qpm >= QPM_THRESHOLD
    ])

    if signals >= 2:
        event["event_type"] = "dns_tunnel_suspected"
        write_logs(event)

    if rcode == 3:
        nxdomain_counts[src_ip].append(now)
        if sum(1 for t in nxdomain_counts[src_ip] if now - t <= WINDOW_SECONDS) >= NXDOMAIN_THRESHOLD:
            event["event_type"] = "dns_nxdomain_abuse"
            write_logs(event)

# =========================
# Main
# =========================

def main():
    global ARGS, baseline

    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True)
    parser.add_argument("--learn", action="store_true")
    parser.add_argument("--log-all", action="store_true")
    ARGS = parser.parse_args()

    ensure_files()
    baseline = load_baseline()

    print("[*] DNS tunneling detector running")
    print("[*] Interface:", ARGS.iface)
    print("[*] Learning mode:", ARGS.learn)
    print("[*] Log all queries:", ARGS.log_all)

    sniff(
        iface=ARGS.iface,
        filter="udp port 53 or tcp port 53",
        store=False,
        prn=process_dns
    )

if __name__ == "__main__":
    main()
  
