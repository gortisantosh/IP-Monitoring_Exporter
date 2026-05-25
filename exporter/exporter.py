from scapy.all import sniff, IP
from prometheus_client import start_http_server, Counter, Gauge
import os
import json
import threading
import time
from collections import defaultdict

# =========================
# Environment Variables
# =========================

INTERFACE = os.getenv("INTERFACE", "eno3")
SUBNET_PREFIX = os.getenv("SUBNET_PREFIX", "10.0.40.")
PORT = int(os.getenv("EXPORTER_PORT", "9090"))
INTERVAL = int(os.getenv("INTERVAL", "5"))

# =========================
# Load Engineer Mapping
# =========================

MAPPING_FILE = "ip-engineer-mapping.json"

try:
    with open(MAPPING_FILE, "r") as f:
        engineer_map = json.load(f)
    print(f"Loaded engineer mapping from {MAPPING_FILE}")
except Exception as e:
    print(f"Failed to load mapping file: {e}")
    engineer_map = {}

# =========================
# Prometheus Metrics
# =========================

# Counters
tx_bytes = Counter(
    'network_tx_bytes_total',
    'TX bytes',
    ['ip', 'engineer']
)

rx_bytes = Counter(
    'network_rx_bytes_total',
    'RX bytes',
    ['ip', 'engineer']
)

tx_packets = Counter(
    'network_tx_packets_total',
    'TX packets',
    ['ip', 'engineer']
)

rx_packets = Counter(
    'network_rx_packets_total',
    'RX packets',
    ['ip', 'engineer']
)

# Gauges
tx_rate = Gauge(
    'network_tx_rate_kbps',
    'TX rate KB/s',
    ['ip', 'engineer']
)

rx_rate = Gauge(
    'network_rx_rate_kbps',
    'RX rate KB/s',
    ['ip', 'engineer']
)

# =========================
# Runtime Stats
# =========================

stats = defaultdict(lambda: {"txb": 0, "rxb": 0})
lock = threading.Lock()

# =========================
# Helper Function
# =========================

def get_engineer_name(ip):
    name = engineer_map.get(ip, "").strip()

    if not name:
        return "unknown"

    return name

# =========================
# Packet Processing
# =========================

def process_packet(pkt):

    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    size = len(pkt)

    with lock:

        # TX
        if src.startswith(SUBNET_PREFIX):

            engineer = get_engineer_name(src)

            stats[src]["txb"] += size

            tx_bytes.labels(
                ip=src,
                engineer=engineer
            ).inc(size)

            tx_packets.labels(
                ip=src,
                engineer=engineer
            ).inc(1)

        # RX
        if dst.startswith(SUBNET_PREFIX):

            engineer = get_engineer_name(dst)

            stats[dst]["rxb"] += size

            rx_bytes.labels(
                ip=dst,
                engineer=engineer
            ).inc(size)

            rx_packets.labels(
                ip=dst,
                engineer=engineer
            ).inc(1)

# =========================
# Rate Calculation
# =========================

def calculate_rates():

    prev = {}

    while True:

        time.sleep(INTERVAL)

        with lock:

            for ip, val in stats.items():

                engineer = get_engineer_name(ip)

                previous = prev.get(ip, {
                    "txb": 0,
                    "rxb": 0
                })

                tx_kbps = (
                    (val["txb"] - previous["txb"])
                    / INTERVAL
                    / 1024
                )

                rx_kbps = (
                    (val["rxb"] - previous["rxb"])
                    / INTERVAL
                    / 1024
                )

                tx_rate.labels(
                    ip=ip,
                    engineer=engineer
                ).set(tx_kbps)

                rx_rate.labels(
                    ip=ip,
                    engineer=engineer
                ).set(rx_kbps)

                prev[ip] = val.copy()

# =========================
# Main
# =========================

if __name__ == "__main__":

    print(f"Starting exporter on port {PORT}...")
    print(f"Monitoring interface: {INTERFACE}")

    start_http_server(PORT)

    threading.Thread(
        target=calculate_rates,
        daemon=True
    ).start()

    sniff(
        iface=INTERFACE,
        prn=process_packet,
        store=0
    )
