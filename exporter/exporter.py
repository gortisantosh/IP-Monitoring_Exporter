from scapy.all import sniff, IP
from prometheus_client import start_http_server, Counter, Gauge
import os

INTERFACE = os.getenv("INTERFACE", "eno3")
SUBNET_PREFIX = os.getenv("SUBNET_PREFIX", "10.0.40.")
PORT = int(os.getenv("EXPORTER_PORT", "9000"))
INTERVAL = int(os.getenv("INTERVAL", "5"))

# Counters (monotonic)
tx_bytes = Counter('network_tx_bytes_total', 'TX bytes', ['ip'])
rx_bytes = Counter('network_rx_bytes_total', 'RX bytes', ['ip'])
tx_packets = Counter('network_tx_packets_total', 'TX packets', ['ip'])
rx_packets = Counter('network_rx_packets_total', 'RX packets', ['ip'])

# Gauges (rates)
tx_rate = Gauge('network_tx_rate_kbps', 'TX rate KB/s', ['ip'])
rx_rate = Gauge('network_rx_rate_kbps', 'RX rate KB/s', ['ip'])

import threading
import time
from collections import defaultdict

stats = defaultdict(lambda: {"txb": 0, "rxb": 0})
lock = threading.Lock()

def process_packet(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    size = len(pkt)

    with lock:
        if src.startswith(SUBNET_PREFIX):
            stats[src]["txb"] += size
            tx_bytes.labels(ip=src).inc(size)
            tx_packets.labels(ip=src).inc(1)

        if dst.startswith(SUBNET_PREFIX):
            stats[dst]["rxb"] += size
            rx_bytes.labels(ip=dst).inc(size)
            rx_packets.labels(ip=dst).inc(1)

def calculate_rates():
    prev = {}

    while True:
        time.sleep(INTERVAL)

        with lock:
            for ip, val in stats.items():

                p = prev.get(ip, {"txb": 0, "rxb": 0})

                tx_rate.labels(ip=ip).set((val["txb"] - p["txb"]) / INTERVAL / 1024)
                rx_rate.labels(ip=ip).set((val["rxb"] - p["rxb"]) / INTERVAL / 1024)

                prev[ip] = val.copy()

if __name__ == "__main__":
    print(f"Starting exporter on port {PORT}...")

    start_http_server(PORT)

    threading.Thread(target=calculate_rates, daemon=True).start()

    sniff(iface=INTERFACE, prn=process_packet, store=0)
