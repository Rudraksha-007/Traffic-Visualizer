import argparse
from scapy.all import sniff, send
from scapy.layers.inet import IP, ICMP, TCP, UDP
from collections import defaultdict
import threading
import matplotlib.pyplot as plt
import time

data_volume = defaultdict(int)
lock = threading.Lock()

def process_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "OTHER"
        sport = None
        dport = None

        if packet.haslayer(TCP):
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto = "ICMP"

        key = (src, dst, sport, dport, proto)
        with lock:
            data_volume[key] += len(packet)

def capture_packets():
    sniff(prn=process_packet, store=False)

def generate_traffic():
    """Generates some dummy ICMP and UDP traffic."""
    while True:
        send(IP(dst="8.8.8.8")/ICMP(), verbose=False)
        time.sleep(2)
        send(IP(dst="8.8.8.8")/UDP(dport=53), verbose=False)
        time.sleep(2)

def visualize(tcp_only=False):
    plt.ion()
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))

    while True:
        with lock:
            if not data_volume:
                time.sleep(1)
                continue

            # Filter TCP packets if requested
            items = [(k, v) for k, v in data_volume.items() if (not tcp_only or k[4] == "TCP")]
            if not items:
                time.sleep(1)
                continue

            keys, values = zip(*items)
            labels = [f"{k[0]}->{k[1]}:{k[4]}" for k in keys]

            protocol_bytes = defaultdict(int)
            for k, v in items:
                protocol = k[4]
                protocol_bytes[protocol] += v

            pie_labels = list(protocol_bytes.keys())
            pie_sizes = list(protocol_bytes.values())
        ax1.clear()
        ax1.barh(labels, values)
        ax1.set_xlabel("Bytes transferred")
        ax1.set_title("Data Volume by Flow")

        ax2.clear()
        ax2.pie(pie_sizes, labels=pie_labels, autopct='%1.1f%%', startangle=90)
        ax2.axis('equal')
        ax2.set_title("Protocol Distribution")

        plt.tight_layout()
        plt.pause(1)
        plt.ylim(0, max(values) * 1.2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network traffic visualizer")
    parser.add_argument("--tcp-only", action="store_true", help="Visualize only TCP traffic")
    args = parser.parse_args()

    t_capture = threading.Thread(target=capture_packets, daemon=True)
    t_capture.start()

    t_generate = threading.Thread(target=generate_traffic, daemon=True)
    t_generate.start()

    visualize(tcp_only=args.tcp_only)
