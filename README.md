# Network-sniffer



#!/usr/bin/env python3
import argparse
from scapy.all import sniff, IP, TCP, UDP, Raw

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--iface", help="Interface to sniff on", default=None)
parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (0 = unlimited)", default=0)
parser.add_argument("-f", "--filter", help="BPF filter (eg. 'tcp')", default=None)
parser.add_argument("-o", "--output", help="Write JSON lines to file (optional)", default=None)
args = parser.parse_args()

import json
def preview_bytes(b):
    return b.hex() if b else ""

def proto_name(num):
    return {6: "TCP", 17: "UDP"}.get(num, str(num))

def process_packet(pkt):
    if IP not in pkt:
        return
    ip = pkt[IP]
    src = ip.src
    dst = ip.dst
    proto = ip.proto
    info = {
        "src": src,
        "dst": dst,
        "proto_num": proto,
        "proto": proto_name(proto),
        "payload_len": 0,
        "payload_preview": ""
    }
    if TCP in pkt or UDP in pkt:
        l4 = pkt[TCP] if TCP in pkt else pkt[UDP]
        info["sport"] = int(l4.sport)
        info["dport"] = int(l4.dport)
    payload = bytes(pkt[Raw].load) if Raw in pkt else b""
    info["payload_len"] = len(payload)
    info["payload_preview"] = preview_bytes(payload[:128])
    print(f'{info["src"]} -> {info["dst"]} {info["proto"]} sport={info.get("sport","-")} dport={info.get("dport","-")} payload_len={info["payload_len"]} payload_preview={info["payload_preview"]}')
    if args.output:
        with open(args.output, "a") as f:
            f.write(json.dumps(info) + "\n")

try:
    sniff(iface=args.iface, prn=process_packet, filter=args.filter, count=args.count, store=0)
except PermissionError:
    print("Permission denied: run with elevated privileges (sudo/Administrator).")
except KeyboardInterrupt:
    pass
