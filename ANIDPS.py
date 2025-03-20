#!/usr/bin/env python3
"""
Advanced Network Intrusion Detection System (IDS/IPS)
------------------------------------------------------
This IDS/IPS captures raw packets on a specified network interface, decodes
the Ethernet and IP headers, and applies signature-based detection to identify
suspicious patterns. It logs alerts in real time using a rotating log file.

Usage (requires root privileges):
  sudo python advanced_ids.py --interface eth0
"""

import socket, struct, argparse, time, logging, sys
from logging.handlers import RotatingFileHandler

# Setup rotating logger
logger = logging.getLogger("AdvancedIDS")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler("advanced_ids.log", maxBytes=1000000, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Predefined malicious signatures (can be extended)
SIGNATURES = {
    b"malware": "Malware Signature Detected",
    b"exploit": "Exploit Attempt Detected"
}

def parse_ethernet_header(packet):
    eth_header = packet[:14]
    eth = struct.unpack("!6s6sH", eth_header)
    return socket.ntohs(eth[2])

def parse_ip_header(packet):
    ip_header = packet[:20]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    return src_ip, dst_ip

def detect_signature(payload):
    """
    Checks the payload for known malicious signatures.
    """
    for sig, desc in SIGNATURES.items():
        if sig in payload:
            return desc
    return None

def ids_loop(interface):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        s.bind((interface, 0))
    except Exception as e:
        logger.error(f"Socket error: {e}")
        sys.exit(1)
    print(f"Advanced IDS started on interface: {interface}")
    while True:
        packet, _ = s.recvfrom(65535)
        eth_proto = parse_ethernet_header(packet)
        if eth_proto == 8:  # IPv4
            src_ip, dst_ip = parse_ip_header(packet[14:34])
            payload = packet[14+20:]  # Skip Ethernet (14 bytes) + IP header (20 bytes)
            alert = detect_signature(payload)
            if alert:
                message = f"{time.ctime()} - {alert} from {src_ip} to {dst_ip}"
                print(message)
                logger.info(message)

def main_ids():
    parser = argparse.ArgumentParser(description="Advanced Network IDS/IPS")
    parser.add_argument("--interface", required=True, help="Interface to monitor (e.g., eth0)")
    args = parser.parse_args()
    ids_loop(args.interface)

if __name__ == "__main__":
    main_ids()
