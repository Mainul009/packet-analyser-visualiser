# analyser/parser.py - Parse .pcap files using Scapy

import os
from scapy.all import rdpcap, Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP


class PacketParser:
    """
    Parses a .pcap file and extracts structured packet data.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._raw_packets = None

    def parse(self) -> list:
        """
        Read the pcap file and return a list of parsed packet dicts.
        """
        print(f"      Reading: {self.filepath}")
        self._raw_packets = rdpcap(self.filepath)
        parsed = []

        for i, pkt in enumerate(self._raw_packets):
            record = {
                "index": i,
                "timestamp": float(pkt.time),
                "length": len(pkt),
                "protocol": self._get_protocol(pkt),
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "flags": None,
            }

            if pkt.haslayer(IP):
                record["src_ip"] = pkt[IP].src
                record["dst_ip"] = pkt[IP].dst

            if pkt.haslayer(TCP):
                record["src_port"] = pkt[TCP].sport
                record["dst_port"] = pkt[TCP].dport
                record["flags"] = str(pkt[TCP].flags)

            elif pkt.haslayer(UDP):
                record["src_port"] = pkt[UDP].sport
                record["dst_port"] = pkt[UDP].dport

            parsed.append(record)

        return parsed

    def _get_protocol(self, pkt: Packet) -> str:
        """
        Determine the highest-level protocol in a packet.
        """
        if pkt.haslayer(DNS):
            return "DNS"
        elif pkt.haslayer(HTTP):
            return "HTTP"
        elif pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if 80 in (sport, dport):
                return "HTTP"
            elif 443 in (sport, dport):
                return "HTTPS"
            elif 22 in (sport, dport):
                return "SSH"
            elif 21 in (sport, dport):
                return "FTP"
            return "TCP"
        elif pkt.haslayer(UDP):
            return "UDP"
        elif pkt.haslayer(ICMP):
            return "ICMP"
        elif pkt.haslayer(IP):
            return "IP"
        return "OTHER"

    @property
    def raw_packets(self):
        return self._raw_packets
