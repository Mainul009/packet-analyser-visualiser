# Packet Analyser Visualiser

A Python tool that reads Wireshark `.pcap` files and visualises network traffic patterns, protocols, and anomalies.

## Features

- Parse `.pcap` files using **Scapy** and **pyshark**
- Visualise protocol distribution (TCP, UDP, DNS, HTTP, ICMP, etc.)
- Display top source/destination IP addresses
- Detect traffic anomalies and unusual patterns
- Generate charts and graphs using **Matplotlib** and **Pandas**
- Command-line interface for quick analysis

## Technologies Used

| Tool | Purpose |
|------|---------|
| Python 3 | Core language |
| Scapy | Packet parsing |
| pyshark | Wireshark/tshark wrapper |
| Pandas | Data analysis |
| Matplotlib | Visualisation |
| Wireshark | .pcap file generation |

## Project Structure

```
packet-analyser-visualiser/
├── analyser/
│   ├── __init__.py
│   ├── parser.py        # Parse .pcap files
│   ├── analyser.py      # Analyse traffic patterns
│   └── visualiser.py    # Generate charts
├── samples/             # Sample .pcap files
├── output/              # Output charts and reports
├── main.py              # Entry point
├── requirements.txt
└── README.md
```

## Getting Started

### Prerequisites

- Python 3.8+
- Wireshark / tshark installed
- pip

### Installation

```bash
git clone https://github.com/Mainul009/packet-analyser-visualiser.git
cd packet-analyser-visualiser
pip install -r requirements.txt
```

### Usage

```bash
python main.py --file samples/capture.pcap
```

## Learning Goals

This project is built to reinforce:
- Network protocols (TCP/IP, UDP, DNS)
- Packet analysis concepts from Wireshark labs
- Python scripting and data visualisation
- Cybersecurity awareness through anomaly detection

## Author

**Mainul Islam Tasin** — BSc Computing Systems, Ulster University

## License

MIT License
