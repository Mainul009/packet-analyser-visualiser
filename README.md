# Packet Analyser Visualiser

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![Status](https://img.shields.io/badge/Status-Active-brightgreen)

A modular Python tool for capturing, parsing, and visualising live network traffic in real time. Built to demonstrate practical network security and data analysis skills using industry-standard libraries.

---

## Key Features

- **Real-time packet capture** using Scapy — supports TCP, UDP, ICMP, DNS protocols
- **Protocol distribution histograms** — visualise which protocols dominate your network
- **Traffic-over-time graphs** — track and compare network activity across time windows
- **Anomaly detection** — flags suspicious spikes using a 2 standard-deviation statistical threshold
- **Top talkers analysis** — identify top source/destination IP addresses by volume
- **Modular architecture** — clean separation into `parser`, `analyser`, and `visualiser` modules
- **Full unit test suite** — tests covering parser and analyser components
- **Sample `.pcap` files** included for testing without live capture
- **Output folder** — saves all generated graphs as `.png` files automatically

---

## Real-Life Use Cases

| Use Case | Description |
|---|---|
| Network Monitoring | IT/network admins can detect unusual traffic spikes or intrusions on corporate networks |
| Cybersecurity Education | Students can learn TCP/IP protocol behaviour hands-on with real packet data |
| DDoS Detection | Anomaly detection flags sudden bandwidth surges typical of DDoS attacks |
| Incident Response | Security teams can load `.pcap` files post-incident to analyse attack patterns |
| Home Network Audit | Identify which devices or apps are consuming bandwidth unexpectedly |

---

## Project Structure

```
packet-analyser-visualiser/
├── analyser/
│   ├── __init__.py
│   ├── analyser.py       # Statistical analysis and anomaly detection
│   ├── parser.py         # Packet parsing and protocol extraction
│   └── visualiser.py     # Graph and chart generation
├── tests/
│   ├── test_analyser.py  # Unit tests for analyser module
│   └── test_parser.py    # Unit tests for parser module
├── samples/
│   └── README.md         # Instructions for sample .pcap files
├── output/               # Generated visualisation images
├── main.py               # Entry point
├── requirements.txt      # Python dependencies
├── setup.py              # Package setup
└── README.md
```

---

## Technologies Used

| Tool | Purpose |
|---|---|
| Python 3.8+ | Core language |
| Scapy | Live packet capture and parsing |
| Matplotlib | Chart and graph generation |
| Pandas | Data manipulation and analysis |
| NumPy | Statistical threshold calculations |
| unittest | Automated testing |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Mainul009/packet-analyser-visualiser.git
cd packet-analyser-visualiser

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

```bash
# Run with live packet capture (requires root/admin)
python main.py

# Run unit tests
python -m pytest tests/
```

Generated graphs are saved to the `output/` folder.

---

## Learning Goals

This project was built as part of my BSc Computing Systems studies to:
- Apply network security theory (TCP/IP, UDP, DNS) to real-world packet analysis
- Practice modular Python software design with clean separation of concerns
- Develop data visualisation skills for cybersecurity contexts
- Implement statistical anomaly detection from scratch
- Build a robust codebase with full unit testing

---

## Author

**Mainul Islam Tasin**  
BSc Computing Systems Student | Ulster University  
[LinkedIn](https://www.linkedin.com/in/mainul-islam-tasin-849072361/) | [GitHub](https://github.com/Mainul009)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
