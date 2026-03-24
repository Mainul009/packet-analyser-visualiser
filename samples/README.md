# samples/

Place your `.pcap` capture files in this folder to analyse them.

## How to get .pcap files

### Option 1 — Capture your own traffic with Wireshark
1. Open **Wireshark**
2. Select a network interface (e.g. `eth0`, `Wi-Fi`)
3. Click the blue shark fin to start capturing
4. Browse the web or run a ping to generate traffic
5. Stop capture and go to **File > Save As**
6. Save as `.pcap` format into this `samples/` folder

### Option 2 — Capture via tshark (Linux/Kali)
```bash
# Capture 100 packets on eth0 and save to samples/
sudo tshark -i eth0 -c 100 -w samples/capture.pcap
```

### Option 3 — Download sample .pcap files
Public `.pcap` samples are available from:
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [PacketLife.net Captures](https://packetlife.net/captures/)

## Running the analyser
```bash
python main.py --file samples/capture.pcap
```

## Available options
```bash
python main.py --file samples/capture.pcap --output output/ --top 10
python main.py --file samples/capture.pcap --no-plots
```
