# tests/test_analyser.py - Unit tests for PacketAnalyser

import unittest
from analyser.analyser import PacketAnalyser


SAMPLE_PACKETS = [
    {"index": 0, "timestamp": 1000.0, "length": 64,  "protocol": "TCP",  "src_ip": "192.168.1.1", "dst_ip": "8.8.8.8",   "src_port": 12345, "dst_port": 80,  "flags": "S"},
    {"index": 1, "timestamp": 1000.1, "length": 128, "protocol": "UDP",  "src_ip": "192.168.1.2", "dst_ip": "8.8.4.4",   "src_port": 54321, "dst_port": 53,  "flags": None},
    {"index": 2, "timestamp": 1000.2, "length": 256, "protocol": "DNS",  "src_ip": "192.168.1.1", "dst_ip": "8.8.8.8",   "src_port": 1234,  "dst_port": 53,  "flags": None},
    {"index": 3, "timestamp": 1001.0, "length": 512, "protocol": "HTTP", "src_ip": "10.0.0.1",   "dst_ip": "93.184.216.34", "src_port": 8080, "dst_port": 80,  "flags": "A"},
    {"index": 4, "timestamp": 1001.5, "length": 64,  "protocol": "ICMP", "src_ip": "192.168.1.1", "dst_ip": "1.1.1.1",   "src_port": None,  "dst_port": None, "flags": None},
    {"index": 5, "timestamp": 1002.0, "length": 9000, "protocol": "TCP", "src_ip": "172.16.0.1",  "dst_ip": "8.8.8.8",   "src_port": 9999,  "dst_port": 443, "flags": "PA"},
]


class TestPacketAnalyser(unittest.TestCase):

    def setUp(self):
        self.analyser = PacketAnalyser(SAMPLE_PACKETS)
        self.stats = self.analyser.analyse(top_n=5)

    def test_total_packets(self):
        """Total packet count should match input."""
        self.assertEqual(self.stats["total_packets"], 6)

    def test_total_bytes(self):
        """Total bytes should be sum of all lengths."""
        expected = 64 + 128 + 256 + 512 + 64 + 9000
        self.assertEqual(self.stats["total_bytes"], expected)

    def test_avg_packet_size(self):
        """Average packet size should be computed correctly."""
        expected = round((64 + 128 + 256 + 512 + 64 + 9000) / 6, 2)
        self.assertEqual(self.stats["avg_packet_size"], expected)

    def test_protocol_counts_keys(self):
        """Protocol counts should include all used protocols."""
        protocols = self.stats["protocol_counts"]
        self.assertIn("TCP", protocols)
        self.assertIn("UDP", protocols)
        self.assertIn("DNS", protocols)

    def test_top_src_ips(self):
        """Top source IPs should be a dict."""
        self.assertIsInstance(self.stats["top_src_ips"], dict)
        self.assertGreater(len(self.stats["top_src_ips"]), 0)

    def test_top_dst_ips(self):
        """Top destination IPs should be a dict."""
        self.assertIsInstance(self.stats["top_dst_ips"], dict)

    def test_anomaly_detection(self):
        """Large packet (9000 bytes) should be flagged as anomaly."""
        self.assertGreater(self.stats["anomaly_count"], 0)
        anomalies = self.stats["anomalies"]
        anomaly_lengths = [a["length"] for a in anomalies]
        self.assertIn(9000, anomaly_lengths)

    def test_anomaly_threshold_positive(self):
        """Anomaly threshold should be a positive number."""
        self.assertGreater(self.stats["anomaly_threshold"], 0)

    def test_dataframe_in_stats(self):
        """Stats should include the dataframe for visualiser."""
        self.assertIn("dataframe", self.stats)

    def test_traffic_over_time(self):
        """Traffic over time should be a dict with positive counts."""
        tot = self.stats.get("traffic_over_time", {})
        self.assertIsInstance(tot, dict)


if __name__ == "__main__":
    unittest.main()
