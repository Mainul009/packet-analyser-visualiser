# tests/test_parser.py - Unit tests for PacketParser

import unittest
from unittest.mock import patch, MagicMock
from analyser.parser import PacketParser


class TestPacketParser(unittest.TestCase):

    def setUp(self):
        self.parser = PacketParser("samples/test.pcap")

    def test_get_protocol_tcp(self):
        """Test TCP protocol detection."""
        pkt = MagicMock()
        pkt.haslayer.side_effect = lambda layer: layer.__name__ in ["TCP"]
        # DNS and HTTP should return False
        from scapy.layers.dns import DNS
        from scapy.layers.http import HTTP
        from scapy.layers.inet import TCP, UDP, ICMP, IP
        pkt.haslayer = lambda l: l in [TCP]
        pkt.__getitem__ = lambda self, l: MagicMock(sport=12345, dport=9999)
        result = self.parser._get_protocol.__func__(self.parser, pkt)
        self.assertIn(result, ["TCP", "HTTP", "HTTPS", "SSH", "FTP"])

    def test_get_protocol_returns_other(self):
        """Packets with no known layers should return OTHER."""
        pkt = MagicMock()
        pkt.haslayer = lambda l: False
        result = self.parser._get_protocol(pkt)
        self.assertEqual(result, "OTHER")

    def test_file_path_stored(self):
        """Filepath should be stored on init."""
        self.assertEqual(self.parser.filepath, "samples/test.pcap")

    def test_raw_packets_none_before_parse(self):
        """raw_packets should be None before parse() is called."""
        self.assertIsNone(self.parser.raw_packets)

    @patch("analyser.parser.rdpcap")
    def test_parse_returns_list(self, mock_rdpcap):
        """parse() should return a list of dicts."""
        mock_pkt = MagicMock()
        mock_pkt.time = 1000.0
        mock_pkt.__len__ = lambda self: 64
        mock_pkt.haslayer = lambda l: False
        mock_rdpcap.return_value = [mock_pkt]

        result = self.parser.parse()
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)
        self.assertIn("protocol", result[0])
        self.assertIn("src_ip", result[0])
        self.assertIn("length", result[0])


if __name__ == "__main__":
    unittest.main()
