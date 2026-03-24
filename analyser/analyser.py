# analyser/analyser.py - Analyse parsed packet data

from collections import Counter
import pandas as pd


class PacketAnalyser:
    """
    Analyses a list of parsed packet dictionaries and computes statistics.
    """

    def __init__(self, packets: list):
        self.packets = packets
        self.df = pd.DataFrame(packets)

    def analyse(self, top_n: int = 10) -> dict:
        """
        Run full analysis and return a stats dictionary.
        """
        stats = {}

        # Basic counts
        stats["total_packets"] = len(self.packets)
        stats["total_bytes"] = self.df["length"].sum()
        stats["avg_packet_size"] = round(self.df["length"].mean(), 2)

        # Protocol distribution
        proto_counts = self.df["protocol"].value_counts()
        stats["protocol_counts"] = proto_counts.to_dict()

        # Top source IPs
        src_ips = self.df["src_ip"].dropna().value_counts().head(top_n)
        stats["top_src_ips"] = src_ips.to_dict()

        # Top destination IPs
        dst_ips = self.df["dst_ip"].dropna().value_counts().head(top_n)
        stats["top_dst_ips"] = dst_ips.to_dict()

        # Top destination ports
        dst_ports = self.df["dst_port"].dropna().value_counts().head(top_n)
        stats["top_dst_ports"] = dst_ports.to_dict()

        # Packet size distribution
        stats["packet_sizes"] = self.df["length"].tolist()

        # Traffic over time (packets per second)
        if "timestamp" in self.df.columns:
            self.df["time_bin"] = self.df["timestamp"].astype(int)
            traffic_over_time = self.df.groupby("time_bin").size()
            stats["traffic_over_time"] = traffic_over_time.to_dict()

        # Anomaly detection: unusually large packets
        threshold = self.df["length"].mean() + 2 * self.df["length"].std()
        anomalies = self.df[self.df["length"] > threshold]
        stats["anomaly_count"] = len(anomalies)
        stats["anomaly_threshold"] = round(threshold, 2)
        stats["anomalies"] = anomalies[["index", "src_ip", "dst_ip", "protocol", "length"]].to_dict("records")

        # Store dataframe for visualiser
        stats["dataframe"] = self.df

        return stats

    def print_summary(self, stats: dict):
        """
        Print a human-readable summary of the analysis.
        """
        print(f"\n{'='*50}")
        print(" Traffic Summary")
        print(f"{'='*50}")
        print(f"  Total Packets   : {stats['total_packets']}")
        print(f"  Total Bytes     : {stats['total_bytes']:,}")
        print(f"  Avg Packet Size : {stats['avg_packet_size']} bytes")

        print(f"\n  Protocol Distribution:")
        for proto, count in stats["protocol_counts"].items():
            pct = round(count / stats["total_packets"] * 100, 1)
            print(f"    {proto:<10} {count:>6} packets  ({pct}%)")

        print(f"\n  Top {len(stats['top_src_ips'])} Source IPs:")
        for ip, count in stats["top_src_ips"].items():
            print(f"    {ip:<20} {count} packets")

        print(f"\n  Top {len(stats['top_dst_ips'])} Destination IPs:")
        for ip, count in stats["top_dst_ips"].items():
            print(f"    {ip:<20} {count} packets")

        print(f"\n  Anomalies Detected: {stats['anomaly_count']} "
              f"(packets > {stats['anomaly_threshold']} bytes)")
        print(f"{'='*50}\n")
