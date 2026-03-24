# analyser/visualiser.py - Generate charts from packet analysis stats

import os
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import pandas as pd


class PacketVisualiser:
    """
    Generates and saves visualisation charts from packet stats.
    """

    def __init__(self, stats: dict, output_dir: str = "output"):
        self.stats = stats
        self.output_dir = output_dir
        self.df = stats.get("dataframe", pd.DataFrame())
        os.makedirs(output_dir, exist_ok=True)

    def plot_all(self):
        """Run all plots."""
        self.plot_protocol_distribution()
        self.plot_top_src_ips()
        self.plot_top_dst_ips()
        self.plot_packet_size_histogram()
        self.plot_traffic_over_time()
        self.plot_anomalies()
        print(f"      All charts saved to '{self.output_dir}/'")

    def plot_protocol_distribution(self):
        """Pie chart of protocol distribution."""
        protocols = self.stats.get("protocol_counts", {})
        if not protocols:
            return

        fig, ax = plt.subplots(figsize=(7, 7))
        ax.pie(
            protocols.values(),
            labels=protocols.keys(),
            autopct="%1.1f%%",
            startangle=140,
            colors=plt.cm.Set3.colors
        )
        ax.set_title("Protocol Distribution", fontsize=14, fontweight="bold")
        self._save(fig, "protocol_distribution.png")

    def plot_top_src_ips(self):
        """Horizontal bar chart of top source IPs."""
        src_ips = self.stats.get("top_src_ips", {})
        if not src_ips:
            return

        fig, ax = plt.subplots(figsize=(10, 5))
        ax.barh(list(src_ips.keys()), list(src_ips.values()), color="steelblue")
        ax.set_xlabel("Packet Count")
        ax.set_title("Top Source IP Addresses", fontsize=14, fontweight="bold")
        ax.invert_yaxis()
        plt.tight_layout()
        self._save(fig, "top_src_ips.png")

    def plot_top_dst_ips(self):
        """Horizontal bar chart of top destination IPs."""
        dst_ips = self.stats.get("top_dst_ips", {})
        if not dst_ips:
            return

        fig, ax = plt.subplots(figsize=(10, 5))
        ax.barh(list(dst_ips.keys()), list(dst_ips.values()), color="coral")
        ax.set_xlabel("Packet Count")
        ax.set_title("Top Destination IP Addresses", fontsize=14, fontweight="bold")
        ax.invert_yaxis()
        plt.tight_layout()
        self._save(fig, "top_dst_ips.png")

    def plot_packet_size_histogram(self):
        """Histogram of packet sizes with anomaly threshold line."""
        sizes = self.stats.get("packet_sizes", [])
        threshold = self.stats.get("anomaly_threshold", None)
        if not sizes:
            return

        fig, ax = plt.subplots(figsize=(10, 5))
        ax.hist(sizes, bins=40, color="mediumpurple", edgecolor="white", alpha=0.8)
        if threshold:
            ax.axvline(threshold, color="red", linestyle="--", linewidth=1.5,
                       label=f"Anomaly Threshold ({threshold} bytes)")
            ax.legend()
        ax.set_xlabel("Packet Size (bytes)")
        ax.set_ylabel("Frequency")
        ax.set_title("Packet Size Distribution", fontsize=14, fontweight="bold")
        plt.tight_layout()
        self._save(fig, "packet_size_histogram.png")

    def plot_traffic_over_time(self):
        """Line chart of packets per second over time."""
        traffic = self.stats.get("traffic_over_time", {})
        if not traffic:
            return

        times = list(traffic.keys())
        counts = list(traffic.values())

        fig, ax = plt.subplots(figsize=(12, 4))
        ax.plot(times, counts, color="darkorange", linewidth=1.2)
        ax.fill_between(times, counts, alpha=0.2, color="orange")
        ax.set_xlabel("Time (Unix Timestamp)")
        ax.set_ylabel("Packets per Second")
        ax.set_title("Network Traffic Over Time", fontsize=14, fontweight="bold")
        plt.tight_layout()
        self._save(fig, "traffic_over_time.png")

    def plot_anomalies(self):
        """Scatter plot highlighting anomalous packets by size."""
        if self.df.empty:
            return

        threshold = self.stats.get("anomaly_threshold", None)
        fig, ax = plt.subplots(figsize=(12, 4))

        normal = self.df[self.df["length"] <= threshold] if threshold else self.df
        anomalies = self.df[self.df["length"] > threshold] if threshold else pd.DataFrame()

        ax.scatter(normal.index, normal["length"], s=5, color="steelblue", alpha=0.5, label="Normal")
        if not anomalies.empty:
            ax.scatter(anomalies.index, anomalies["length"], s=20, color="red", alpha=0.9, label="Anomaly")
        if threshold:
            ax.axhline(threshold, color="red", linestyle="--", linewidth=1, label=f"Threshold ({threshold}B)")

        ax.set_xlabel("Packet Index")
        ax.set_ylabel("Packet Size (bytes)")
        ax.set_title("Anomaly Detection — Packet Sizes", fontsize=14, fontweight="bold")
        ax.legend()
        plt.tight_layout()
        self._save(fig, "anomaly_detection.png")

    def _save(self, fig, filename: str):
        """Save and close a figure."""
        filepath = os.path.join(self.output_dir, filename)
        fig.savefig(filepath, dpi=150, bbox_inches="tight")
        plt.close(fig)
        print(f"      Saved: {filename}")
