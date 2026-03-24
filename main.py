#!/usr/bin/env python3
"""
main.py - Entry point for Packet Analyser Visualiser
Usage: python main.py --file samples/capture.pcap
"""

import argparse
import os
import sys
from analyser.parser import PacketParser
from analyser.analyser import PacketAnalyser
from analyser.visualiser import PacketVisualiser


def parse_args():
    parser = argparse.ArgumentParser(
        description="Packet Analyser Visualiser - Analyse and visualise .pcap files"
    )
    parser.add_argument(
        "--file", "-f",
        required=True,
        help="Path to the .pcap file to analyse"
    )
    parser.add_argument(
        "--output", "-o",
        default="output",
        help="Output directory for charts (default: output/)"
    )
    parser.add_argument(
        "--top", "-t",
        type=int,
        default=10,
        help="Number of top IPs/protocols to display (default: 10)"
    )
    parser.add_argument(
        "--no-plots",
        action="store_true",
        help="Skip plot generation, show stats only"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Validate file
    if not os.path.exists(args.file):
        print(f"[ERROR] File not found: {args.file}")
        sys.exit(1)

    if not args.file.endswith(".pcap"):
        print("[WARNING] File does not have .pcap extension. Proceeding anyway...")

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    print(f"\n{'='*50}")
    print(" Packet Analyser Visualiser")
    print(f"{'='*50}")
    print(f" File   : {args.file}")
    print(f" Output : {args.output}/")
    print(f"{'='*50}\n")

    # Step 1: Parse packets
    print("[1/3] Parsing packets...")
    parser = PacketParser(args.file)
    packets = parser.parse()
    print(f"      Loaded {len(packets)} packets.\n")

    # Step 2: Analyse
    print("[2/3] Analysing traffic...")
    analyser = PacketAnalyser(packets)
    stats = analyser.analyse(top_n=args.top)
    analyser.print_summary(stats)

    # Step 3: Visualise
    if not args.no_plots:
        print("\n[3/3] Generating visualisations...")
        visualiser = PacketVisualiser(stats, output_dir=args.output)
        visualiser.plot_all()
        print(f"      Charts saved to: {args.output}/\n")
    else:
        print("\n[3/3] Skipping plots (--no-plots flag set).")

    print("[DONE] Analysis complete.\n")


if __name__ == "__main__":
    main()
