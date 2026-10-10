"""Receiver-side counters for marked attack packets, sampled every second."""

import argparse
import json
import signal
import time
from scapy.all import AsyncSniffer, IP

running = True


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--ip", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    counts = {}

    def receive(packet):
        if IP in packet and packet[IP].dst == args.ip and packet[IP].tos == 0x10:
            src = packet[IP].src
            counts[src] = counts.get(src, 0) + 1

    def stop(*_):
        global running
        running = False

    signal.signal(signal.SIGTERM, stop)
    sniffer = AsyncSniffer(
        prn=receive, store=False, filter="ip and dst host " + args.ip
    )
    sniffer.start()
    with open(args.output, "x", buffering=1) as handle:
        while running:
            handle.write(
                json.dumps(
                    dict(
                        kind="receiver",
                        wall=time.time(),
                        dst=args.ip,
                        counts=dict(counts),
                    )
                )
                + "\n"
            )
            time.sleep(1)
    sniffer.stop()


if __name__ == "__main__":
    main()
