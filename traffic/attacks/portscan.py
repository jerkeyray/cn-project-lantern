"""Port scan (experimental case C2).

A loud, conventional TCP SYN sweep across many ports on one target. This is the
attack the per-flow baseline is *supposed* to catch -- it crosses an obvious
threshold by design. Including it matters: a comparison in which the graph
detector wins every case would suggest the baseline was built to lose.
"""

import random
import sys
import time

sys.path.insert(0, "/opt/lantern")

from scapy.all import IP, TCP, send  # noqa: E402

from lantern import config  # noqa: E402
from traffic.common import GroundTruth, attack_parser, jitter, resolve_source, seeded  # noqa: E402

DEFAULT_PORTS = list(range(20, 90)) + [110, 143, 443, 445, 993, 995, 1433,
                                       3306, 3389, 5432, 5900, 8080, 8443]


def run(src_ip, target_ip, ports, delay=0.05, verbose=False):
    scanned = 0
    for port in ports:
        send(
            IP(src=src_ip, dst=target_ip)
            / TCP(sport=random.randint(30000, 60000), dport=port, flags="S"),
            verbose=verbose,
        )
        scanned += 1
        time.sleep(jitter(delay))
    return scanned


def main():
    parser = attack_parser(__doc__)
    parser.add_argument("--target", default=None)
    parser.add_argument("--delay", type=float, default=0.05)
    args = parser.parse_args()
    seeded(args.seed)

    src_ip = resolve_source(args)
    target_ip = args.target or config.HOST_TO_IP[config.APP_SERVER]

    with GroundTruth("portscan", args.case, args.trial, src_ip,
                     targets=[target_ip],
                     note="TCP SYN sweep across %d ports" % len(DEFAULT_PORTS)):
        scanned = run(src_ip, target_ip, DEFAULT_PORTS, delay=args.delay)

    print("portscan: %s -> %s, %d ports" % (src_ip, target_ip, scanned))


if __name__ == "__main__":
    main()
