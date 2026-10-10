"""Repeated SYN connection-attempt simulation on an authentication port.

This is a transport-level proxy. It does not send passwords, complete SSH
sessions, or establish that authentication actually failed.
"""

import random
import sys
import time


from scapy.all import IP, TCP  # noqa: E402

from traffic.common import send

from lantern import config  # noqa: E402
from traffic.common import (
    GroundTruth,
    attack_parser,
    jitter,
    resolve_source,
    seeded,
)  # noqa: E402


def run(src_ip, target_ip, port, attempts, delay=0.08, verbose=False):
    for _ in range(attempts):
        sport = random.randint(30000, 60000)
        # Send a SYN and abandon the handshake; no authentication is performed.
        send(
            IP(src=src_ip, dst=target_ip) / TCP(sport=sport, dport=port, flags="S"),
            verbose=verbose,
        )
        time.sleep(jitter(delay))
    return attempts


def main():
    parser = attack_parser(__doc__)
    parser.add_argument("--target", default=None)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--attempts", type=int, default=config.BRUTEFORCE_ATTEMPTS * 3)
    parser.add_argument("--delay", type=float, default=0.08)
    args = parser.parse_args()
    seeded(args.seed)

    src_ip = resolve_source(args)
    target_ip = args.target or config.HOST_TO_IP[config.AUTH_SERVER]

    with GroundTruth(
        "bruteforce",
        args.case,
        args.trial,
        src_ip,
        targets=[target_ip],
        note="%d SYN connection attempts" % args.attempts,
    ):
        attempts = run(src_ip, target_ip, args.port, args.attempts, delay=args.delay)

    print(
        "bruteforce: %s -> %s:%d, %d attempts"
        % (src_ip, target_ip, args.port, attempts)
    )


if __name__ == "__main__":
    main()
