"""Lateral movement (experimental case C5) -- the scenario the project is about.

A compromised host works its way across the internal network: it contacts one
unfamiliar machine, then another, on ordinary service ports, a handful of
packets each.

**The design constraint that makes this a valid experiment:** every individual
connection here must be unremarkable, and the pacing must stay *below every
threshold the per-flow baseline uses*. If this script tripped the baseline's
port-scan rule, the comparison would no longer be testing the claim the project
makes -- that graph structure exposes behaviour per-flow analysis cannot see.
It would only be testing which detector has the lower threshold.

So the pacing is chosen against `lantern/config.py`, and `check_pacing()`
verifies it at runtime rather than trusting that it is still true after someone
retunes a threshold. A scenario that has drifted loud is a scenario bug, and it
should fail noisily rather than quietly hand the baseline a win.
"""

import random
import sys
import time

sys.path.insert(0, "/opt/lantern")

from scapy.all import IP, TCP, send  # noqa: E402

from lantern import config  # noqa: E402
from traffic.common import GroundTruth, attack_parser, jitter, resolve_source, seeded  # noqa: E402

# One plausible service port per target. Using a single port per host keeps the
# per-window port count far below the port-scan rule, while still being the
# kind of service an attacker would actually probe.
DEFAULT_PATH = [
    ("h1", 22),       # SSH to a workstation
    ("h2", 445),      # SMB file sharing
    ("h3", 3389),     # RDP
    ("h5", 22),       # SSH to the auth server
    ("server", 1433), # database
]

PACKETS_PER_TARGET = 3


def check_pacing(dwell, packets_per_target=PACKETS_PER_TARGET):
    """Verify this scenario cannot trip the baseline's thresholds.

    Returns a list of problems; empty means the scenario is still a fair test.
    """
    problems = []

    hosts_per_window = config.WINDOW_SECONDS / dwell
    if hosts_per_window > config.PORTSCAN_HOSTS:
        problems.append(
            "pacing contacts ~%.1f hosts per %.0fs window, which crosses the "
            "baseline's port-scan host threshold of %d -- increase --dwell"
            % (hosts_per_window, config.WINDOW_SECONDS, config.PORTSCAN_HOSTS)
        )

    ports_per_window = hosts_per_window   # one port per target
    if ports_per_window > config.PORTSCAN_PORTS:
        problems.append(
            "pacing touches ~%.1f ports per window, crossing the port threshold of %d"
            % (ports_per_window, config.PORTSCAN_PORTS)
        )

    auth_targets = [t for t in DEFAULT_PATH if t[1] in config.AUTH_PORTS]
    attempts_per_target = packets_per_target
    if attempts_per_target > config.BRUTEFORCE_ATTEMPTS and auth_targets:
        problems.append(
            "%d attempts per auth target crosses the brute-force threshold of %d"
            % (attempts_per_target, config.BRUTEFORCE_ATTEMPTS)
        )

    return problems


def run(src_ip, path, dwell, packets_per_target=PACKETS_PER_TARGET,
        truth=None, verbose=False):
    """Walk the path, pausing `dwell` seconds between targets."""
    visited = []
    for host_name, port in path:
        target_ip = config.HOST_TO_IP[host_name]
        if target_ip == src_ip:
            continue

        sport = random.randint(30000, 60000)
        for index in range(packets_per_target):
            # A SYN then a small amount of traffic: exactly what a legitimate
            # short-lived client connection looks like in isolation.
            flags = "S" if index == 0 else "A"
            payload = b"" if index == 0 else b"x" * random.randint(20, 120)
            send(
                IP(src=src_ip, dst=target_ip)
                / TCP(sport=sport, dport=port, flags=flags) / payload,
                verbose=verbose,
            )
            time.sleep(jitter(0.15))

        visited.append({"host": host_name, "ip": target_ip, "port": port})
        if truth is not None:
            truth.add_target(target_ip)
        time.sleep(jitter(dwell, spread=0.15))

    return visited


def main():
    parser = attack_parser(__doc__)
    parser.add_argument(
        "--dwell",
        type=float,
        default=4.0,
        help="seconds between targets; raise it to make the scenario quieter",
    )
    parser.add_argument("--packets", type=int, default=PACKETS_PER_TARGET)
    parser.add_argument(
        "--allow-loud",
        action="store_true",
        help="run even if the pacing would trip a baseline threshold",
    )
    args = parser.parse_args()
    seeded(args.seed)

    problems = check_pacing(args.dwell, args.packets)
    if problems:
        for problem in problems:
            print("lateral: PACING PROBLEM: %s" % problem, file=sys.stderr)
        if not args.allow_loud:
            print(
                "lateral: refusing to run -- a scenario the baseline can see on "
                "volume alone does not test the project's claim. Re-run with "
                "--allow-loud only if you intend that.",
                file=sys.stderr,
            )
            return 2

    src_ip = resolve_source(args)
    with GroundTruth(
        "lateral", args.case, args.trial, src_ip,
        note="sequential contact with %d internal hosts, %d packets each, %.1fs apart"
        % (len(DEFAULT_PATH), args.packets, args.dwell),
    ) as truth:
        visited = run(src_ip, DEFAULT_PATH, args.dwell, args.packets, truth=truth)

    print("lateral: %s reached %d hosts: %s"
          % (src_ip, len(visited), ", ".join(v["host"] for v in visited)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
