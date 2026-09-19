"""Background workload: what "normal" looks like on this network.

This runs in *every* experimental case, including attack cases, and throughout
the warmup period. It has to: the graph detector scores each host against its
own established normal, so if normal traffic only ran in C1 there would be no
profile to depart from in C2-C7 and the detector would have nothing to say.

The pattern is deliberately narrow and client-server -- workstations talk to
the servers, not to each other. That is what makes a workstation suddenly
fanning out across its peers a genuine departure rather than business as usual.
"""

import random
import sys
import time

sys.path.insert(0, "/opt/lantern")

from scapy.all import IP, TCP, UDP, ICMP, send  # noqa: E402

from lantern import config  # noqa: E402
from traffic.common import attack_parser, jitter, seeded  # noqa: E402

HTTP_PORTS = [80, 443]
DNS_PORT = 53


def one_exchange(src_ip, dst_ip, verbose=False):
    """Send one short, ordinary-looking client-server exchange."""
    choice = random.random()

    if choice < 0.35:
        # HTTP/HTTPS request: SYN then a couple of data packets.
        port = random.choice(HTTP_PORTS)
        sport = random.randint(30000, 60000)
        send(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=port, flags="S"),
             verbose=verbose)
        for _ in range(random.randint(1, 3)):
            send(IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=port, flags="A")
                 / ("x" * random.randint(40, 400)), verbose=verbose)

    elif choice < 0.6:
        # DNS query.
        send(IP(src=src_ip, dst=dst_ip)
             / UDP(sport=random.randint(30000, 60000), dport=DNS_PORT)
             / ("q" * random.randint(20, 60)), verbose=verbose)

    else:
        # ICMP reachability check.
        send(IP(src=src_ip, dst=dst_ip) / ICMP(), verbose=verbose)


def run(src_ip, duration, rate=1.5, verbose=False, progress_every=10):
    """Generate client-server traffic from one host for `duration` seconds.

    Destinations are the servers only. Workstation-to-workstation traffic is
    excluded on purpose: including it would teach every host that talking to
    every other host is normal, which is precisely the behaviour the lateral
    -movement detector needs to be able to call abnormal.
    """
    servers = [config.HOST_TO_IP[config.APP_SERVER],
               config.HOST_TO_IP[config.AUTH_SERVER]]
    weights = [0.75, 0.25]   # the app server carries most of the load

    deadline = time.time() + duration
    started = time.time()
    sent = 0
    while time.time() < deadline:
        dst_ip = random.choices(servers, weights=weights, k=1)[0]
        one_exchange(src_ip, dst_ip, verbose=verbose)
        sent += 1
        if progress_every and sent % progress_every == 0:
            # A heartbeat, not decoration: without it a generator that stalls
            # looks identical in the results to a network that was simply quiet.
            print("%s t=%.1fs sent=%d" % (src_ip, time.time() - started, sent),
                  flush=True)
        time.sleep(jitter(1.0 / rate))
    return sent


def main():
    parser = attack_parser(__doc__)
    parser.add_argument("--rate", type=float, default=1.5,
                        help="exchanges per second")
    args = parser.parse_args()
    seeded(args.seed)

    src_ip = args.src or config.HOST_TO_IP["h1"]
    sent = run(src_ip, args.duration, rate=args.rate)
    print("normal: %s sent %d exchanges over %.0fs" % (src_ip, sent, args.duration))


if __name__ == "__main__":
    main()
