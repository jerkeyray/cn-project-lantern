"""Run one experimental case, one or more trials.

    python3 experiments/run_case.py --case C5 --trials 3

Every trial is a complete, independent run: fresh controller, fresh topology,
fresh profiles. Nothing carries over between trials, so the repeated runs the
report calls for are genuinely independent rather than a single run measured
several times.
"""

import argparse
import os
import sys
import time

sys.path.insert(0, "/opt/lantern")

from mininet.log import setLogLevel  # noqa: E402

from lantern import config  # noqa: E402
from lantern.metrics import run_log_path, truth_log_path  # noqa: E402
from experiments.cases import CASES, FORCED_MITIGATOR  # noqa: E402
from experiments.runner import Controller, Workload, dump_flows  # noqa: E402
from topo.lantern_topo import build_network  # noqa: E402

# Warmup must cover the graph detector's profile warmup with room to spare;
# scoring cannot begin until every host has a profile.
WARMUP_SECONDS = config.PROFILE_WARMUP_WINDOWS * config.WINDOW_SECONDS + 10.0

# After the attacks stop, the run continues briefly so that the last window
# closes and is scored. Without this the final -- often the most interesting --
# window would be discarded at teardown.
DRAIN_SECONDS = config.WINDOW_SECONDS * 2 + 5.0


def check_connectivity(net):
    """Confirm the control loop forwards traffic, without polluting the graph.

    Mininet's pingAll would be the obvious check, and it is the wrong one here:
    it makes every host contact every other host, which teaches the graph
    detector that full-mesh communication is this network's normal. The very
    signal lateral movement depends on -- a workstation contacting peers it has
    never contacted -- would be trained away before the experiment began.

    So the check follows the same client-server shape as the normal workload:
    each workstation pings the application server, nothing else.
    """
    server = net.get(config.APP_SERVER)
    failures = []
    for name in config.WORKSTATIONS:
        host = net.get(name)
        result = host.cmd("ping -c 1 -W 2 %s" % server.IP())
        if " 0% packet loss" not in result:
            failures.append(name)
    if failures:
        raise RuntimeError(
            "no connectivity from %s to the application server; the control "
            "loop is not forwarding" % ", ".join(failures)
        )


def run_trial(case, trial, mitigator, warmup=None, seed=None, verbose=False,
              label=None):
    """Run one trial of `case`.

    `label` names the output files. It is separate from `case` so the same case
    can be run more than once under different mitigator settings -- the
    detection pass and the mitigation pass -- without the second run silently
    overwriting the first.
    """
    case_definition = CASES[case]
    mitigator = FORCED_MITIGATOR.get(case, mitigator)
    warmup = WARMUP_SECONDS if warmup is None else warmup
    label = label or case

    log_path = run_log_path(label, trial)
    truth_path = truth_log_path(label, trial)
    for path in (log_path, truth_path):
        if os.path.exists(path):
            os.remove(path)

    attack_seconds = case_definition.attack_duration
    total_workload = warmup + attack_seconds + DRAIN_SECONDS

    print("\n=== %s trial %d ===" % (label, trial))
    print("    purpose:   %s" % case_definition.purpose)
    print("    mitigator: %s" % mitigator)
    print("    warmup:    %.0fs   drain: %.0fs" % (warmup, DRAIN_SECONDS))

    controller = Controller(label, trial, mitigator, log_path)
    controller.start()

    net = build_network()
    workload = None
    try:
        net.start()

        # Pre-populate every host's ARP table.
        #
        # Without this, Linux drops packets while an ARP resolution is pending
        # -- and scapy sends one packet and moves on, so most generated traffic
        # never reached the wire at all. It also removes a large source of
        # broadcast noise: ARP floods to every port, which both inflates the
        # PacketIn count the overhead metric reports and would add an edge from
        # every host to every other host if it were modelled.
        net.staticArp()

        # Let the switches finish connecting and the learning switch settle
        # before any measurement begins.
        time.sleep(3)
        check_connectivity(net)

        workload = Workload(net, label, trial)
        workload.start_normal(
            duration=total_workload, rate=case_definition.normal_rate, seed=seed
        )

        print("    warming up profiles (%.0fs)..." % warmup)
        time.sleep(warmup)

        for module, extra_args in case_definition.attacks:
            print("    running %s" % os.path.basename(module))
            args = list(extra_args)
            if seed is not None:
                args += ["--seed", str(seed)]
            code = workload.run_attack(module, extra_args=args)
            if code != 0:
                print("    WARNING: %s exited with code %d" % (module, code))

        print("    draining (%.0fs)..." % DRAIN_SECONDS)
        time.sleep(DRAIN_SECONDS)

        flows_path = log_path.replace(".jsonl", ".flows.txt")
        dump_flows(net, flows_path)
        print("    flow tables written to %s" % flows_path)

    finally:
        if workload is not None:
            workload.stop()
        net.stop()
        controller.stop()

    print("    log: %s" % log_path)
    return log_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, choices=sorted(CASES))
    parser.add_argument("--trials", type=int, default=1,
                        help="run trials 1..N")
    parser.add_argument(
        "--trial",
        type=int,
        default=None,
        help="run exactly this one trial number instead of 1..N; used by the "
             "sweep driver, which runs each trial in its own container",
    )
    parser.add_argument(
        "--mitigator",
        default=config.DEFAULT_MITIGATOR,
        choices=list(config.MITIGATOR_MODES),
        help="which detector may install rules (C7 always forces 'none')",
    )
    parser.add_argument(
        "--warmup",
        type=float,
        default=None,
        help="override warmup seconds (shortening it below the profile warmup "
             "will disable graph scoring)",
    )
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument(
        "--label",
        default=None,
        help="name for this run's output files (defaults to the case name); "
             "lets the same case be run under several mitigator settings",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    setLogLevel("warning" if not args.verbose else "info")

    trials = [args.trial] if args.trial is not None else range(1, args.trials + 1)
    for trial in trials:
        seed = None if args.seed is None else args.seed + trial
        run_trial(
            args.case,
            trial,
            args.mitigator,
            warmup=args.warmup,
            seed=seed,
            verbose=args.verbose,
            label=args.label,
        )

    print("\nDone. Analyse with: python3 experiments/analyze.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
