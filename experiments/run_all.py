"""Plan the experiment sweep. Execution lives in scripts/run_sweep.sh.

Two passes, deliberately separated:

**Detection pass** -- every case C1-C7 with mitigation disabled. Both detectors
score the same traffic and neither is allowed to install a rule. This is the
pass the coverage comparison is built from, because a detector that blocks the
attacker also deletes the evidence the other detector needed; with mitigation on,
the comparison would measure which detector is faster to act, not which sees more.

**Mitigation pass** -- the attack cases again, once per actuating detector, with
that detector allowed to install rules. This is the pass the timing figures come
from: decision latency, rule-installation latency and time to containment only
exist when something is actually actuating.

Runs from the two passes are labelled differently on disk (C2 versus
C2-mit-graph), so the analysis keeps them apart.

This module only *plans*. It used to run the sweep too, looping over every trial
inside a single container, and that turned out to corrupt results rather than
fail: after roughly twenty consecutive Mininet start/stops the container's
networking degrades, traffic generators are starved, and runs stop producing
enough windows for the graph detector to finish profiling. Those runs then look
like detection failures in the output. Execution therefore moved to
scripts/run_sweep.sh, which gives every run its own container -- and the
in-container loop was deleted rather than left behind with a warning, because a
footgun that silently produces plausible-looking wrong numbers is worse than no
convenience at all.

Usage:
    python3 experiments/run_all.py --dry-run      # human-readable plan
    python3 experiments/run_all.py --emit-plan    # machine-readable, for the driver
"""

import argparse
import sys

sys.path.insert(0, "/opt/lantern")

from experiments.cases import CASES, FORCED_MITIGATOR, ORDER  # noqa: E402
from experiments.run_case import DRAIN_SECONDS, WARMUP_SECONDS  # noqa: E402

# Cases that contain an attack worth actuating on.
MITIGATION_CASES = ["C2", "C3", "C4", "C5"]
ACTUATORS = ["baseline", "graph"]


def estimate_seconds(case, warmup):
    return warmup + CASES[case].attack_duration + DRAIN_SECONDS + 20.0


def plan(detection_trials, mitigation_trials, warmup, cases=None):
    """Build the full list of runs before executing any, so the cost is visible."""
    cases = cases or ORDER
    runs = []
    for case in cases:
        for trial in range(1, detection_trials + 1):
            runs.append({"case": case, "label": case, "trial": trial,
                         "mitigator": "none", "pass": "detection"})

    for case in cases:
        if case not in MITIGATION_CASES or case in FORCED_MITIGATOR:
            continue
        for actuator in ACTUATORS:
            for trial in range(1, mitigation_trials + 1):
                runs.append(
                    {
                        "case": case,
                        "label": "%s-mit-%s" % (case, actuator),
                        "trial": trial,
                        "mitigator": actuator,
                        "pass": "mitigation",
                    }
                )
    return runs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=3,
                        help="trials per case in the detection pass")
    parser.add_argument("--mitigation-trials", type=int, default=1,
                        help="trials per actuating detector in the mitigation pass")
    parser.add_argument("--warmup", type=float, default=None)
    parser.add_argument("--seed", type=int, default=1000)
    parser.add_argument("--cases", nargs="*", default=None, choices=sorted(CASES))
    parser.add_argument("--skip-mitigation", action="store_true")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the plan and the time estimate, then exit")
    parser.add_argument(
        "--emit-plan",
        action="store_true",
        help="print the plan as 'case|label|trial|mitigator' lines and exit, "
             "for a driver that runs each entry in its own container",
    )
    args = parser.parse_args()

    warmup = WARMUP_SECONDS if args.warmup is None else args.warmup
    runs = plan(args.trials, 0 if args.skip_mitigation else args.mitigation_trials,
                warmup, args.cases)

    if args.emit_plan:
        for run in runs:
            print("%s|%s|%d|%s" % (run["case"], run["label"], run["trial"],
                                   run["mitigator"]))
        return 0

    total = sum(estimate_seconds(run["case"], warmup) for run in runs)
    print("planned runs: %d   estimated wall time: %.0f min"
          % (len(runs), total / 60.0))
    for run in runs:
        print("  %-18s trial %d   mitigator=%-8s (%s pass)"
              % (run["label"], run["trial"], run["mitigator"], run["pass"]))

    if args.dry_run:
        return 0

    print(
        "\nThis module does not execute the sweep. Run it with:\n"
        "    make run-all TRIALS=%d\n"
        "or directly:\n"
        "    scripts/run_sweep.sh --trials %d\n"
        "which gives each run its own container." % (args.trials, args.trials)
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
