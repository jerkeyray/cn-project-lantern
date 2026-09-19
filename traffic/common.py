"""Shared helpers for traffic generators.

Every attack script writes a ground-truth marker before and after it runs. That
marker is what the analysis joins alerts against, so it is the only thing that
makes a detection a *true* positive rather than merely an alert. Writing it
from the attack process rather than from the controller matters: the controller
must not be told what the truth is, or the experiment would be circular.
"""

import argparse
import random
import sys
import time

sys.path.insert(0, "/opt/lantern")

from lantern import config  # noqa: E402
from lantern.metrics import truth_log_path, write_truth_marker  # noqa: E402


def attack_parser(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--case", default="adhoc", help="experimental case label")
    parser.add_argument("--trial", type=int, default=0)
    parser.add_argument("--src", default=None, help="source IP (defaults to attacker)")
    parser.add_argument("--duration", type=float, default=20.0)
    parser.add_argument("--seed", type=int, default=None)
    return parser


def resolve_source(args):
    return args.src or config.HOST_TO_IP[config.ATTACKER]


class GroundTruth:
    """Context manager writing the start and end markers for one attack."""

    def __init__(self, attack_class, case, trial, src, targets=None, note=""):
        self.path = truth_log_path(case, trial)
        self.attack_class = attack_class
        self.src = src
        self.targets = list(targets or [])
        self.note = note
        self.t_start = None

    def __enter__(self):
        self.t_start = time.time()
        return self

    def add_target(self, target):
        if target not in self.targets:
            self.targets.append(target)

    def __exit__(self, exc_type, exc, tb):
        write_truth_marker(
            self.path,
            {
                "attack_class": self.attack_class,
                "src": self.src,
                "targets": self.targets,
                "t_start": self.t_start,
                "t_end": time.time(),
                "note": self.note,
                "aborted": exc_type is not None,
            },
        )
        return False


def seeded(seed):
    """Seed the RNG so a trial can be reproduced exactly."""
    if seed is not None:
        random.seed(seed)


def jitter(base, spread=0.3):
    """Randomised delay; constant-rate traffic is unrealistically easy to spot."""
    return max(base * (1.0 + random.uniform(-spread, spread)), 0.0)
