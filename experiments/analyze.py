"""Turn raw run logs into the tables and figures the Review-2 report needs.

Nothing is aggregated inside the controller; every number here is derived from
the JSONL event logs and the ground-truth markers the attack scripts wrote. That
separation means a metric can be redefined and recomputed without re-running a
single experiment, and it keeps measurement off the detection path.

Two scoring conventions are reported side by side, and the difference between
them matters:

* **class-agnostic** -- did the detector flag the attacking host while the
  attack was running? This is the fair cross-detector comparison. The graph
  detector only ever emits "lateral movement"; it makes no claim to name which
  attack it is looking at, so scoring it on class accuracy would penalise it
  for something it never claimed to do.
* **class-exact** -- did it also get the attack class right? The per-flow
  baseline does claim this, so it is reported too.

The headline coverage table uses class-agnostic scoring. Reporting only the
convention that flatters the proposed method would not be a comparison.
"""

import argparse
import csv
import glob
import json
import os
import statistics
import sys
from collections import defaultdict

sys.path.insert(0, "/opt/lantern")

from lantern import config  # noqa: E402
from lantern.alerts import DETECTOR_BASELINE, DETECTOR_GRAPH  # noqa: E402

DETECTORS = (DETECTOR_BASELINE, DETECTOR_GRAPH)

# An alert is credited to an attack if it names the attacking host and lands
# inside the attack's interval, extended by this grace period. The grace exists
# because a detector scores at window boundaries: an attack ending mid-window
# is legitimately reported when that window closes, up to one window later.
DETECTION_GRACE_SECONDS = config.WINDOW_SECONDS * 1.5


# ----------------------------------------------------------------------
# Loading
# ----------------------------------------------------------------------

def load_events(path):
    events = []
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
    return events


def load_truth(path):
    if not os.path.exists(path):
        return []
    return load_events(path)


def discover_runs(directory):
    """Find every (case, trial, log path, truth path) triple on disk."""
    runs = []
    for log_path in sorted(glob.glob(os.path.join(directory, "*_trial*.jsonl"))):
        base = os.path.basename(log_path)
        if base.endswith("_truth.jsonl"):
            continue
        stem = base[: -len(".jsonl")]
        case, _, trial_part = stem.partition("_trial")
        try:
            trial = int(trial_part)
        except ValueError:
            continue
        runs.append(
            {
                "case": case,
                "trial": trial,
                "log": log_path,
                "truth": os.path.join(directory, "%s_truth.jsonl" % stem),
            }
        )
    return runs


# ----------------------------------------------------------------------
# Scoring one run
# ----------------------------------------------------------------------

def effective_windows(truths):
    """Give each attack a matching window that cannot swallow the next attack.

    An attack's window is its own interval plus a grace period, because a
    detector scores at window boundaries and an attack ending mid-window is
    legitimately reported when that window closes.

    But every attack in a run comes from the same compromised host, so the
    source address cannot tell two of them apart. Left uncapped, the grace
    period lets an alert for a *later* attack fall inside an *earlier* one's
    window and be credited to it. That is not a hypothetical: it credited the
    per-flow baseline with catching lateral movement in C6 and C7, at a
    mean-time-to-detect of 26-36 seconds -- well after the ~22-second lateral
    attack had finished. The "detections" were its port-scan alerts for the
    attack that ran next.

    So the grace period is truncated at the start of the following attack from
    the same host.
    """
    windows = []
    by_source = defaultdict(list)
    for truth in truths:
        if truth.get("t_start") is not None and truth.get("t_end") is not None:
            by_source[truth.get("src")].append(truth)

    for source, items in by_source.items():
        items.sort(key=lambda t: t["t_start"])
        for index, truth in enumerate(items):
            end = truth["t_end"] + DETECTION_GRACE_SECONDS
            if index + 1 < len(items):
                end = min(end, items[index + 1]["t_start"])
            windows.append((truth, truth["t_start"], end))
    return windows


def match_alert(alert, truths, class_exact):
    """Return the attack this alert detected, or None if it is a false positive.

    When more than one attack could claim the alert, an exact class match wins;
    failing that, the most recently started attack does.
    """
    when = alert.get("wall", 0)
    candidates = [
        truth
        for truth, start, end in effective_windows(truths)
        if alert.get("src_ip") == truth.get("src") and start <= when <= end
    ]
    if not candidates:
        return None

    exact = [c for c in candidates if c.get("attack_class") == alert.get("attack_class")]
    if exact:
        return max(exact, key=lambda t: t["t_start"])
    if class_exact:
        return None
    return max(candidates, key=lambda t: t["t_start"])


def score_run(run):
    """Score one run into per-detector detection, timing and overhead figures."""
    events = load_events(run["log"])
    truths = load_truth(run["truth"])

    alerts = [e for e in events if e["kind"] == "alert"]
    decisions = [e for e in events if e["kind"] == "mitigation_decided"]
    flowmods = [e for e in events if e["kind"] == "flowmod_sent"]
    barriers = [e for e in events if e["kind"] == "barrier_reply"]
    timings = [e for e in events if e["kind"] == "detector_timing"]
    samples = [e for e in events if e["kind"] == "resource_sample"]
    run_start = next((e for e in events if e["kind"] == "run_start"), {})
    run_end = next((e for e in events if e["kind"] == "run_end"), {})

    result = {
        "case": run["case"],
        "trial": run["trial"],
        "mitigator": run_start.get("mitigator", "?"),
        "attacks": len(truths),
        "detectors": {},
        "attack_details": [],
        "timing": {},
        "overhead": {},
    }

    # -- detection ----------------------------------------------------
    for detector in DETECTORS:
        detector_alerts = [a for a in alerts if a.get("detector") == detector]

        agnostic_hits, exact_hits, false_positives = {}, {}, []
        matched_alerts = 0
        for alert in detector_alerts:
            matched = match_alert(alert, truths, class_exact=False)
            if matched is None:
                false_positives.append(alert)
                continue
            matched_alerts += 1
            key = (matched["attack_class"], matched["t_start"])
            agnostic_hits.setdefault(key, alert)
            if alert.get("attack_class") == matched["attack_class"]:
                exact_hits.setdefault(key, alert)

        # Coverage counts distinct *attacks* caught; precision counts correct
        # *alerts*. Dividing attacks-caught by alerts-raised would mix the two
        # and punish a detector for reporting one attack twice, which the alert
        # cooldown already limits.
        detected = len(agnostic_hits)
        result["detectors"][detector] = {
            "alerts": len(detector_alerts),
            "true_positives": detected,
            "matched_alerts": matched_alerts,
            "false_positives": len(false_positives),
            "class_exact_detections": len(exact_hits),
            "attacks": len(truths),
            "detection_rate": detected / len(truths) if truths else None,
            "precision": (
                matched_alerts / len(detector_alerts) if detector_alerts else None
            ),
        }

    # -- per attack: which detector saw it, and how fast ---------------
    for truth in truths:
        detail = {
            "case": run["case"],
            "trial": run["trial"],
            "attack_class": truth.get("attack_class"),
            "src": truth.get("src"),
            "duration": round(truth.get("t_end", 0) - truth.get("t_start", 0), 2),
        }
        for detector in DETECTORS:
            first = None
            for alert in sorted(
                (a for a in alerts if a.get("detector") == detector),
                key=lambda a: a.get("wall", 0),
            ):
                # Matched against *every* attack in the run, then checked to
                # see whether this one won. Passing a single attack here would
                # hide its neighbours from the matcher, and the grace period
                # would once again reach across into the next attack -- which
                # is exactly the miscrediting effective_windows() exists to
                # prevent.
                if match_alert(alert, truths, class_exact=False) is truth:
                    first = alert
                    break
            detail["%s_detected" % detector] = first is not None
            detail["%s_mttd" % detector] = (
                round(first["wall"] - truth["t_start"], 3) if first else None
            )
            detail["%s_score" % detector] = round(first["score"], 3) if first else None
        result["attack_details"].append(detail)

    # -- timing -------------------------------------------------------
    # Decision latency is small by construction (the decision is taken
    # synchronously with the alert), so it is reported but is not the
    # interesting number. Rule-installation latency -- FlowMod sent to switch
    # barrier confirmation -- is the one that answers Research Gap 4.
    decision_latencies = [
        d["t"] - d["alert_ts"] for d in decisions if d.get("alert_ts") is not None
    ]
    install_latencies = [
        b["install_latency"] for b in barriers if b.get("install_latency") is not None
    ]

    containment = []
    for truth in truths:
        confirmations = [
            b["wall"] for b in barriers
            if b.get("wall", 0) >= truth.get("t_start", 0)
        ]
        if confirmations:
            containment.append(min(confirmations) - truth["t_start"])

    result["timing"] = {
        "mean_decision_latency": mean_or_none(decision_latencies),
        "mean_install_latency": mean_or_none(install_latencies),
        "max_install_latency": max(install_latencies) if install_latencies else None,
        "rules_installed": len(flowmods),
        "rules_confirmed": len(install_latencies),
        # First malicious packet to a rule confirmed on a switch: the number
        # that actually describes how long the attacker had.
        "mean_time_to_containment": mean_or_none(containment),
    }

    # -- overhead -----------------------------------------------------
    scoring_timings = [t for t in timings if not t.get("warming_up")]
    cpu = [s["cpu_percent"] for s in samples if s.get("cpu_percent") is not None]
    rss = [s["rss_bytes"] for s in samples if s.get("rss_bytes") is not None]

    baseline_times = [t["baseline_seconds"] for t in timings if "baseline_seconds" in t]
    graph_times = [t["graph_total_seconds"] for t in timings if "graph_total_seconds" in t]
    betweenness_times = [
        t["betweenness_seconds"] for t in timings if "betweenness_seconds" in t
    ]

    result["overhead"] = {
        "windows_scored": len(scoring_timings),
        "mean_baseline_seconds": mean_or_none(baseline_times),
        "mean_graph_seconds": mean_or_none(graph_times),
        "max_graph_seconds": max(graph_times) if graph_times else None,
        "mean_betweenness_seconds": mean_or_none(betweenness_times),
        "graph_cost_ratio": (
            (statistics.mean(graph_times) / statistics.mean(baseline_times))
            if baseline_times and graph_times and statistics.mean(baseline_times) > 0
            else None
        ),
        "mean_cpu_percent": mean_or_none(cpu),
        "max_cpu_percent": max(cpu) if cpu else None,
        "mean_rss_mb": (statistics.mean(rss) / 1e6) if rss else None,
        "packet_in_count": run_end.get("packet_in_count"),
        "records_ingested": run_end.get("records_ingested"),
        "records_from_packet_in": run_end.get("records_from_packet_in"),
        "records_from_flow_stats": run_end.get("records_from_flow_stats"),
        "records_rejected_late": run_end.get("records_rejected_late"),
        "mitigation_rules": run_end.get("rules_installed"),
    }

    # -- disruption ---------------------------------------------------
    attack_sources = {t.get("src") for t in truths}
    blocked_sources = {d.get("src_ip") for d in decisions if d.get("actuate")}
    innocent_blocked = sorted(blocked_sources - attack_sources)
    result["disruption"] = {
        "blocked_sources": len(blocked_sources),
        "innocent_hosts_blocked": len(innocent_blocked),
        "innocent_hosts": ",".join(innocent_blocked),
    }

    return result


def mean_or_none(values):
    return statistics.mean(values) if values else None


# ----------------------------------------------------------------------
# Tables
# ----------------------------------------------------------------------

def write_csv(path, rows, fieldnames=None):
    if not rows:
        return None
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fieldnames = fieldnames or list(rows[0].keys())
    with open(path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return path


def round_row(row, places=4):
    out = {}
    for key, value in row.items():
        if isinstance(value, float):
            out[key] = round(value, places)
        else:
            out[key] = value
    return out


def build_tables(results, tables_dir):
    written = []

    # 1. Per-run detection summary.
    detection_rows = []
    for result in results:
        for detector, figures in result["detectors"].items():
            detection_rows.append(
                round_row(
                    {
                        "case": result["case"],
                        "trial": result["trial"],
                        "mitigator": result["mitigator"],
                        "detector": detector,
                        "attacks": figures["attacks"],
                        "alerts": figures["alerts"],
                        "true_positives": figures["true_positives"],
                        "matched_alerts": figures["matched_alerts"],
                        "false_positives": figures["false_positives"],
                        "class_exact": figures["class_exact_detections"],
                        "detection_rate": figures["detection_rate"],
                        "precision": figures["precision"],
                    }
                )
            )
    written.append(write_csv(os.path.join(tables_dir, "detection_by_run.csv"),
                             detection_rows))

    # 2. THE headline table: per attack class, did each detector see it?
    by_class = defaultdict(lambda: defaultdict(list))
    mttd = defaultdict(lambda: defaultdict(list))
    for result in results:
        for detail in result["attack_details"]:
            attack_class = detail["attack_class"]
            for detector in DETECTORS:
                by_class[attack_class][detector].append(
                    1 if detail["%s_detected" % detector] else 0
                )
                value = detail["%s_mttd" % detector]
                if value is not None:
                    mttd[attack_class][detector].append(value)

    coverage_rows = []
    for attack_class in sorted(by_class):
        row = {"attack_class": attack_class,
               "attack_instances": len(by_class[attack_class][DETECTOR_BASELINE])}
        for detector in DETECTORS:
            hits = by_class[attack_class][detector]
            row["%s_coverage" % detector] = (
                sum(hits) / len(hits) if hits else None
            )
            row["%s_mttd_mean" % detector] = mean_or_none(mttd[attack_class][detector])
        coverage_rows.append(round_row(row))
    written.append(write_csv(os.path.join(tables_dir, "coverage_by_class.csv"),
                             coverage_rows))

    # 3. Per-attack detail, so a single odd trial can be found rather than
    #    hidden inside a mean.
    detail_rows = [round_row(d) for r in results for d in r["attack_details"]]
    written.append(write_csv(os.path.join(tables_dir, "attacks_detail.csv"),
                             detail_rows))

    # 4. Timing.
    timing_rows = [
        round_row(dict(case=r["case"], trial=r["trial"], mitigator=r["mitigator"],
                       **r["timing"]))
        for r in results
    ]
    written.append(write_csv(os.path.join(tables_dir, "timing.csv"), timing_rows))

    # 5. Overhead -- the cost side of the comparison.
    overhead_rows = [
        round_row(dict(case=r["case"], trial=r["trial"], **r["overhead"]))
        for r in results
    ]
    written.append(write_csv(os.path.join(tables_dir, "overhead.csv"), overhead_rows))

    # 6. False positives on normal-only traffic (C1).
    fp_rows = []
    for result in results:
        if result["attacks"]:
            continue
        for detector, figures in result["detectors"].items():
            fp_rows.append(
                {
                    "case": result["case"],
                    "trial": result["trial"],
                    "detector": detector,
                    "false_positive_alerts": figures["false_positives"],
                }
            )
    if fp_rows:
        written.append(write_csv(os.path.join(tables_dir, "false_positives.csv"),
                                 fp_rows))

    # 7. Disruption.
    disruption_rows = [
        dict(case=r["case"], trial=r["trial"], mitigator=r["mitigator"],
             **r["disruption"])
        for r in results
    ]
    written.append(write_csv(os.path.join(tables_dir, "disruption.csv"),
                             disruption_rows))

    return [path for path in written if path]


# ----------------------------------------------------------------------
# Figures
# ----------------------------------------------------------------------

def build_figures(results, figs_dir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as error:
        print("figures skipped (matplotlib unavailable: %s)" % error)
        return []

    os.makedirs(figs_dir, exist_ok=True)
    written = []

    # Figure 1: coverage per attack class, baseline vs graph.
    by_class = defaultdict(lambda: defaultdict(list))
    for result in results:
        for detail in result["attack_details"]:
            for detector in DETECTORS:
                by_class[detail["attack_class"]][detector].append(
                    1 if detail["%s_detected" % detector] else 0
                )

    if by_class:
        classes = sorted(by_class)
        baseline = [
            100 * sum(by_class[c][DETECTOR_BASELINE]) / len(by_class[c][DETECTOR_BASELINE])
            for c in classes
        ]
        graph = [
            100 * sum(by_class[c][DETECTOR_GRAPH]) / len(by_class[c][DETECTOR_GRAPH])
            for c in classes
        ]
        positions = range(len(classes))
        width = 0.38

        figure, axis = plt.subplots(figsize=(7.5, 4.2))
        axis.bar([p - width / 2 for p in positions], baseline, width,
                 label="per-flow baseline", color="#4C72B0")
        axis.bar([p + width / 2 for p in positions], graph, width,
                 label="graph-based", color="#DD8452")
        axis.set_xticks(list(positions))
        axis.set_xticklabels(classes)
        axis.set_ylabel("detection coverage (%)")
        axis.set_ylim(0, 105)
        axis.set_title("Detection coverage by attack class (class-agnostic)")
        axis.legend()
        axis.grid(axis="y", alpha=0.3)
        figure.tight_layout()
        path = os.path.join(figs_dir, "coverage_by_class.png")
        figure.savefig(path, dpi=150)
        plt.close(figure)
        written.append(path)

    # Figure 2: what the graph detector costs per window, against the baseline.
    baseline_times, graph_times = [], []
    for result in results:
        if result["overhead"]["mean_baseline_seconds"] is not None:
            baseline_times.append(result["overhead"]["mean_baseline_seconds"] * 1000)
        if result["overhead"]["mean_graph_seconds"] is not None:
            graph_times.append(result["overhead"]["mean_graph_seconds"] * 1000)

    if baseline_times and graph_times:
        figure, axis = plt.subplots(figsize=(6.5, 4.2))
        axis.boxplot([baseline_times, graph_times],
                     labels=["per-flow baseline", "graph-based"])
        axis.set_ylabel("detector compute time per window (ms)")
        axis.set_yscale("log")
        axis.set_title("Per-window detection cost (log scale)")
        axis.grid(axis="y", alpha=0.3)
        figure.tight_layout()
        path = os.path.join(figs_dir, "detector_cost.png")
        figure.savefig(path, dpi=150)
        plt.close(figure)
        written.append(path)

    return written


# ----------------------------------------------------------------------

def print_summary(results):
    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)

    by_class = defaultdict(lambda: defaultdict(list))
    for result in results:
        for detail in result["attack_details"]:
            for detector in DETECTORS:
                by_class[detail["attack_class"]][detector].append(
                    1 if detail["%s_detected" % detector] else 0
                )

    if by_class:
        print("\nDetection coverage by attack class (class-agnostic):")
        print("  %-12s %10s %12s %12s" % ("class", "instances", "baseline", "graph"))
        for attack_class in sorted(by_class):
            hits = by_class[attack_class]
            instances = len(hits[DETECTOR_BASELINE])
            print(
                "  %-12s %10d %11.0f%% %11.0f%%"
                % (
                    attack_class,
                    instances,
                    100 * sum(hits[DETECTOR_BASELINE]) / instances,
                    100 * sum(hits[DETECTOR_GRAPH]) / instances,
                )
            )

    normal_only = [r for r in results if not r["attacks"]]
    if normal_only:
        print("\nFalse positives on normal-only traffic (%d run(s)):" % len(normal_only))
        for detector in DETECTORS:
            total = sum(r["detectors"][detector]["false_positives"] for r in normal_only)
            print("  %-10s %d alert(s)" % (detector, total))

    costs = [r["overhead"]["graph_cost_ratio"] for r in results
             if r["overhead"]["graph_cost_ratio"]]
    if costs:
        print("\nCost of the graph detector relative to the baseline: %.1fx per window"
              % statistics.mean(costs))

    latencies = [r["timing"]["mean_install_latency"] for r in results
                 if r["timing"]["mean_install_latency"]]
    if latencies:
        print("Mean rule-installation latency (FlowMod to switch confirmation): %.1f ms"
              % (1000 * statistics.mean(latencies)))

    containment = [r["timing"]["mean_time_to_containment"] for r in results
                   if r["timing"]["mean_time_to_containment"]]
    if containment:
        print("Mean time to containment (first malicious packet to rule confirmed): "
              "%.1f s" % statistics.mean(containment))

    innocent = sum(r["disruption"]["innocent_hosts_blocked"] for r in results)
    print("Innocent hosts blocked across all runs: %d" % innocent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", default=config.RESULTS_RAW_DIR)
    parser.add_argument("--tables", default=config.RESULTS_TABLES_DIR)
    parser.add_argument("--figs", default=config.RESULTS_FIGS_DIR)
    args = parser.parse_args()

    runs = discover_runs(args.raw)
    if not runs:
        print("no runs found in %s -- run experiments/run_case.py first" % args.raw)
        return 1

    print("analysing %d run(s) from %s" % (len(runs), args.raw))
    results = [score_run(run) for run in runs]

    for path in build_tables(results, args.tables):
        print("  wrote %s" % path)
    for path in build_figures(results, args.figs):
        print("  wrote %s" % path)

    print_summary(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
