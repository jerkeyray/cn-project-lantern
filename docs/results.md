# Final evaluation results

The selected campaign is `results/campaigns/submission-20260922-v2`. Its
implementation and configuration were frozen before calibration. The campaign
contains one pilot, three normal-only calibration trials, and 95 evaluation
trials: 35 detection-only, 50 mitigation, five benign-variation, and five
reversed-order trials. All 99 runs passed the validity checks on their first
attempt; no failed attempts were excluded.

Calibration selected the following fixed thresholds from normal-only
observations: port-scan ports 6, port-scan hosts 4, DoS packets/second 21,
SYN-retry attempts 1, and graph score 6. The calibration observations,
selected values, and checksum are included with the evidence.

## Detection-only results

The primary evidence is five mitigation-disabled trials for each single-class
case C2--C5. Detection means attacker identification with an unambiguous
source-and-window match; class-exact additionally requires the reported class.
Intervals are Wilson 95% intervals. Each row has five attack instances, so a
100% estimate has a 56.6--100% interval and a 0% estimate has a 0--43.4%
interval.

| Workload | Threshold baseline | Graph detector | Interpretation |
| --- | --- | --- | --- |
| Port scan (C2) | 5/5 detected, 5/5 class-exact | 5/5 detected, 0/5 class-exact | The graph identified the source but labelled these alerts differently. |
| DoS simulation (C3) | 5/5, 5/5 class-exact | 0/5, 0/5 class-exact | The graph missed this configured workload. |
| SYN-retry simulation (C4) | 5/5, 5/5 class-exact | 0/5, 0/5 class-exact | The graph missed this configured workload. |
| Sequential contact (C5) | 5/5 detected, 0/5 class-exact | 5/5 detected, 5/5 class-exact | Only the graph gave the configured lateral label. |

Among detected primary cases, mean detection delay ranged from 8.72 to 18.69
seconds for the baseline and from 8.72 to 8.75 seconds for the graph. Full
per-trial timing, medians, and ranges are in `submission/tables/coverage.csv`
and `submission/tables/timing_summary.csv`.

The mixed C6/C7 cases are secondary because attacks in a run share evolving
profiles. Mixed C6/C7 coverage was 4/5 baseline versus 0/5 graph for
SYN-retry, 10/10 versus 10/10 for sequential contact, and 7/10 versus 4/10
for port scan. Pooling primary and mixed detection cases gives 9/10 versus
0/10 for SYN-retry, 15/15 versus 15/15 for sequential contact, and 12/15
versus 9/15 for port scan. In the five reversed C7 trials, both detectors found only the
sequential-contact attack (5/5); neither found the port-scan or SYN-retry
attack. This demonstrates order dependence in the online profiling design.

The benign peer-communication variation produced false-positive candidates in
30/273 eligible benign source-host windows (11.0%) for the baseline and 14/273
(5.1%) for the graph. These are candidate counts before cooldown suppression;
operational alert counts are retained separately in
`submission/tables/detections.csv`.

## Mitigation, delivery, and resources

The 50 mitigation trials separately actuated the baseline or graph for C2--C6.
Rule confirmation and observed blocking are different measures. The baseline
had correlated switch confirmation for 25 of 30 attack records, but none met
the receiver-plus-drop-counter blocking criterion. The graph had correlated
confirmation and observed blocking for 10 of 30 attack records; the remaining
records are reported as unverified rather than credited. For confirmed records,
the graph's rule-confirmation delay had mean 8.78 seconds (range 8.75--8.81).
The baseline's confirmed-record mean was 10.88 seconds (range 8.75--19.28).

Innocent HTTP clients completed all 621/621 attack-period requests and all
1,683/1,683 recovery requests for both actuators. Requests originating from
the attack source are intentionally reported separately: baseline source
failure was 13.5% during attack and 72.4% in recovery; graph source failure
was 37.2% during attack and 39.9% in recovery. Continuing source traffic can
refresh a source-wide idle-timeout rule, so recovery is an observation rather
than a guaranteed property.

`submission/tables/overhead.csv` contains per-run warmup and evaluation CPU, RSS,
PacketIn, flow-statistics, detector-compute, and flow-table occupancy samples.
The table reports software OVS occupancy only; it is not a hardware TCAM
measurement.

## Evidence and limits

Every headline value is traceable through `submission/tables/evidence_map.csv`
and the per-run identifiers in the other CSVs.
`submission/tables/validity.csv` records all 99 valid runs. The raw event logs,
truth records, receiver observations, probe logs, manifests, configuration,
dependency inventory, and checksums are in the curated `submission/` directory.

These controlled simulations support a comparison with this configured
threshold baseline on this six-host topology. They do not show that graph
methods uniquely detect lateral movement, generalize to production traffic, or
demonstrate a successful authentication attack or host compromise. Five trials
per condition are a small sample, and multi-attack observations within a run
are dependent.

## Submission verification

The repository validation passes all 67 unit and regression tests. Earlier live
checks passed 30/30 datapath pings and 13 service integration checks covering
forwarding, source/pair blocking, unaffected clients, and idle-expiry recovery.
The included evidence passes checksum verification and exact regeneration of
every published CSV. Source and curated evidence are scanned for credential
patterns and accidental machine-local paths before packaging.

The allowlisted archive is generated with `make package`. Its extracted source
is checked with `make build`, `make validate`, and `make verify`; these commands
require Docker and do not require the original development directory.
