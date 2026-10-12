# Lantern: final evaluation and conclusion

**Evaluation date:** 12 October 2026  
**Campaign:** `submission-20261012-measurement-v3`  
**Evidence:** `submission-repaired-20261012`  
**Measurement protocol:** 2

## Final conclusion

In controlled SDN simulations, the graph detector improved lateral-movement
classification and blocking compared with the calibrated threshold baseline.
Both detectors identified the attacker in all five primary lateral trials,
but the graph correctly classified all five, while the baseline correctly
classified none. Across the ten lateral attack records in the C5 and C6
mitigation conditions, graph blocking was verified in nine records. All ten
baseline lateral records showed receiver leakage.

This is a positive result for the graph approach on the evaluated lateral
workload. It does not establish overall superiority: the baseline correctly
identified and classified primary scans, floods, and SYN retries, while the
graph missed floods and SYN retries and reported an incorrect class for scans.
The results suggest complementary strengths; a combined mitigation policy was
not evaluated in this campaign.

## What was repaired

Historical receiver sniffers did not explicitly select a network interface.
In the Mininet hosts, Scapy selected loopback, so the receivers reported zero
attack packets even when mitigation was disabled. Historical receiver silence
therefore did not establish blocking. Some short historical attacks also ended
before enough post-confirmation traffic could be observed.

The repaired evaluation requires each receiver to select its host's actual
interface, record readiness, and capture five separately marked diagnostic
packets before warmup. Diagnostic packets are separate from attack counts and
ground truth. Capture startup or health-check failure invalidates the run.

Scan and SYN-retry generators now support duration-based repetition while
retaining their original one-pass behavior when repetition is omitted. Scan,
SYN-retry, and flood evaluation workloads send for 40 seconds, including mixed
and reversed cases. Packet rates, targets, lateral pacing, seeds, warmup,
recovery, detector logic, graph weights, and mitigation policy were preserved.

The historical calibrated thresholds were imported without recalibration:

| Threshold | Fixed value |
| --- | ---: |
| Scan ports | 6 |
| Scan hosts | 4 |
| Flood rate | 21 |
| SYN attempts | 1 |
| Graph score | 6 |

Longer attacks can change detection outcomes, so the new and historical
campaigns remain separate.

## Evaluation completion

All 12 C2–C5 pilots passed measurement checks. The subsequent evaluation
completed all 95 conditions with no invalid attempts:

| Phase | Trials |
| --- | ---: |
| Detection with mitigation disabled | 35 |
| Baseline or graph mitigation | 50 |
| Changed benign workload | 5 |
| Reversed attack order | 5 |
| **Total** | **95** |

All 570 receiver logs passed independent capture health checks. Source and
image hashes were frozen, and calibration provenance was retained.

## Detection and classification

Source identification means the detector flagged the attacking host during
an overlapping attack window. Correct classification additionally requires
the reported attack label to match ground truth. These are separate outcomes.

| Primary simulated workload | Baseline source | Baseline correct label | Graph source | Graph correct label |
| --- | ---: | ---: | ---: | ---: |
| Port scan | 5/5 | 5/5 | 5/5 | 0/5 |
| Flood | 5/5 | 5/5 | 0/5 | 0/5 |
| SYN retries | 5/5 | 5/5 | 0/5 | 0/5 |
| Lateral sequential contacts | 5/5 | 0/5 | 5/5 | 5/5 |

The graph's lateral advantage is improved classification, rather than improved
attacker identification: both detectors found the source.

In reversed-order trials, the baseline identified all five instances of each
workload. The graph identified lateral contacts in 5/5, scans in 1/5, and SYN
retries in 0/5. Its detected scan still had an incorrect label. Order sensitivity
is therefore part of the observed behavior.

## Blocking results

Protocol-2 verification requires healthy receivers, correlated confirmation
from every targeted switch for the same mitigation decision, at least three
seconds of subsequent malicious sending, increasing matching rule drop
counters, and stable attack counts at every target across at least two
samples after the existing one-second settling allowance.

Every attack remains in the overall denominator. Testable records additionally
have enough post-confirmation sending and healthy receiver samples.

| Actuator | Overall verified | Testable verified | Leakage | No confirmation | Insufficient counter evidence |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline | 15/30 | 15/25 | 10 | 5 | 0 |
| Graph | 9/30 | 9/10 | 0 | 20 | 1 |

| Simulated workload | Baseline verified / all | Graph verified / all |
| --- | ---: | ---: |
| Port scan | 5/10 | 0/10 |
| Flood | 5/5 | 0/5 |
| SYN retries | 5/5 | 0/5 |
| Lateral sequential contacts | 0/10 | 9/10 |

The ten scan records per actuator include primary and mixed conditions.
Baseline confirmed no scan rule in five mixed records. All five primary scan
blocks verified. Graph confirmed no rules for scans, floods, or SYN retries.

The ten lateral records per actuator span C5 and C6. All were testable. All
baseline lateral records showed leakage. Nine graph records verified; the
remaining graph record had insufficient increasing counter evidence and is
explicitly unverified. It is not counted as either verified blocking or
observed leakage.

No repaired blocking record was rejected for unavailable receiver evidence or
insufficient post-confirmation duration. Verification applies to the sampled
interval; it is not proof of zero delivery throughout the whole attack or a
lossless wire capture. Source-wide counters can include legitimate traffic
from the attack source.

## Innocent-user delivery

| Actuator | During attacks | During recovery | Combined |
| --- | ---: | ---: | ---: |
| Baseline | 1476/1476 | 1691/1692 | 3167/3168 |
| Graph | 1476/1476 | 1687/1690 | 3163/3166 |

All innocent HTTP requests succeeded during attacks under both actuators.
There was one failed recovery request under baseline and three under graph.
These failures remain in the results; overall delivery is not reported as
perfect. Their cause has not been established by these aggregate counts.

## False alarms

For scheduled legitimate changes in communication patterns, baseline flagged
31 of 297 eligible benign source-host/windows (10.44%), and graph flagged
16 of 297 (5.39%). The graph produced fewer false alarms in this workload,
but both produced false alarms.

These rates use detector candidates before cooldown suppression. In the
detection phase, baseline flagged 4/1868 eligible benign windows and graph
flagged 0/1868. Neither flagged an eligible benign window in the reversed-order
phase (0/390 each). Ambiguous candidates are reported separately in the full
results report.

## Timing and computational cost

| Primary workload | Baseline mean detection delay | Graph mean detection delay |
| --- | ---: | ---: |
| Scan | 4.551 s | 4.553 s |
| Flood | 14.482 s | No detection |
| SYN retries | 4.498 s | No detection |
| Lateral sequential contacts | 4.521 s | 4.523 s |

For C5 lateral mitigation, mean decision-to-all-switch-confirmation time was
12.81 ms for baseline and 10.37 ms for graph. Confirmation is distinct from
successful blocking. All phase, class, and timing measurements are available
in the detailed tables.

| Detection-only resource measurement | Mean across trials |
| --- | ---: |
| Controller CPU | 3.838% |
| Controller RSS | 73.676 MiB |
| Baseline detector compute per window | 0.148 ms |
| Graph detector compute per window | 1.636 ms |

The graph uses more computation than the baseline, though both measured
compute times are small relative to the ten-second detector window. Resource
measurements describe this test environment.

## Validation and provenance

Before the pilots, all 107 Python tests, replay model checks, 30 datapath pings,
13 integration checks, and historical checksum/table regeneration passed.
After the evaluation, independent checks confirmed all 95 matrix conditions,
their seeds and warmup, frozen source/image provenance, imported calibration,
570 healthy receiver logs, curated checksums, and byte-for-byte regeneration
of the new CSV tables. The detailed report reproduced exactly from the tables.
The final replay archive contains all 95 runs with chronological events and
explicit protocol-2 blocking outcomes. Replay tests and UI checks passed.

**Frozen source content hash:**
`a77f8f748cabe612a6dea20801bd2146083f802452122d24119bd92d2c0e68d8`

**Frozen image ID:**
`sha256:42e24c106f14aae617598b849bbc1870c0021ec659c92fbe6d5df62fb8b34daf`

Historical submission data and preliminary pilot attempts remain preserved.
Historical “verified” blocking records are interpreted as counter-based
evidence with receiver delivery unavailable. No code was committed or pushed,
and the supplied presentation PDF was not edited.

## Limits of the conclusion

- Five trials per condition and a six-host topology limit generalization.
- Lateral movement is simulated as sequential contacts; the workload does not
  compromise hosts or demonstrate actual propagation.
- SYN retries simulate repeated connection attempts, not password guessing or
  successful authentication.
- The graph does not reliably detect all evaluated attack classes.
- The comparison uses the fixed calibrated baseline and graph configuration;
  it does not establish superiority over other detectors or tuned variants.
- A combined detector or mitigation policy remains a proposal for future work.

## Report-ready conclusion

> The repaired evaluation demonstrates that graph-based analysis can improve
> lateral-movement classification and mitigation in a controlled SDN testbed.
> Both detectors identified the attacking source in all five primary lateral
> trials, but only the graph correctly classified all five. Across ten lateral
> mitigation records, graph blocking was verified in nine, while all ten
> baseline records showed receiver leakage. The baseline nevertheless covered
> more attack classes and successfully blocked the primary scan, flood, and
> SYN-retry workloads. These findings support complementary detector roles
> within the evaluated simulations, rather than overall graph superiority.

## Supporting artifacts

- [Detailed results report](../submission-repaired-20261012-results.md)
- [Detection and classification table](../submission-repaired-20261012/tables/coverage.csv)
- [Blocking summary](../submission-repaired-20261012/tables/blocking_summary.csv)
- [Per-attack blocking evidence](../submission-repaired-20261012/tables/containment.csv)
- [Innocent and attack-source delivery](../submission-repaired-20261012/tables/disruption.csv)
- [Timing summary](../submission-repaired-20261012/tables/timing_summary.csv)
- [Frozen manifest](../submission-repaired-20261012/manifest.json)
- [Evidence checksums](../submission-repaired-20261012/checksums.json)
- [Portable replay archive](../output/lantern-repaired-20261012-replay.zip)
- [Replay archive checksum](../output/lantern-repaired-20261012-replay.zip.sha256)
