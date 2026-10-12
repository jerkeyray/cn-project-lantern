# Repaired campaign results

Measurement protocol 2: receivers explicitly select host interfaces and pass independent capture health checks.

Thresholds reuse the historical normal-only calibration. Detector logic, weights, mitigation policy, seeds, warmup, and recovery are unchanged. Scan, SYN-retry, and flood workloads send for 40 seconds; longer workloads can change detection results.

## Primary detection comparison

| Workload | Detector | Source identification | Correct label | Mean detection delay (s) |
| --- | --- | --- | --- | --- |
| bruteforce | baseline | 5/5 | 5/5 | 4.497840356826782 |
| bruteforce | graph | 0/5 | 0/5 | unavailable |
| dos | baseline | 5/5 | 5/5 | 14.48231782913208 |
| dos | graph | 0/5 | 0/5 | unavailable |
| lateral | baseline | 5/5 | 0/5 | 4.52108941078186 |
| lateral | graph | 5/5 | 5/5 | 4.522620058059692 |
| portscan | baseline | 5/5 | 5/5 | 4.551313066482544 |
| portscan | graph | 5/5 | 0/5 | 4.552883911132812 |

## Blocking evidence

| Actuator | Workload | All records | Testable | Verified | Leakage | No confirmation | Too short | Receiver unavailable | Insufficient drops |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| baseline | all | 30 | 25 | 15 | 10 | 5 | 0 | 0 | 0 |
| baseline | bruteforce | 5 | 5 | 5 | 0 | 0 | 0 | 0 | 0 |
| baseline | dos | 5 | 5 | 5 | 0 | 0 | 0 | 0 | 0 |
| baseline | lateral | 10 | 10 | 0 | 10 | 0 | 0 | 0 | 0 |
| baseline | portscan | 10 | 5 | 5 | 0 | 5 | 0 | 0 | 0 |
| graph | all | 30 | 10 | 9 | 0 | 20 | 0 | 0 | 1 |
| graph | bruteforce | 5 | 0 | 0 | 0 | 5 | 0 | 0 | 0 |
| graph | dos | 5 | 0 | 0 | 0 | 5 | 0 | 0 | 0 |
| graph | lateral | 10 | 10 | 9 | 0 | 0 | 0 | 0 | 1 |
| graph | portscan | 10 | 0 | 0 | 0 | 10 | 0 | 0 | 0 |

All attacks remain in the overall denominator. Testable records require sufficient ongoing sending and healthy receiver samples. Verification concerns the sampled interval after a one-second settling allowance; it is not a lossless wire capture. Source-wide drop counters also include legitimate source traffic.

## Innocent HTTP delivery

| Actuator | Period | Successful requests |
| --- | --- | --- |
| baseline | attack | 1476/1476 |
| baseline | recovery | 1691/1692 |
| graph | attack | 1476/1476 |
| graph | recovery | 1687/1690 |

## Candidate precision and false alarms

| Phase | Detector | Matched candidates | Unmatched | Ambiguous | Flagged benign windows |
| --- | --- | --- | --- | --- | --- |
| detection | baseline | 227 | 4 | 32 | 4/1868 |
| detection | graph | 44 | 0 | 7 | 0/1868 |
| benign | baseline | 0 | 31 | 0 | 31/297 |
| benign | graph | 0 | 16 | 0 | 16/297 |
| order | baseline | 55 | 0 | 30 | 0/390 |
| order | graph | 6 | 0 | 10 | 0/390 |

Precision uses matched/(matched + unmatched); ambiguous candidates are reported separately. False-positive rates count unique eligible benign source-host/windows, before cooldown suppression.

## Controller resources

| Detection-only evaluation | Mean across trials |
| --- | --- |
| CPU percent | 3.838 |
| RSS MiB | 73.676 |
| Baseline compute ms | 0.148 |
| Graph compute ms | 1.636 |

## Mitigation timing

| Case | Actuator | Metric | Trials | Mean seconds |
| --- | --- | --- | --- | --- |
| C2 | baseline | alert_to_decision | 5 | 0.00398936373142836 |
| C2 | graph | alert_to_decision | 5 | 0.003952426639152691 |
| C3 | baseline | alert_to_decision | 5 | 0.0006118500023148954 |
| C3 | graph | alert_to_decision | 5 | 0.0015118206007173284 |
| C4 | baseline | alert_to_decision | 5 | 0.0021562832058407365 |
| C4 | graph | alert_to_decision | 5 | 0.002621374902082607 |
| C5 | baseline | alert_to_decision | 5 | 0.00286554019645943 |
| C5 | graph | alert_to_decision | 5 | 0.0030409347692814965 |
| C6 | baseline | alert_to_decision | 5 | 0.0033053751666254055 |
| C6 | graph | alert_to_decision | 5 | 0.0033147832000395283 |
| C2 | baseline | decision_to_confirmation | 5 | 0.014960841805441305 |
| C2 | graph | decision_to_confirmation | 0 | unavailable |
| C3 | baseline | decision_to_confirmation | 5 | 0.4625597003963776 |
| C3 | graph | decision_to_confirmation | 0 | unavailable |
| C4 | baseline | decision_to_confirmation | 5 | 0.029195333598181605 |
| C4 | graph | decision_to_confirmation | 0 | unavailable |
| C5 | baseline | decision_to_confirmation | 5 | 0.012806516699492931 |
| C5 | graph | decision_to_confirmation | 5 | 0.010369099798845127 |
| C6 | baseline | decision_to_confirmation | 5 | 0.016529333300422878 |
| C6 | graph | decision_to_confirmation | 5 | 0.013584533397806808 |
| C2 | baseline | flowmod_to_confirmation | 5 | 0.008576283298316412 |
| C2 | graph | flowmod_to_confirmation | 0 | unavailable |
| C3 | baseline | flowmod_to_confirmation | 5 | 0.2781365584931336 |
| C3 | graph | flowmod_to_confirmation | 0 | unavailable |
| C4 | baseline | flowmod_to_confirmation | 5 | 0.015394162604934536 |
| C4 | graph | flowmod_to_confirmation | 0 | unavailable |
| C5 | baseline | flowmod_to_confirmation | 5 | 0.007698127049661707 |
| C5 | graph | flowmod_to_confirmation | 5 | 0.007716566495946609 |
| C6 | baseline | flowmod_to_confirmation | 5 | 0.010069408350682351 |
| C6 | graph | flowmod_to_confirmation | 5 | 0.010315733304014429 |

## Provenance and limits

95 of 95 retained runs passed validity checks. Failed attempts remain available and are excluded from measured aggregates.

Source content hash: `a77f8f748cabe612a6dea20801bd2146083f802452122d24119bd92d2c0e68d8`.

Calibration provenance: `{"calibration_sha256": "406ef7af661f1720b7eaa213859fba9e0217781880682a5fb7baf909b5383ea5", "mode": "reused", "source": "submission", "source_hash": "2ad916a6938167c3086624dc3fead7c422563b0ccf734a47244a8a05aa63c526", "threshold_sha256": "bce1a39f14e6c794479230dbdc0978e8568b3bfbdeafb890f5680bc171734ccf"}`.

Historical CSVs are preserved separately; their old verified blocking values are counter-based outcomes with receiver delivery unavailable. The lateral workload models sequential contacts, not host compromise; SYN retries do not perform authentication. Five trials per condition and this six-host topology limit generalization.
