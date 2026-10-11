# Recorded experiment replay

From the repository root, run `python3 -m replay serve --port 8000`, then open
http://localhost:8000. Stop the server with Ctrl+C. If the port is occupied,
choose another port, such as `--port 8001`. Python 3 is the only playback
dependency; no Docker, Node, network emulation, or internet connection is needed.

## Views

- **Results** (`#results`): a verdict and five questions (attacks
  caught, false alarms, did blocking work, innocent users, cost), each with one
  visual and a plain answer, plus collapsible definitions and Review 1 objectives.
  The numbers come from `replay/summary.py`, which reads the published tables
  (the PDF report uses the same module). Click a coverage row to replay that case.
- **Guided replay** (`#replay`): five chapters, each with "what to watch" and the
  five-trial result. The pipeline strip shows each stage as the run reaches it:
  Algorithm A collection, B/C candidates, decision, D rule confirmation, and the
  retrospective blocking verdict. Detector cards show source/class verdict chips
  and the score against its threshold; graph cards also list the top feature
  contributions. **Focus on attack** (on by default) zooms the timeline and
  charts to the attack and its response instead of the 135 s warmup.

## Present the project

The five guided chapters use trial 1 as an illustrative example, not an average:

1. **Source versus class:** C5 detection with mitigation disabled. Both detectors
   identify the source; only the graph assigns the configured lateral class.
2. **Baseline mitigation:** C5 with the baseline actuating. Switch confirmation
   exists, while the published blocking assessment remains unverified.
3. **Graph mitigation:** C5 with graph actuation. Inspect confirmations, sampled
   receiver counts, and legitimate requests before consulting the published
   verified-blocking result.
4. **Legitimate change:** benign peer communication produces false-positive
   candidates. Cooldown can suppress operational alerts but not those candidates.
5. **Attack order:** reversed C7 demonstrates the online profile's order effects.

Use **Event →** to explain
milestones one at a time, or Play at 2× or 5× for a continuous walkthrough.
The slider supports backward scrubbing; each position is reconstructed from
observations up to that point. Changing chapters or trials resets to a paused
start. Expand **Browse all trials** to filter by phase, case, actuator, and trial. Pilot and calibration
remain labelled supplementary.

Deep links open a chapter at a position, for example
`http://localhost:8000/#replay&chapter=3&t=151` (graph mitigation at rule
confirmation); `#results` opens the overview.

Keyboard: Space toggles playback, Left/Right step milestones, Home restarts.
Native buttons, selects, and the slider retain their normal keyboard controls
when focused. Reduced-motion preferences disable decorative moving dashes.

## Read the visuals accurately

- Grey lines are fixed physical links. Dashed communication overlays represent
  recorded HTTP observations or receiver-count increases, not packet trajectories.
- Attack intervals and target rings come from experiment truth, not detector
  inference. Total sends are available; exact per-send timestamps are not.
- Receiver curves contain cumulative marked-traffic samples. Lines connect
  samples for readability; they do not supply missing packet arrival times.
- HTTP circles show successful request latency; crosses show failed requests.
  Innocent clients and the attack source are counted separately. In normal-only
  runs, the configured h4 source role is used for that display grouping.
- Detector candidates precede cooldown; operational alerts are separate. An
  unmatched candidate is not automatically labelled a false positive: consult
  the eligible-benign-window denominator in the published summary.
- An operational decision may be observation-only. A complete confirmation
  requires the same actuating decision's full targeted switch set. No block
  is inferred simply because a switch acknowledged a rule.
- Verified/unverified containment is the published retrospective assessment.
  It appears as a timeline event at run end and is always labelled retrospective
  in the results panel. Missing confirmation times stay unavailable.
- Expiry notifications and switch occupancy snapshots are separate measurements;
  stale or differing counts must not be treated as proof of forwarding recovery.

Expand **Trial results & event log** to inspect published outcomes and milestones.
Click an event in the trail to inspect its full JSON, actual/recorded clock,
stable identifiers, attribution, source filename, and line number. Evidence
links open the original allowlisted logs and CSV tables. The full historical
communication graph was not logged, so the replay does not reconstruct it.

## Export and validate

```sh
python3 -m unittest discover -s replay/tests -v
python3 -m replay export --output output/lantern-replay.zip
```

Export refuses to overwrite an existing ZIP. Extract into a fresh directory,
enter `lantern-replay/`, and run `python3 serve.py --port 8000`. The ZIP includes
the static viewer, deterministic data, referenced evidence, and checksums.
Both servers verify their inventory before starting and bind only to
`127.0.0.1`; unknown paths and directory listings are not served.

For optional developer checks of the pure browser state model, run
`node replay/tests/model.test.mjs`. Node is not a user-facing dependency.

This module and its tests live outside the frozen experiment source inventory.
Preparation verifies every curated checksum, refuses invalid or incomplete runs,
and writes only generated output. No experiment source, curated evidence, or
original submission archive is modified.

## Results report

`python3 -m replay.report` verifies the curated checksums, then writes
`output/pdf/lantern-results-report.html` and prints it to
`output/pdf/lantern-results-report.pdf` with headless Chrome. It reads
only `submission/`; the earlier `lantern-research-report.pdf` is left untouched.
