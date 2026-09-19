# Lantern — Graph-Based SDN Controller-Integrated IDS

An intrusion detection system that runs inside a Ryu SDN controller, detects
attacks on live OpenFlow traffic, and installs blocking rules automatically.

It exists to answer one question:

> Does adding graph-based host-communication analysis to an SDN
> controller-integrated IDS improve the detection of lateral movement compared
> with a conventional per-flow detector, while maintaining acceptable mitigation
> latency and legitimate-traffic disruption?

So the deliverable is not really "an IDS" — it is a **controlled comparison**.
Two detectors observe byte-identical traffic inside the same live control loop:

| | Per-flow baseline | Graph-based detector |
|---|---|---|
| Sees | one host's flows at a time | the whole host-communication graph |
| Method | thresholds on rate, port count, failed connections | per-host anomaly score `S(h,t)` over graph features |
| Catches | port scans, DoS, brute force | lateral movement |
| Costs | almost nothing | measurably more (reported, not hidden) |

The baseline represents the approach used by essentially every paper in the
project's literature survey. It is built to be a fair opponent, not a straw man.

## What makes the comparison valid

Four decisions do most of the work, and each is enforced in code rather than
left as an intention:

1. **Both detectors receive the same `Window` object.** Neither can see traffic
   the other cannot (`lantern/app.py`, `on_window_closed`).
2. **Mitigation is off during comparison runs.** If both detectors installed
   drop rules, the faster one would destroy the traffic the other still needed;
   the comparison would measure the race, not the detectors. Enforced by the
   mitigator mode in `lantern/decision.py`, forced to `none` for case C7.
3. **The lateral-movement scenario refuses to run if it is loud enough for the
   baseline to catch on volume alone** (`traffic/attacks/lateral.py`,
   `check_pacing`). A scenario that drifts loud is a scenario bug, and it fails
   noisily rather than quietly handing the baseline a win.
4. **Thresholds are tuned on normal traffic only** (case C1), never on the
   attacks they are then scored against.
5. **An alert is only credited to an attack that was still running**
   (`experiments/analyze.py`, `effective_windows`). Every attack in a run comes
   from the same compromised host, so the source address cannot separate them;
   left uncapped, the grace period let a port-scan alert be credited to the
   lateral-movement attack that ran before it. That one bug reported the
   per-flow baseline as catching lateral movement 55% of the time. It catches
   it 0% of the time.

## Requirements

Docker. Nothing else — Mininet, Open vSwitch and Ryu all live in the image.
Everything runs on macOS (Apple Silicon included) and on Linux.

## Quick start

```bash
make build           # build the container image
make datapath-check  # gate: does the userspace datapath forward traffic?
make test            # unit tests, seconds, no emulation needed
make run-case CASE=C5 TRIALS=1   # watch the graph detector catch lateral movement
make analyze         # tables and figures from whatever runs exist
```

`make datapath-check` is not optional the first time. Docker Desktop's LinuxKit
kernel has no `openvswitch` module, so every bridge runs on the userspace
(netdev) datapath; if that does not forward, nothing else in the project will.
If it fails, run under a real kernel instead:

```bash
colima start --vm-type=vz --cpu 4 --memory 8
```

## The experiment

Seven cases, exactly as the project report defines them
(`experiments/cases.py`):

| Case | Traffic | Purpose |
|---|---|---|
| C1 | normal only | measure the false-positive rate, and set the thresholds |
| C2 | port scan | scanning detection — the baseline should win this one |
| C3 | denial of service | high-rate anomaly detection |
| C4 | brute force | repeated failed connections |
| C5 | lateral movement | **the case the project exists for** |
| C6 | mixed normal + attack | legitimate-traffic disruption |
| C7 | every attack, no mitigation | the headline comparison |

```bash
make plan TRIALS=3      # print the plan and a time estimate, run nothing
make run-all TRIALS=3   # full sweep, roughly 100 minutes
make analyze
```

The sweep runs two passes. The **detection pass** disables mitigation so the
coverage comparison is uncontaminated. The **mitigation pass** re-runs the
attack cases with one detector actuating at a time, which is where the timing
figures come from. Runs are labelled separately on disk (`C2` versus
`C2-mit-graph`) so the analysis keeps them apart.

**Every run gets its own container**, and that matters more than it sounds.
`scripts/run_sweep.sh` drives the loop from the host rather than looping inside
one long-lived container, because after roughly twenty consecutive Mininet
start/stops the container's networking degrades: traffic generators are starved,
the PacketIn rate drops by an order of magnitude, and runs stop producing enough
windows for the graph detector to finish profiling. Those runs do not fail —
they quietly show up in the results as "the detector missed it". In one 29-run
sweep this silently cost four runs before it was caught.

## Results

From 29 runs: 3 trials of each case C1–C7 (detection pass) plus one run per
actuating detector for C2–C5 (mitigation pass).

**Detection coverage by attack class** — did the detector flag the attacking
host while the attack was running?

| Attack class | Instances | Per-flow baseline | Graph-based | Graph MTTD |
|---|---|---|---|---|
| **lateral movement** | 11 | **0%** | **100%** | 5.86 s |
| port scan | 11 | 91% | 82% | 4.66 s |
| brute force | 8 | 100% | 25% | 4.53 s |
| denial of service | 5 | 100% | 0% | — |

The baseline winning three classes out of four is the point, not a defect. The
graph detector is not a better detector; it is a differently blind one, and it
sees the single thing per-flow analysis structurally cannot. A method that won
everywhere would mean the baseline had been built to lose.

**Safety.** Zero false positives from either detector across three normal-only
runs, 100% precision on the attack cases (all 46 alerts matched a real attack),
and zero innocent hosts blocked in any run.

**Cost** (Research Gap 4). The graph detector costs ~70x more per window than
the baseline — 4.05 ms against 0.09 ms — which is 0.04% of a ten-second window.
Controller CPU averaged 1.9% and RSS 69 MB. Betweenness centrality alone is
2.95 ms of that 4.05 ms, and it is the term that grows with host count, so it is
also the best available evidence on Research Gap 5 at this scale.

**Closing the loop.** On identical C5 traffic, the baseline installed no rules
because it never saw the attack; the graph detector installed two (one per
switch), barrier-confirmed in 7 ms, containing the attacker 5.65 s after its
first malicious packet. Rule installation degraded to 311 ms under the DoS
flood — mitigation is slowest exactly when it is most needed.

## Output

`make analyze` writes to `results/`:

- `tables/coverage_by_class.csv` — **the headline**: per attack class, what
  fraction each detector caught, and how fast
- `tables/attacks_detail.csv` — every individual attack, so an odd trial can be
  found rather than hidden inside a mean
- `tables/timing.csv` — decision latency, rule-installation latency (FlowMod to
  switch barrier confirmation), and time to containment
- `tables/overhead.csv` — controller CPU and memory, PacketIn volume, and what
  the graph detector costs per window relative to the baseline
- `tables/false_positives.csv` — C1, the run that sets the thresholds
- `tables/disruption.csv` — innocent hosts caught by mitigation
- `figs/coverage_by_class.png`, `figs/detector_cost.png`

Coverage is reported **class-agnostically** by default: did the detector flag
the attacking host while the attack was running? The graph detector only ever
emits "lateral movement" and makes no claim to name which attack it is looking
at, so scoring it on class accuracy would penalise it for something it never
claimed. Class-exact counts are reported alongside, because the baseline *does*
make that claim.

## How it fits together

```
Mininet topology ──▶ OpenFlow switches ──▶ PacketIn + FlowStats
                                                │
                              ┌─────────────────▼──────────────────┐
                              │          Ryu controller            │
                              │                                    │
                              │  FlowCollector ─▶ WindowAggregator │
                              │                       │            │
                              │        ┌──────────────┴─────────┐  │
                              │        ▼                        ▼  │
                              │  BaselineDetector        GraphDetector
                              │        └──────────┬─────────────┘  │
                              │                   ▼                │
                              │            AlertManager            │
                              │                   ▼                │
                              │          MitigationEngine          │
                              └───────────────────┬────────────────┘
                                                  ▼
                                    OpenFlow drop / redirect rules
```

| File | Role |
|---|---|
| `lantern/config.py` | every threshold, weight and topology fact, in one place |
| `lantern/collector.py` | PacketIn + flow-stats ingest (Algorithm A) |
| `lantern/features.py` | counter diffing and windowing — no Ryu import, so it is unit testable |
| `lantern/detector_baseline.py` | threshold rules (Algorithm B) |
| `lantern/graph_builder.py` | `G_t=(V_t,E_t)` and per-host rolling profiles |
| `lantern/detector_graph.py` | graph features → z-scores → `S(h,t)` (Algorithm C) |
| `lantern/decision.py` | severity, dedupe, action choice, actuation gating |
| `lantern/mitigation.py` | FlowMod + barrier-confirmed timing (Algorithm D) |
| `lantern/metrics.py` | JSONL event log and controller resource sampling |
| `experiments/run_all.py` | plans the sweep (it does not run it) |
| `scripts/run_sweep.sh` | runs the sweep, one fresh container per run |

## Three detector design decisions worth knowing before changing anything

**Directional graph features.** The communication graph is undirected, but
degree, new-neighbour ratio and port diversity are computed over the peers a
host *reached out to*, not everyone it exchanged packets with. Without that
distinction, an attacker contacting four machines makes all four gain an
unfamiliar neighbour — so every victim alerts alongside the attacker, and since
mitigation blocks the host an alert names, the system would answer an intrusion
by cutting off the machines that were broken into. This showed up in a real run
before it was fixed: a port scan made the *server* alert, because its RST
replies came from all 64 scanned ports. Betweenness and community membership
stay undirected, because "does this host sit between two groups" has no
direction to it.

**The graph detector does not always say "lateral movement".** It detects that
a host's communication structure changed sharply. When the new-neighbour ratio
is what drove the score, that is lateral movement and it says so; when the score
came from somewhere else — port diversity exploding against a host it always
talks to — it reports a `graph_anomaly` instead, and the decision manager logs
rather than blocks unless the score was extreme. Asserting a movement that was
not observed would put a wrong word in front of an analyst.

**Attack order matters in multi-attack runs.** The graph detector's profiles
keep learning, so a loud attack run first trains away the signal for a quiet one
that follows: a port scan folds a window of ~80 ports into the attacker's own
baseline and adds every host it touched to its seen-neighbours set. C7 therefore
runs lateral movement first, and the single-attack cases C2–C5 — each against a
clean profile — remain the primary evidence.

## Two emulation details, for the same reason

**Microflow forwarding rules.** The learning switch installs 5-tuple rules, not
MAC-pair rules. With MAC-pair rules, everything after a conversation's first
packet — every new port a scanner touches, every login retry — would be
forwarded without the controller ever seeing it, and port-scan and brute-force
detection would be blind by construction. The cost is more PacketIn events and
more flow-table entries, which is not hidden: it is exactly the controller
overhead this project set out to measure.

**Static ARP.** Every run pre-populates host ARP tables. Without it, Linux drops
packets while ARP resolution is pending — scapy sends one packet and moves on,
so most generated traffic never reached the wire. ARP also floods to every port,
which would add an edge from every host to every other host if it were modelled.

## Scope

Implemented: the report's minimum viable project and its main research
contribution. Deliberately not implemented, per the report's own scoping: a
scikit-learn ML baseline, Suricata signature integration, honeypot redirection,
multi-controller scalability, and adversarial-evasion robustness.

`lantern/decision.py` takes alerts from any source, so adding a third detector
later means emitting an `Alert` and nothing more.
