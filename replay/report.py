"""Build the supplementary Lantern results report (HTML, then PDF via headless Chrome).

Run from the repository root:  python3 -m replay.report
Lives outside the frozen experiment source inventory, like the replay viewer.
Every figure is drawn from submission/ after its checksums are verified.
No experiment is re-run and no detector is re-tuned.
"""

import csv
import glob
import hashlib
import json
import shutil
import statistics as st
import subprocess
import sys
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
from .summary import overview, NAMES, ATTACKS

E = ROOT / "submission"
OUT_DIR = ROOT / "output/pdf"
HTML = OUT_DIR / "lantern-results-report.html"
PDF = OUT_DIR / "lantern-results-report.pdf"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

checks = json.loads((E / "checksums.json").read_text())
for name, sha in checks.items():
    assert hashlib.sha256((E / name).read_bytes()).hexdigest() == sha, name
T = {p.stem: list(csv.DictReader(p.open())) for p in sorted((E / "tables").glob("*.csv"))}
assert len(T["validity"]) == 99 and all(r["valid"] == "True" for r in T["validity"])
M = json.loads((E / "manifest.json").read_text())
TH = json.loads((E / "thresholds.json").read_text())
O = overview(T, TH)
P = lambda a, d: O["primary"]["%s|%s" % (a, d)]
FP = lambda p, d: O["false_positives"]["%s|%s" % (p, d)]
DL = lambda k: O["delivery"][k]


def f(x, scale=1, nd=2):
    return "—" if x in ("", None) else "%.*f" % (nd, float(x) * scale)


def pct(n, d):
    return "%.1f%%" % (100 * n / d) if d else "n/a"


def table(headers, rows, cls=""):
    head = "".join("<th>%s</th>" % h for h in headers)
    body = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % c for c in r) for r in rows)
    return '<table class="%s"><thead><tr>%s</tr></thead><tbody>%s</tbody></table>' % (cls, head, body)


def chip(ok, text):
    return '<span class="chip %s">%s</span>' % ({True: "ok", False: "no", None: "mid"}[ok], text)


# ---------- worked example: C5 trial 1, both actuators ----------
def example(mitigator):
    log = glob.glob(str(E / ("evidence/mitigation/**/mitigation-C5-%s_trial01.jsonl" % mitigator)), recursive=True)[0]
    truth = json.loads(open(log.replace(".jsonl", "_truth.jsonl")).readline())
    first = truth["first_send"]
    ev = [json.loads(l) for l in open(log)]
    at = lambda d: (d.get("created_wall") or d.get("decided_wall") or d["wall"]) - first
    cand = {}
    for d in ev:  # first candidate per detector after the attack starts
        if d["kind"] == "detector_candidate" and 0 < at(d) < 30:
            cand.setdefault(d["detector"], d)
    dec = next(d for d in ev if d["kind"] == "mitigation_decided" and d.get("actuate"))
    replies = [d for d in ev if d["kind"] == "barrier_reply" and d["decision_id"] == dec["decision_id"]]
    window = max(d["wall"] - first for d in ev if d["kind"] == "window_closed" and d["wall"] - first <= at(cand["graph"]))
    expiry = [d for d in ev if d["kind"] == "mitigation_expired" and d.get("decision_id") == dec["decision_id"]]
    match = next(d["match"] for d in ev if d["kind"] == "flowmod_sent" and d["decision_id"] == dec["decision_id"])
    block = next(r for r in T["containment"] if r["phase"] == "mitigation" and r["case"] == "C5"
                 and r["mitigator"] == mitigator and r["trial"] == "1")["observed_blocking"]
    return {"truth": truth, "cand": cand, "dec": dec, "replies": replies, "window": window, "at": at,
            "last": truth["last_send"] - first, "expiry": [at(d) for d in expiry], "match": match, "block": block}


G, B = example("graph"), example("baseline")
gc = G["cand"]["graph"]
contrib = gc["evidence"]["contributions"]

# ---------- SVG figures ----------
def svg_pipeline():
    boxes = [("Mininet hosts", "h1–h5, server", 10), ("OVS switches", "s1, s2 · OF 1.3", 140),
             ("A · Collect", "PacketIn + stats → windows", 270)]
    s = '<svg viewBox="0 0 700 190" class="fig">'
    for title, sub, x in boxes:
        s += '<rect x="%d" y="20" width="118" height="54" rx="8" class="bx"/><text x="%d" y="43" class="bt">%s</text><text x="%d" y="60" class="bs">%s</text>' % (x, x + 59, title, x + 59, sub)
    s += '<rect x="410" y="6" width="118" height="38" rx="8" class="bx base"/><text x="469" y="22" class="bt">B · Baseline</text><text x="469" y="36" class="bs">thresholds</text>'
    s += '<rect x="410" y="52" width="118" height="38" rx="8" class="bx graph"/><text x="469" y="68" class="bt">C · Graph</text><text x="469" y="82" class="bs">host graph</text>'
    s += '<rect x="560" y="20" width="130" height="54" rx="8" class="bx"/><text x="625" y="43" class="bt">Decision</text><text x="625" y="60" class="bs">cooldown · act / observe</text>'
    s += '<rect x="560" y="116" width="130" height="54" rx="8" class="bx act"/><text x="625" y="139" class="bt">D · Mitigate</text><text x="625" y="156" class="bs">drop rule · 30 s idle</text>'
    s += '<rect x="270" y="116" width="258" height="54" rx="8" class="bx dim"/><text x="399" y="139" class="bt">Evaluation module</text><text x="399" y="156" class="bs">truth · receivers · HTTP · CPU · timing</text>'
    for x1, x2, y in [(128, 140, 47), (258, 270, 47), (528, 560, 25), (528, 560, 71)]:
        s += '<path d="M%d %d H%d" class="ar"/>' % (x1, y, x2)
    s += '<path d="M388 47 H398 V25 H410 M398 47 V71 H410" class="ar"/>'
    s += '<path d="M625 74 V116" class="ar"/><path d="M560 143 H528" class="ar dash"/>'
    s += '<path d="M625 170 V182 H199 V74" class="ar"/><text x="412" y="186" class="bs">FlowMod + barrier → switches</text>'
    return s + "</svg>"


def svg_topology():
    pos = {"h1": (60, 40), "h2": (60, 100), "h3": (60, 160), "s1": (230, 100), "s2": (420, 100),
           "h4": (590, 40), "h5": (590, 100), "server": (590, 160)}
    role = {"h1": "workstation", "h2": "workstation", "h3": "workstation", "h4": "attack source",
            "h5": "auth-service role", "server": "real HTTP service"}
    s = '<svg viewBox="0 0 660 200" class="fig">'
    for a, b in [("h1", "s1"), ("h2", "s1"), ("h3", "s1"), ("s1", "s2"), ("s2", "h4"), ("s2", "h5"), ("s2", "server")]:
        s += '<line x1="%d" y1="%d" x2="%d" y2="%d" class="ln"/>' % (*pos[a], *pos[b])
    for n, (x, y) in pos.items():
        if n.startswith("s") and n != "server":
            s += '<rect x="%d" y="%d" width="70" height="36" rx="7" class="bx"/><text x="%d" y="%d" class="bt">%s</text>' % (x - 35, y - 18, x, y + 4, n)
        else:
            s += '<circle cx="%d" cy="%d" r="19" class="nd %s"/><text x="%d" y="%d" class="bt">%s</text><text x="%d" y="%d" class="bs">%s</text>' % (x, y, "atk" if n == "h4" else "", x, y + 4, n, x, y + 32, role[n])
    s += '<text x="325" y="190" class="bs">Both switches connect to one Ryu controller (out-of-band)</text>'
    return s + "</svg>"


def svg_coverage():
    s = '<svg viewBox="0 0 660 230" class="fig">'
    x = lambda v: 200 + 360 * v
    for i, a in enumerate(ATTACKS):
        y = 30 + i * 48
        s += '<text x="0" y="%d" class="lt">%s</text>' % (y + 10, NAMES[a])
        for j, d in enumerate(["baseline", "graph"]):
            r, yy = P(a, d), y + j * 16
            cls = "base" if d == "baseline" else "graph"
            s += '<line x1="%.1f" x2="%.1f" y1="%d" y2="%d" class="ci %s"/>' % (x(r["wilson_low"]), x(r["wilson_high"]), yy, yy, cls)
            s += '<circle cx="%.1f" cy="%d" r="5" class="pt %s"/>' % (x(r["detected"] / r["instances"]), yy, cls)
            mark = "✓" if r["class_exact"] == r["instances"] else ("✗" if r["detected"] else "–")
            s += '<text x="580" y="%d" class="ls">%d/5 · class %s</text>' % (yy + 4, r["detected"], mark)
    for v in (0, .5, 1):
        s += '<line x1="%.1f" x2="%.1f" y1="18" y2="212" class="grid"/><text x="%.1f" y="226" class="ls" text-anchor="middle">%d%%</text>' % (x(v), x(v), x(v), v * 100)
    s += '<circle cx="8" cy="221" r="4" class="pt base"/><text x="16" y="225" class="ls">baseline</text><circle cx="86" cy="221" r="4" class="pt graph"/><text x="94" y="225" class="ls">graph</text>'
    return s + "</svg>"


def svg_example():
    """Timeline of C5 trial 1 (graph actuator), seconds from first malicious send."""
    span = 42
    x = lambda t: 30 + t / span * 620
    s = '<svg viewBox="0 0 680 190" class="fig">'
    s += '<rect x="%.1f" y="30" width="%.1f" height="18" rx="4" class="atk"/><text x="%.1f" y="24" class="ls">sequential contact: %d sends to 5 hosts</text>' % (x(0), x(G["last"]) - x(0), x(0), G["truth"]["sent"])
    for w in range(-1, 4):
        t = G["window"] + 10 * w
        if 0 <= t <= span:
            s += '<line x1="%.1f" x2="%.1f" y1="60" y2="150" class="grid"/>' % (x(t), x(t))
    s += '<text x="%.1f" y="164" class="ls" text-anchor="middle">window closes</text>' % x(G["window"])
    pts = [(G["at"](gc), "graph candidate · score %.2f" % gc["score"], 78), (G["at"](G["dec"]), "drop_source decided", 98),
           (G["at"](G["replies"][-1]), "both switches confirm (+%.1f ms)" % ((G["at"](G["replies"][-1]) - G["at"](G["dec"])) * 1000), 118)]
    for t, lab, y in pts:
        s += '<circle cx="%.1f" cy="%d" r="4.5" class="pt graph"/><text x="%.1f" y="%d" class="ls">%s</text>' % (x(t), y, x(t) + 10, y + 4, lab)
    for t in G["expiry"]:
        s += '<circle cx="%.1f" cy="138" r="4.5" class="pt dim"/><text x="%.1f" y="142" class="ls" text-anchor="end">rule idle-expiry (30 s after last match)</text>' % (x(t), x(t) - 10)
    s += '<line x1="30" x2="650" y1="172" y2="172" class="ln"/>'
    for t in range(0, span + 1, 5):
        s += '<text x="%.1f" y="186" class="ls" text-anchor="middle">%d s</text>' % (x(t), t)
    return s + "</svg>"


def svg_bars(rows, vmax, unit_fmt, width=660):
    """rows: (label, value, class, annotation). One shared scale, labelled ends."""
    h = 34 * len(rows) + 24
    s = '<svg viewBox="0 0 %d %d" class="fig">' % (width, h)
    x = lambda v: 200 + v / vmax * 360
    for i, (lab, v, cls, note) in enumerate(rows):
        y = 8 + i * 34
        s += '<text x="0" y="%d" class="lt">%s</text><rect x="200" y="%d" width="360" height="18" rx="4" class="trk"/>' % (y + 13, lab, y)
        if v:
            s += '<rect x="200" y="%d" width="%.1f" height="18" rx="4" class="%s"/>' % (y, max(2, x(v) - 200), cls)
        s += '<text x="%.1f" y="%d" class="lv">%s</text>' % (x(v) + 6, y + 13, note)
    s += '<text x="200" y="%d" class="ls">0</text><text x="560" y="%d" class="ls" text-anchor="end">%s</text>' % (h - 4, h - 4, unit_fmt(vmax))
    return s + "</svg>"


# ---------- derived values ----------
mb, mg = O["mitigation"]["baseline"], O["mitigation"]["graph"]
inn = sum(DL("%s|innocent|%s" % (d, p))["successes"] for d in ("baseline", "graph") for p in ("attack", "recovery"))
inn_n = sum(DL("%s|innocent|%s" % (d, p))["attempts"] for d in ("baseline", "graph") for p in ("attack", "recovery"))
cost = O["cost"]
tm = lambda k: O["timing"][k]["mean_ms"]
ratios = {}
for case in ["C%d" % i for i in range(1, 8)]:
    rr = [r for r in T["overhead"] if r["phase"] == "detection" and r["case"] == case and r["period"] == "evaluation"]
    ratios[case] = st.mean(float(r["graph_cost_ratio"]) for r in rr)

# ---------- document ----------
S = []
add = S.append

add('''<section class="cover">
<p class="kicker">Computer Networks · Semester Project · Final results</p>
<h1>Graph-Based SDN Controller-Integrated Intrusion Detection and Automated Mitigation</h1>
<p class="sub"><b>Lantern</b>: a controlled comparison of a threshold baseline and a host-communication graph detector inside a Ryu controller, with automated OpenFlow drop rules</p>
<div class="kpis">
<div><b>%d/%d</b><span>runs valid on the first attempt (95 evaluation + 4 supplementary)</span></div>
<div><b>5/5 vs 0/5</b><span>sequential contact correctly classified, graph vs baseline</span></div>
<div><b>%s vs %s</b><span>benign-change host-windows flagged, graph vs baseline</span></div>
<div><b>%d/30 vs %d/30</b><span>independently verified blocks, graph vs baseline</span></div>
<div><b>%s</b><span>innocent HTTP requests served during mitigation (%s/%s)</span></div>
<div><b>%.1f ms</b><span>decision → both switches confirmed (C5, graph)</span></div>
</div>
<table class="meta"><tr><td>Team</td><td>Vatsala Rai (24BCE2803) · Yoshita Vanapalli (24BCE2812) · Jahnavi Sharma (24BCE2707) · Hasini (24BCE0342)</td></tr>
<tr><td>Department</td><td>Computer Science and Engineering</td></tr>
<tr><td>Evidence</td><td>Campaign <code>submission-20260922-v2</code>; all curated checksums re-verified when this report was generated</td></tr>
<tr><td>Date</td><td>10 October 2026</td></tr></table>
<p class="toc"><b>Contents</b> 1 Summary · 2 Review 1 → delivered · 3 System · 4 Experiment design · 5 Reading the metrics · 6 Detection · 7 Worked example · 8 False alarms &amp; order · 9 Mitigation &amp; delivery · 10 Cost · 11 Research questions answered · 12 Limitations &amp; future work · 13 Reproduction · Appendices A–C</p>
</section>''' % (O["validity"]["valid"], O["validity"]["runs"], pct(FP("benign", "graph")["flagged"], 273), pct(FP("benign", "baseline")["flagged"], 273),
       mg["verified"], mb["verified"], pct(inn, inn_n), "{:,}".format(inn), "{:,}".format(inn_n), tm("C5|graph|decision_to_confirmation")))

add('''<section class="pb"><h2>1 · Executive summary</h2>
<p class="lead">Review 1 asked whether adding a <b>host-communication graph</b> to an SDN controller IDS improves detection of internal lateral movement compared with a conventional per-flow detector, while keeping mitigation latency and collateral disruption acceptable. We built both detectors into one Ryu application and ran them on identical 10-second observation windows. Across 95 evaluation trials, the answer is <b>yes for classifying the lateral pattern, but not as a replacement</b>. The two detectors are complementary.</p>
<div class="findings">
<div class="f good"><b>Graph wins on lateral classification</b><p>The graph labelled sequential contact correctly in 5/5 primary trials, while the baseline did so in 0/5. The baseline did see h4, but its SYN-retry rule fired first because the contacts touched SSH port 22.</p></div>
<div class="f good"><b>…and that label drives better mitigation</b><p>The correct label produced a source-wide drop that met the independent blocking test in 10/30 records, all of them sequential contact. The baseline's mislabel produced a narrow h4→h1:22 pair rule: 25/30 rules were confirmed, but 0/30 blocks were verified.</p></div>
<div class="f warn"><b>Baseline wins on breadth</b><p>The baseline identified every primary attack (scan, DoS, SYN retry, sequential contact). The graph missed DoS and SYN retry entirely (0/5 each). Both are single-pair floods with no new neighbours, so they produce no structural signal.</p></div>
<div class="f good"><b>Low cost, no collateral damage</b><p>The graph needs %.2f ms per window against %.2f ms for the baseline, which is small next to the 10 s window. Controller CPU averaged %.2f%%. Every one of the %s innocent HTTP requests succeeded under both actuators.</p></div>
<div class="f warn"><b>Neither is false-alarm-free</b><p>When legitimate peer traffic changed, the graph flagged %s of host-windows and the baseline %s. Reversing the attack order made both miss the scan and SYN retry, because the online profiles adapt.</p></div>
<div class="f"><b>Detection delay is set by the window</b><p>Mean detection delays of about 8.7 s match the time until the current 10 s window closes. The candidates followed the window close within 2 ms. DoS took about 18.7 s because its rule needs two windows.</p></div>
</div>
<p class="note">Scope: one six-host, two-switch emulated topology with synthetic workloads and five repeats per condition. The results support complementary signals in this testbed. They do not support a claim of production accuracy, scalability or universal graph superiority.</p></section>''' % (cost["graph_ms"]["mean"], cost["baseline_ms"]["mean"], cost["cpu_percent"]["mean"], "{:,}".format(inn_n), pct(FP("benign", "graph")["flagged"], 273), pct(FP("benign", "baseline")["flagged"], 273)))

trace = [
    ["O1 · Ryu IDS collecting PacketIn + flow stats", chip(True, "Delivered"), "Algorithm A: PacketIn and 5 s flow-statistics polling feed shared 10 s windows. All 99 runs are logged with wall and monotonic timestamps."],
    ["O2 · Detect scan, DoS, brute force, lateral movement", chip(None, "Partly"), "Baseline: all four primary classes. Graph: scan and sequential contact only. Brute force was implemented as repeated SYN attempts (no password guessing). Lateral movement is a sequential-contact simulation, not real compromise."],
    ["O3 · Automatic OpenFlow mitigation", chip(None, "Drop only"), "Algorithm D installs drop rules (priority 100, 30 s idle timeout) and records barrier confirmations. Redirect/quarantine actions were not implemented."],
    ["O4 · Compare detectors on identical traffic", chip(True, "Delivered"), "Both detectors score every window. Mitigation runs alternate the actuator. All Review 1 metric families are reported (mapping below)."],
    ["Cases C1–C7", chip(True, "Run as planned"), "C4 'brute force' became SYN retry. C7 is the multi-attack sequence (sequential contact → scan → SYN retry) plus a reversed-order check. Benign peer-variation runs were added."],
    ["Algorithms A–D", chip(True, "Implemented"), "Matches the Review 1 steps. One difference: profiles keep learning during evaluation (EWMA α = 0.2), and this was measured rather than hidden."],
    ["Tier 3 extensions", chip(False, "Not attempted"), "No ML classifier, Suricata integration, honeypot redirection or temporal embeddings. Review 1 declared these optional."],
    ["Gap 5 · scalability", chip(False, "Deferred"), "As declared in Review 1. This is a single small topology and nothing here measures scaling."],
]
metrics = [
    ["True-positive rate / per-class coverage", "Identification coverage and class-exact coverage per attack, with Wilson 95% intervals (§6)"],
    ["False-positive rate", "Flagged eligible benign host-windows ÷ all eligible host-windows (§8)"],
    ["Precision", "Candidate precision: matched ÷ (matched + unmatched), with ambiguous candidates kept separate (§8)"],
    ["Mean time to detect", "Alert creation minus first malicious send, over detected attacks only (§6)"],
    ["Mean time to mitigate", "Alert → decision (ms) and attack start → all-switch confirmation (s) (§9, §10)"],
    ["Rule-installation latency", "Decision → every targeted switch's barrier reply, and per-rule FlowMod → barrier (§10)"],
    ["TCAM usage", "Sampled OVS software flow-entry occupancy, used as a proxy rather than hardware TCAM (§10)"],
    ["CPU / memory, PacketIn & stats counts", "Controller CPU% and RSS per run; PacketIn and flow-stats counters retained in overhead.csv (§10)"],
    ["Legitimate-traffic disruption", "HTTP success/attempts and latency, split into innocent clients and the attack source (§9)"],
]
add('<section><h2>2 · From Review 1 plan to delivered system</h2><p>Each Review 1 commitment is listed with its outcome, so an evaluator can trace the presentation through to the evidence. Changes from the plan are stated explicitly.</p>%s<h3>Review 1 metrics → where they are reported</h3>%s<h3>Research gaps addressed</h3><p><b>Gaps 1 and 4</b> (live control loop; detection-to-mitigation latency and overhead): both detectors ran live on PacketIn and flow-stats data inside Ryu, with timing and CPU measured per run. <b>Gaps 2 and 3</b> (beyond DDoS; network-wide host graph): the graph detector targets a low-volume sequential-contact pattern and is compared head-to-head with per-flow thresholds. <b>Gap 5</b> stays open as declared.</p></section>' % (table(["Review 1 item", "Status", "What was delivered"], trace, "trace"), table(["Planned metric", "Reported as"], metrics)))

w = {"degree": "1.0", "packet volume": "0.3", "new-neighbour ratio": "2.0", "port diversity": "1.0", "betweenness": "0.5", "community change": "1.0"}
add('''<section class="pb"><h2>3 · System architecture and algorithms</h2>%s<p class="cap">Figure 1. The data path, labelled with the Review 1 algorithm letters. Both detectors read the same windows. In a given mitigation trial only one is allowed to actuate.</p>%s<p class="cap">Figure 2. Physical testbed: Mininet hosts, Open vSwitch with OpenFlow 1.3, and one Ryu 4.34 controller. All attack generators run on h4.</p>
<div class="cols"><div><h3>Algorithm B · threshold baseline</h3><p>Per source (or source–destination pair) in each window:</p><ul><li>Port scan: &gt; %d distinct destination ports, or &gt; %d hosts</li><li>DoS: &gt; %d packets/s to one destination, sustained for two windows</li><li>SYN retry: &gt; %d connection attempt to an authentication port</li></ul><p>Thresholds = ⌈1.25 × max normal-only calibration value + 1⌉, frozen before any attack run.</p></div>
<div><h3>Algorithm C · graph detector</h3><p>A host graph G<sub>t</sub> per window. Each host's features are compared with its own rolling profile:</p><p class="formula">S(h,t) = Σ w<sub>i</sub> · clamp(z<sub>i</sub>(h,t), 6)</p><p>Weights: %s. EWMA α = 0.2. Alert if S &gt; %d. The class is <i>lateral</i> when new-neighbour ratio ≥ 0.3, otherwise a generic <i>graph anomaly</i>. Community change compares peer sets, not labels.</p></div></div>
<h3>Decision and Algorithm D · mitigation</h3><p>Candidates are logged before a 30 s cooldown, and only post-cooldown alerts reach the decision manager. Lateral and scan labels map to a <b>source-wide</b> drop (<code>ipv4_src=h4</code>). DoS and SYN-retry labels map to a <b>pair</b> drop on the named victim and port. Generic graph anomalies are <b>logged only</b>. Rules use priority 100 over forwarding priority 1, a 30 s idle timeout and no hard timeout. Each FlowMod is followed by a barrier request, and the barrier reply is treated as confirmation.</p></section>''' % (svg_pipeline(), svg_topology(), TH["PORTSCAN_PORTS"], TH["PORTSCAN_HOSTS"], TH["DOS_PPS"], TH["BRUTEFORCE_ATTEMPTS"], ", ".join("%s %s" % (k, v) for k, v in w.items()), TH["GRAPH_SCORE_THRESHOLD"]))

add('<section><h2>4 · Experimental design and calibration</h2>%s<p>Total: 95 evaluation trials plus 4 supplementary runs. All 99 passed validity on the first attempt. Detection misses and false positives count as outcomes, not validity failures. Every trial ran in a fresh isolated container (<code>--network none</code>). Trial seeds 20100–20500 are shared across corresponding conditions.</p>%s<p>Warmup is 135 s: 120 s of profiling plus a 15 s allowance. Calibration observed 600 s of normal-only traffic per trial, with the background rate doubling halfway through. Real HTTP probes run every 2 s from h1–h4 to the server.</p></section>' % (
    table(["Group", "Conditions", "Runs"], [["Detection", "C1–C7, mitigation disabled, 5 repeats", "35"], ["Mitigation", "C2–C6, baseline and graph actuating separately, 5 each", "50"], ["Benign variation", "Scheduled legitimate peer changes, no actuation", "5"], ["Order check", "C7 with reversed attack order, no actuation", "5"], ["Calibration (suppl.)", "Normal only", "3"], ["Pilot (suppl.)", "Execution/runtime check", "1"]]),
    table(["Case", "Review 1 intent", "Configured workload"], [["C1", "Normal only (FPR)", "Synthetic exchanges plus real HTTP probes"], ["C2", "Port scan", "TCP SYN sweep across 83 ports, 0.05 s spacing"], ["C3", "Controlled DoS", "Generator configured for 1,500 packets/s for 20 s"], ["C4", "Brute force", "60 repeated SYN attempts to an auth port (no password guessing)"], ["C5", "Lateral movement", "Sequential contact to h1, h2, h3, h5, server; 4 s dwell, 3 packets each"], ["C6", "Mixed normal + attack", "Sequential contact then scan; normal rate raised to 3 exchanges/s"], ["C7", "Baseline vs graph on identical traffic", "Sequential contact → scan → SYN retry (DoS tested separately in C3)"]])))

add('''<section><h2>5 · Reading the results: four levels of evidence</h2><p>The project's main methodological rule is that each stage of the response needs its own evidence. A detector flagging a host does not mean the right attack was recognised, and a switch acknowledging a rule does not mean traffic stopped.</p>
<ol class="ladder"><li><b>Candidate</b><span>The detector's per-window output, before cooldown. Attributed to an attack only when it comes from the attack source and its window overlaps the attack's send interval. If it overlaps several attacks it is <i>ambiguous</i> and credited to none.</span></li>
<li><b>Class-exact identification</b><span>An attributed candidate that also names the correct attack type.</span></li>
<li><b>Confirmed rule</b><span>Every switch targeted by the actuating decision has returned a barrier reply for that decision.</span></li>
<li><b>Verified block</b><span>Requires at least 3 s of malicious sends after confirmation, positive matching drop counters, and receiver counts that stay flat for at least 2 samples at every target. Anything less is recorded as <i>unverified</i>, which means insufficient evidence rather than proof that nothing was dropped.</span></li></ol>
<p>Coverage uses Wilson 95%% intervals. With five trials, 5/5 gives 56.6–100%% and 0/5 gives 0–43.4%%, so only all-or-nothing contrasts are clearly separable. Host-windows and multiple attacks within one run are dependent, so pooled figures are descriptive. Timing and overhead use per-trial means with equal weighting.</p></section>''')

rows = []
for a in ATTACKS:
    rb, rg = P(a, "baseline"), P(a, "graph")
    rows.append(["<b>%s</b>" % NAMES[a],
                 chip(rb["detected"] == 5, "source %d/5" % rb["detected"]) + chip(rb["class_exact"] == 5, "class %d/5" % rb["class_exact"]),
                 f(rb["mttd_mean"]),
                 chip(rg["detected"] == 5, "source %d/5" % rg["detected"]) + chip(rg["class_exact"] == 5 if rg["detected"] else False, "class %d/5" % rg["class_exact"]),
                 f(rg["mttd_mean"])])
why = [
    ["Port scan (C2)", "Both detected h4. The graph's alert was a generic <i>graph anomaly</i> (score ≈ 7.8 against a threshold of 6; 84 ports, only 2 hosts), because the new-neighbour ratio stayed below 0.3. That label is log-only, so the graph never acted on scans (0/5 confirmed)."],
    ["DoS (C3)", "This is a single-pair flood with no new peers and no structural change. Packet volume carries only weight 0.3 and is clamped, so the graph produced no candidates. The baseline needs two windows above 21 packets/s, which accounts for its ≈ 18.7 s delay."],
    ["SYN retry (C4)", "Repeated attempts to one known peer change neither degree nor neighbour set, so the graph produced no candidates. The baseline's SYN-retry threshold is a single attempt, the most sensitive rule in the set."],
    ["Sequential contact (C5)", "In C5 mitigation trial 1 (Section 7) h4 contacted 4 hosts in one window (6 ports, 50%% new neighbours) and scored %.2f against a threshold of 6. The baseline saw h4 too, but its first rule to fire was SYN retry, because one of the contacts was a SYN to h1:22." % gc["score"]],
]
add('<section class="pb"><h2>6 · Detection results</h2><p>Primary cohort: one attack per run, five mitigation-disabled trials per attack class.</p>%s%s<p class="cap">Figure 3. Source-identification coverage with Wilson 95%% intervals (grey: baseline, blue: graph). The right-hand column shows class-exact outcomes. Source: coverage.csv.</p><h3>Why each outcome happened</h3><p>These explanations come from the recorded candidate reasons and evidence fields. They are interpretations, not feature ablations.</p>%s<h3>Mixed and pooled cohorts</h3>%s<p>In the multi-attack runs (C6, C7) the graph found sequential contact every time (10/10) but caught scans less often (4/10) than the baseline (7/10). Earlier attacks in the same run shift the adaptive profiles.</p></section>' % (
    table(["Attack", "Baseline (B)", "Mean delay s", "Graph (C)", "Mean delay s"], rows), svg_coverage(), table(["Case", "Mechanism observed in the logs"], why),
    table(["Cohort", "Attack", "Baseline", "Graph"], [[c, NAMES[a]] + ["%s/%s" % (r["detected"], r["instances"]) for d in ("baseline", "graph") for r in T["coverage"] if r["phase"] == "detection" and r["cohort"] == c and r["attack_class"] == a and r["detector"] == d] for c in ("mixed", "pooled") for a in ATTACKS if any(r["cohort"] == c and r["attack_class"] == a for r in T["coverage"])])))

bc = B["cand"]["baseline"]
add('''<section class="pb"><h2>7 · Worked example: C5, trial 1</h2><p>The same attack is shown under both actuators. Times are seconds from the first malicious send.</p>%s<p class="cap">Figure 4. C5 trial 1 with the graph actuating. Detection waits for the window to close, and confirmation then follows within milliseconds. Source: mitigation-C5-graph_trial01.jsonl.</p>
<div class="cols"><div><h3>Graph actuating</h3><ul><li>Candidate at <b>%.3f s</b>: <i>lateral</i>, score <b>%.2f</b> (threshold %d)</li><li>Largest score contributions: degree %.2f, port diversity %.2f, new-neighbour ratio %.2f</li><li>Decision <code>drop_source</code>, match <code>%s</code></li><li>Both switches confirmed %.1f ms after the decision</li><li>%.1f s of attack traffic remained after confirmation. Published assessment: <b>%s</b></li></ul></div>
<div><h3>Baseline actuating</h3><ul><li>Candidate at <b>%.3f s</b>: <i>%s</i> ("%s")</li><li>Decision <code>drop_pair</code>, match <code>%s</code></li><li>Both switches confirmed %.1f ms after the decision</li><li>Contacts to h2, h3, h5 and the server do not match the rule. Published assessment: <b>%s</b></li><li>The same pattern held in all 5 baseline C5 trials: the first actuating decision was always this SYN-retry pair drop</li></ul></div></div>
<p>This example shows the project's central finding in one run. Both detectors spotted h4 within the same window and at the same speed. The <b>class</b> decided whether the response contained the whole behaviour or only one conversation.</p></section>''' % (
    svg_example(), G["at"](gc), gc["score"], TH["GRAPH_SCORE_THRESHOLD"], contrib["degree"], contrib["port_diversity"], contrib["new_neighbour_ratio"], G["match"],
    (G["at"](G["replies"][-1]) - G["at"](G["dec"])) * 1000, G["last"] - G["at"](G["replies"][-1]), G["block"],
    B["at"](bc), NAMES.get(bc["attack_class"], bc["attack_class"]), escape(bc["reason"]), B["match"], (B["at"](B["replies"][-1]) - B["at"](B["dec"])) * 1000, B["block"]))

fprows = [[ph, d, "%d/%d" % (FP(ph, d)["flagged"], FP(ph, d)["eligible"]), pct(FP(ph, d)["flagged"], FP(ph, d)["eligible"]), FP(ph, d)["candidates"], FP(ph, d)["alerts"], FP(ph, d)["ambiguous"]] for ph in ("detection", "benign", "order") for d in ("baseline", "graph")]
add('<section><h2>8 · False alarms and attack-order effects</h2>%s<p class="cap">Figure 5. Benign peer-variation runs: share of eligible host-windows with at least one candidate.</p>%s<p>Detection rows pool the eligible benign windows from C1–C7. Benign rows are the changed peer workload, and order rows are reversed C7. In the detection-only runs, every attributable candidate matched a real attack (candidate precision 100%% for both detectors: %d and %d matched, with %d and %d ambiguous). Cooldown cuts operational alerts, but the candidate count is what the false-positive rate measures.</p><h3>Reversed attack order</h3><p>The primary C7 order is sequential contact → scan → SYN retry. Reversed (SYN retry → scan → sequential contact), both detectors still found sequential contact in 5/5 trials, but <b>neither found the scan or the SYN retry</b>. Most baseline candidates overlapped several attacks and were not credited (%d of %d ambiguous). Because the profiles keep learning, accuracy depends on order. This is a design limitation, not a validity failure.</p></section>' % (
    svg_bars([("Threshold baseline", FP("benign", "baseline")["flagged"] / 273, "base", "%s  (30/273)" % pct(30, 273)), ("Graph detector", FP("benign", "graph")["flagged"] / 273, "graph", "%s  (14/273)" % pct(14, 273))], 0.15, lambda v: "15%"),
    table(["Phase", "Detector", "Flagged windows", "Rate", "Candidates", "Alerts", "Ambiguous"], fprows), FP("detection", "baseline")["matched"], FP("detection", "graph")["matched"], FP("detection", "baseline")["ambiguous"], FP("detection", "graph")["ambiguous"], FP("order", "baseline")["ambiguous"], FP("order", "baseline")["candidates"]))

mrows = []
for case in ["C2", "C3", "C4", "C5", "C6"]:
    for d in ("baseline", "graph"):
        rr = [r for r in T["containment"] if r["phase"] == "mitigation" and r["case"] == case and r["mitigator"] == d]
        v = [float(r["rule_confirmation_delay"]) for r in rr if r["rule_confirmation_delay"]]
        mrows.append([case, d, len(rr), len(v), sum(r["observed_blocking"] == "verified" for r in rr), f(st.mean(v)) if v else "—"])
drow = []
for d in ("baseline", "graph"):
    for g, gl in (("innocent", "Innocent (h1–h3)"), ("compromised", "Attack source (h4)")):
        cells = []
        for p in ("attack", "recovery"):
            r = DL("%s|%s|%s" % (d, g, p))
            cells.append(chip(r["successes"] == r["attempts"] if g == "innocent" else None, pct(r["successes"], r["attempts"])) + " %d/%d" % (r["successes"], r["attempts"]))
        drow.append([d, gl] + cells)
add('<section class="pb"><h2>9 · Mitigation and legitimate delivery</h2>%s<p class="cap">Figure 6. Out of 30 attack records per actuator (C6 has two attacks per run).</p>%s<p><b>Why baseline rules were never verified.</b> The baseline’s actuating rules were pair drops on its first label in C2–C6 (SYN retry or DoS). In C3 and C4 the pair rule matches the attack, but the remaining evidence criteria were not all met. In C5 and C6 the pair rule targets h1:22 while the sequential contacts go elsewhere. <b>Why graph confirmations are confined to C5/C6.</b> The graph raised no candidates in C3/C4, and its C2 scan label is log-only. Where it did act, all 10 confirmed rules also passed the independent blocking test. Mean attack-start-to-confirmation was %.2f s for the graph and %.2f s for the baseline (the baseline mean is pulled up by C3’s two-window DoS rule).</p>%s<p>Innocent clients completed <b>every</b> measured HTTP request during the attack and recovery periods under both actuators. Because the drops are source-wide, legitimate requests from h4 also failed, and continued h4 traffic can keep refreshing a 30 s idle-timeout rule. That is why the graph run shows 39.9%% recovery-period failures for h4. Appendix B lists success latencies.</p></section>' % (
    svg_bars([("Baseline · confirmed", mb["confirmed"], "base", "%d/30" % mb["confirmed"]), ("Baseline · verified", mb["verified"], "good", "%d/30" % mb["verified"]), ("Graph · confirmed", mg["confirmed"], "graph", "%d/30" % mg["confirmed"]), ("Graph · verified", mg["verified"], "good", "%d/30" % mg["verified"])], 30, lambda v: "30 records"),
    table(["Case", "Actuator", "Records", "Confirmed", "Verified", "Mean start→confirm s"], mrows), mg["delay"]["mean"], mb["delay"]["mean"], table(["Actuator", "HTTP clients", "During attack", "Recovery"], drow)))

crow = []
for key, title, unit in [("cpu_percent", "Controller CPU", "%"), ("rss_mib", "Controller RSS", "MiB"), ("baseline_ms", "Baseline compute / window", "ms"), ("graph_ms", "Graph compute / window", "ms"), ("graph_build_ms", " · graph build", "ms"), ("betweenness_ms", " · betweenness", "ms"), ("peak_entries", "Peak software flow entries", "entries")]:
    s_ = cost[key]
    crow.append([title, s_["n"], "%.2f %s" % (s_["mean"], unit), "%.2f" % s_["median"], "%.2f–%.2f" % (s_["min"], s_["max"])])
trow = [[c, d, lab, O["timing"]["%s|%s|%s" % (c, d, k)]["n"], f(tm("%s|%s|%s" % (c, d, k)))] for c in ("C5",) for k, lab in (("alert_to_decision", "Alert → decision"), ("decision_to_confirmation", "Decision → all switches"), ("flowmod_to_confirmation", "FlowMod → barrier")) for d in ("baseline", "graph")]
add('<section><h2>10 · Controller cost and rule latency</h2>%s<p class="cap">Figure 7. Mean computation per 10 s window over 35 detection-only runs (evaluation period, per-run means).</p>%s<p>The graph costs %.0f–%.0f× the baseline per condition (mean of per-run ratios, Appendix B), yet even at its maximum it uses well under 0.1%% of a window. The C3 rows reflect the DoS load: CPU ≈ 10%% and RSS ≈ 121 MiB, against ≈ 1.7%% and 65 MiB elsewhere. Peak entries are sampled software occupancy, not hardware TCAM.</p><h3>Rule timing</h3>%s<p>C5 rows shown; all conditions are in timing_summary.csv. In C5, a decision follows an alert within about 2 ms, and both switches confirm about 11 ms later. Under the C3 flood, baseline decision → all-switch confirmation took %.0f ms (FlowMod → barrier %.0f ms) because the switches and controller were busy. The end-to-end delay is therefore dominated by the observation window rather than by computation or rule installation.</p></section>' % (
    svg_bars([("Threshold baseline", cost["baseline_ms"]["mean"], "base", "%.2f ms" % cost["baseline_ms"]["mean"]), ("Graph detector", cost["graph_ms"]["mean"], "graph", "%.2f ms" % cost["graph_ms"]["mean"]), ("  · betweenness", cost["betweenness_ms"]["mean"], "graph lite", "%.2f ms" % cost["betweenness_ms"]["mean"]), ("  · graph build", cost["graph_build_ms"]["mean"], "graph lite", "%.2f ms" % cost["graph_build_ms"]["mean"])], 1.6, lambda v: "1.6 ms"),
    table(["Measurement", "Runs", "Mean", "Median", "Range"], crow), min(ratios.values()), max(ratios.values()), table(["Case", "Actuator", "Metric", "n", "Mean ms"], trow), tm("C3|baseline|decision_to_confirmation"), tm("C3|baseline|flowmod_to_confirmation")))

add('''<section class="pb"><h2>11 · Research questions answered</h2>
<div class="qa"><p class="q">Central question: does graph analysis improve lateral-movement detection over a per-flow detector while keeping latency and disruption acceptable?</p><p><b>Partly yes.</b> It improves <i>classification</i> of lateral movement (5/5 vs 0/5) and, through that, <i>containment</i> (10/30 verified vs 0/30). It does not improve <i>source detection</i>, because the baseline found h4 too. Latency (≈ 11 ms to confirm in C5) and innocent-client disruption (0 failed requests) were both acceptable in this testbed.</p></div>
<div class="qa"><p class="q">Q1 · Can the system detect port scans, DoS, brute force and lateral movement?</p><p>Yes, as a combined system. The baseline detected all four primary classes in 5/5 trials. The graph detected only scan and sequential contact.</p></div>
<div class="qa"><p class="q">Q2 · Does graph analysis detect internal propagation that per-flow features miss?</p><p>Not the <i>source</i>, which the baseline also identified, but the <i>pattern</i>: only the graph recognised it as lateral. Review 1 expected per-flow detection to miss this traffic entirely. That did not happen here, because the sequential contacts tripped other per-flow rules.</p></div>
<div class="qa"><p class="q">Q3 · How quickly can the controller install a mitigation rule once an alert fires?</p><p>Alert → decision ≈ %.1f ms; decision → all switches ≈ %.1f ms (C5, graph); per-rule FlowMod → barrier ≈ %.1f ms. Under DoS load, about 450 ms.</p></div>
<div class="qa"><p class="q">Q4 · What does graph detection cost in CPU and flow-table usage?</p><p>%.2f ms per window (vs %.2f ms baseline), %.2f%% mean controller CPU and %.0f MiB RSS for the whole application, with about %.0f peak software entries. All of these are small at six hosts. Scaling was not tested (Gap 5).</p></div></section>''' % (
    tm("C5|graph|alert_to_decision"), tm("C5|graph|decision_to_confirmation"), tm("C5|graph|flowmod_to_confirmation"), cost["graph_ms"]["mean"], cost["baseline_ms"]["mean"], cost["cpu_percent"]["mean"], cost["rss_mib"]["mean"], cost["peak_entries"]["mean"]))

add('''<section><h2>12 · Limitations, threats to validity and future work</h2><div class="cols"><div><h3>Threats to validity</h3><ul>
<li><b>Small n:</b> five repeats per condition give wide intervals, and only all-or-nothing contrasts are clear.</li>
<li><b>Dependence:</b> host-windows and multi-attack runs share adaptive profiles, so pooled rates are descriptive.</li>
<li><b>One topology:</b> six hosts, two switches and a narrow synthetic workload family.</li>
<li><b>Simulated attacks:</b> the DoS is a packet generator, SYN retry is not password guessing, and sequential contact is not real host compromise or propagation.</li>
<li><b>No ablation:</b> the run does not show which graph feature produced the gain.</li>
<li><b>Measurement proxies:</b> receiver sampling is not a lossless trace, and software flow entries are not TCAM.</li>
<li><b>Calibration sensitivity:</b> a SYN-retry threshold of 1 makes the baseline very sensitive, which is part of why C5 was visible to it.</li></ul></div>
<div><h3>Future work, from Review 1 and these findings</h3><ul>
<li><b>Hybrid decision:</b> combine baseline breadth with graph class. For example, let a lateral graph label override the baseline's pair rule for the same source.</li>
<li><b>Graph coverage of volumetric attacks:</b> add edge-rate features, or route DoS and SYN retry to the threshold path.</li>
<li><b>Order robustness:</b> freeze or gate profile updates while a source is under alert.</li>
<li><b>Gap 5 scalability:</b> larger topologies and distributed or multi-controller graph computation.</li>
<li><b>Adversarial robustness:</b> slow, low-fan-out lateral movement designed to evade the new-neighbour signal.</li>
<li><b>Tier 3:</b> ML baseline, Suricata signatures and redirection to a quarantine host.</li></ul></div></div></section>''')

add('''<section class="pb"><h2>13 · Verification and reproduction</h2>%s<h3>Commands</h3><pre>make build &amp;&amp; make validate &amp;&amp; make verify      # clean checkout
make plan
make campaign CAMPAIGN=results/campaigns/new-replication
make analyze  CAMPAIGN=results/campaigns/new-replication
python3 -m replay serve --port 8000                # interactive evidence replay
python3 -m replay.report                           # regenerate this report</pre><p>Docker is required. Network experiments also need privileged namespaces. Unit tests and analysis do not.</p><h3>Evidence locator</h3><p>All CSVs are under <code>submission/tables/</code>: coverage, attacks, detections, containment, disruption, overhead, timing, timing_summary, validity and evidence_map. Raw controller, truth, probe and receiver logs are under <code>submission/evidence/</code>. Provenance is in manifest.json, calibration.json, thresholds.json, source.sha256 and checksums.json.</p></section>''' % table(["Check", "Recorded status"], [["Research unit/regression suite", "67 passing tests (docs/results.md)"], ["Live forwarding gate", "30/30 datapath pings"], ["Live service integration", "13 checks: forwarding, source/pair drop, unaffected clients, idle-expiry recovery"], ["Campaign validity", "99/99 valid; all 95 evaluation conditions covered"], ["Evidence integrity", "All %d curated checksums re-verified while building this report" % len(checks)], ["Replay viewer", "17 Python tests + 20 state assertions"]]))

arow = [[r["case"], r["trial"], chip(r["baseline_detected"] == "True", "ID") + chip(r["baseline_class_exact"] == "True", "class"), f(r["baseline_mttd"]), chip(r["graph_detected"] == "True", "ID") + chip(r["graph_class_exact"] == "True", "class") if r["graph_detected"] == "True" else chip(False, "missed"), f(r["graph_mttd"])] for r in T["attacks"] if r["phase"] == "detection" and r["case"] in ("C2", "C3", "C4", "C5")]
add('<section class="appendix pb"><h2>Appendix A · Primary per-trial detection</h2><p>All 20 primary detection-only attack instances. "—" means the attack was missed, which is not the same as zero delay. Source: attacks.csv.</p>%s</section>' % table(["Case", "Trial", "Baseline", "Delay s", "Graph", "Delay s"], arow, "dense"))

lrow = []
for d in ("baseline", "graph"):
    for g in ("compromised", "innocent"):
        for p in ("pre_attack", "attack", "recovery"):
            vals = [float(r["mean_success_latency"]) * 1000 for r in T["disruption"] if r["phase"] == "mitigation" and r["mitigator"] == d and r["group"] == g and r["period"] == p and r["mean_success_latency"]]
            lrow.append([d, "Attack source" if g == "compromised" else "Innocent", p.replace("_", " "), len(vals), f(st.mean(vals)) if vals else "—", f(st.median(vals)) if vals else "—", "%s–%s" % (f(min(vals)), f(max(vals))) if vals else "—"])
orow = []
for case in ["C%d" % i for i in range(1, 8)]:
    rr = [r for r in T["overhead"] if r["phase"] == "detection" and r["case"] == case and r["period"] == "evaluation"]
    mean = lambda k: st.mean(float(r[k]) for r in rr)
    orow.append([case, f(mean("cpu_percent_mean")), f(mean("rss_bytes_mean") / 1048576), f(mean("baseline_seconds_mean") * 1000), f(mean("graph_total_seconds_mean") * 1000), f(ratios[case])])
add('<section class="appendix"><h2>Appendix B · Delivery latency and per-condition cost</h2><p>Means of per-trial mean successful-response latency (failed requests excluded). A trial with no successful request cannot contribute.</p>%s<h3>Detection computation by condition</h3>%s<p>Five run means per row. The cost ratio is the mean of per-run graph/baseline ratios, not a ratio of grand means.</p></section>' % (table(["Actuator", "Clients", "Period", "Trials", "Mean ms", "Median ms", "Range ms"], lrow, "dense"), table(["Case", "CPU %", "RSS MiB", "Baseline ms", "Graph ms", "Cost ratio"], orow, "dense")))

add('<section class="appendix pb"><h2>Appendix C · Provenance</h2>%s<p>NetworkX 2.6.3 uses the implemented greedy-modularity fallback. Because the experimental source had uncommitted changes when the campaign was created, the manifest records both the Git revision and per-file content hashes.</p>%s<p class="note">This is an empirical results report built on the Review 1 literature survey (29 references, as presented). It makes no claim that graph-based detection is new in the wider literature.</p></section>' % (
    table(["Component", "Version"], [["Ryu", "4.34"], ["Mininet", "2.3.0"], ["Open vSwitch", "2.13.8"], ["NetworkX", "2.6.3"], ["Scapy", "2.5.0"], ["pytest", "7.4.4"], ["Container Python", "3.8.10"], ["Host", "macOS 26.1 arm64, Docker"]]),
    table(["Identifier", "Value"], [["Manifest revision", "<code>%s</code>" % M["revision"]], ["Frozen source aggregate", "<code>%s</code>" % M["source_hash"]], ["Container image", "<code>%s</code>" % M["image_id"]], ["checksums.json SHA-256", "<code>%s</code>" % hashlib.sha256((E / "checksums.json").read_bytes()).hexdigest()]], "ids")))

CSS = """
@page{size:A4;margin:16mm 15mm 18mm;@bottom-left{content:"Lantern · Graph-based SDN IDS · Final results";font:8pt system-ui;color:#7a838a}@bottom-right{content:counter(page);font:8pt system-ui;color:#7a838a}}
@page:first{@bottom-left{content:none}@bottom-right{content:none}}
:root{--ink:#1d2328;--muted:#5f6870;--line:#dfe2e4;--soft:#f3f4f2;--base:#6b7680;--graph:#2a78d6;--good:#1f7a4d;--goodbg:#e4f3ea;--bad:#c23a3a;--badbg:#fbe5e3;--warn:#a36200;--warnbg:#fbefd9;--atk:#d97a2b}
*{box-sizing:border-box}body{margin:0;color:var(--ink);font:9.6pt/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;-webkit-print-color-adjust:exact;print-color-adjust:exact}
section{margin-top:9mm}section.pb{break-before:page;margin-top:0}h2,h3{break-after:avoid}svg.fig,.findings,.cols,.ladder{break-inside:avoid}
h1{font-size:25pt;line-height:1.15;letter-spacing:-.4px;margin:6mm 0 4mm}h2{font-size:15pt;margin:0 0 3mm;letter-spacing:-.2px}h3{font-size:10.5pt;margin:5mm 0 1.5mm;color:#204d80}
p{margin:0 0 2.6mm}ul,ol{margin:0 0 3mm;padding-left:5mm}li{margin-bottom:1mm}code,pre{font:8.3pt ui-monospace,SFMono-Regular,Menlo,monospace}pre{background:var(--soft);padding:3mm;border-radius:2mm;white-space:pre-wrap}
.kicker{font-size:8.5pt;letter-spacing:.8px;text-transform:uppercase;color:var(--muted);margin-top:18mm}.sub{font-size:11.5pt;color:var(--muted);max-width:165mm}
.kpis{display:grid;grid-template-columns:repeat(3,1fr);gap:3mm;margin:9mm 0}.kpis div{border:1px solid var(--line);border-radius:3mm;padding:3.5mm 4mm}.kpis b{display:block;font-size:17pt;letter-spacing:-.3px}.kpis span{font-size:8.3pt;color:var(--muted)}
.meta{width:100%;border-collapse:collapse;margin-top:4mm}.meta td{padding:2mm 0;border-bottom:1px solid var(--line);vertical-align:top}.meta td:first-child{width:30mm;color:var(--muted)}
.toc{margin-top:8mm;font-size:8.8pt;color:var(--muted)}
.lead{font-size:10.5pt}.findings{display:grid;grid-template-columns:1fr 1fr;gap:3mm;margin:4mm 0}.f{border:1px solid var(--line);border-left:3px solid var(--base);border-radius:2mm;padding:3mm 3.5mm;break-inside:avoid}.f.good{border-left-color:var(--good)}.f.warn{border-left-color:var(--warn)}.f b{display:block;margin-bottom:1mm}.f p{margin:0;font-size:9pt}
.note{font-size:8.6pt;color:var(--muted);border-top:1px solid var(--line);padding-top:2mm}
table{width:100%;border-collapse:collapse;margin:2mm 0 4mm;font-size:8.8pt;break-inside:auto}th{text-align:left;font-weight:600;font-size:8pt;color:var(--muted);border-bottom:1.2px solid #204d80;padding:1.6mm 1.8mm}td{border-bottom:1px solid var(--line);padding:1.6mm 1.8mm;vertical-align:top}tr{break-inside:avoid}
table.dense td{padding:1mm 1.8mm}table.trace td:first-child{width:52mm;font-weight:500}table.trace td:nth-child(2){width:24mm}table.ids code{word-break:break-all}
.chip{display:inline-block;font-size:7.8pt;font-weight:600;border-radius:9pt;padding:.3mm 2mm;margin:0 1mm .5mm 0;white-space:nowrap}.chip.ok{background:var(--goodbg);color:var(--good)}.chip.no{background:var(--badbg);color:var(--bad)}.chip.mid{background:var(--warnbg);color:var(--warn)}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:6mm}.formula{font:10pt "Times New Roman",serif;background:var(--soft);padding:2mm 3mm;border-radius:2mm;text-align:center}
.cap{font-size:8.2pt;color:var(--muted);margin-top:-1mm}
.ladder{list-style:none;padding:0;counter-reset:l;display:grid;gap:2.5mm}.ladder li{counter-increment:l;display:grid;grid-template-columns:42mm 1fr;gap:3mm;border:1px solid var(--line);border-radius:2mm;padding:2.5mm 3mm}.ladder b:before{content:counter(l) " · ";color:var(--graph)}.ladder span{font-size:9pt;color:var(--muted)}
.qa{border:1px solid var(--line);border-radius:2mm;padding:3mm 4mm;margin-bottom:3mm;break-inside:avoid}.qa .q{font-weight:600;color:#204d80;margin-bottom:1mm}.qa p:last-child{margin:0}
svg.fig{width:100%;height:auto;display:block;margin:2mm 0 3mm}
.fig text{font-family:system-ui,-apple-system,sans-serif}.bt{font-size:11px;font-weight:600;fill:var(--ink);text-anchor:middle}.bs{font-size:9px;fill:var(--muted);text-anchor:middle}
.bx{fill:#fff;stroke:#a9b1b8}.bx.base{fill:#eef0f2;stroke:var(--base)}.bx.graph{fill:#e6f0fb;stroke:var(--graph)}.bx.act{fill:#fbe5e3;stroke:var(--bad)}.bx.dim{fill:var(--soft);stroke:var(--line)}
.ar{stroke:#7a838a;stroke-width:1.3;fill:none;marker-end:none}.ar.dash{stroke-dasharray:4 3}.ln{stroke:#c9ced2;stroke-width:1.6}.nd{fill:#fff;stroke:#a9b1b8;stroke-width:1.4}.nd.atk{fill:#fdf1e6;stroke:var(--atk)}
.lt{font-size:11px;fill:var(--ink)}.ls{font-size:9.5px;fill:var(--muted)}.lv{font-size:10.5px;font-weight:600;fill:var(--ink)}.grid{stroke:#e8eaeb;stroke-width:1}
.ci{stroke-width:2.2}.ci.base{stroke:var(--base)}.ci.graph{stroke:var(--graph)}.pt.base{fill:var(--base)}.pt.graph{fill:var(--graph)}.pt.dim{fill:#a9b1b8}
.trk{fill:var(--soft)}rect.base{fill:var(--base)}rect.graph{fill:var(--graph)}rect.graph.lite{fill:#86b6ef}rect.good{fill:var(--good)}rect.atk{fill:#fbe3cc;stroke:var(--atk)}
.appendix h2{font-size:13pt}
"""

OUT_DIR.mkdir(parents=True, exist_ok=True)
HTML.write_text('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Lantern · Final results report</title><style>%s</style></head><body>%s</body></html>' % (CSS, "\n".join(S)))
chrome = CHROME if Path(CHROME).exists() else shutil.which("google-chrome") or shutil.which("chromium")
if not chrome:
    sys.exit("HTML written to %s; install Chrome/Chromium to print the PDF." % HTML)
subprocess.run([chrome, "--headless", "--disable-gpu", "--no-pdf-header-footer", "--print-to-pdf=%s" % PDF, HTML.as_uri()],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(PDF)
