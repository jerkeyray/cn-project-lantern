#!/usr/bin/env bash
#
# Run an experiment sweep with one fresh container per run.
#
# The obvious design -- loop over every run inside a single long-lived
# container -- does not survive a sweep of this length. Each trial starts and
# tears down a Mininet topology, and after a couple of dozen cycles the
# container's networking state degrades: traffic generators are starved, the
# PacketIn rate collapses by an order of magnitude, and runs stop producing
# enough windows for the graph detector to finish profiling. In one 29-run
# sweep the last four runs never left warmup at all, while every early run was
# healthy -- a failure that quietly turns into "the detector missed it" in the
# results rather than into an error.
#
# So the loop lives here, on the host, and every run gets a clean container.
# That also makes true the claim run_case.py's docstring already made: that
# each trial is a complete, independent run.
#
# Usage:
#   scripts/run_sweep.sh [--trials N] [--mitigation-trials N] [--cases C1 C5]
#   scripts/run_sweep.sh --skip-mitigation --trials 3

set -uo pipefail

IMAGE="${IMAGE:-lantern-sdn-ids}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${LOG_DIR:-$REPO/results/raw}"

DOCKER_RUN=(docker run --rm --privileged --network none -v "$REPO:/opt/lantern" "$IMAGE")

mkdir -p "$LOG_DIR"

echo "planning sweep..."
PLAN="$("${DOCKER_RUN[@]}" python3 experiments/run_all.py --emit-plan "$@" 2>/dev/null | grep -E '^[A-Za-z0-9_.-]+\|')"

if [ -z "$PLAN" ]; then
    echo "could not produce a plan; check the arguments" >&2
    exit 1
fi

TOTAL=$(echo "$PLAN" | wc -l | tr -d ' ')
echo "$TOTAL run(s), each in its own container"
echo

STARTED=$(date +%s)
INDEX=0
FAILED=0
FAILED_RUNS=()

while IFS='|' read -r CASE LABEL TRIAL MITIGATOR; do
    [ -z "$CASE" ] && continue
    INDEX=$((INDEX + 1))
    ELAPSED=$(( ($(date +%s) - STARTED) / 60 ))
    echo "[$INDEX/$TOTAL] ${ELAPSED}min elapsed  ->  $LABEL trial $TRIAL (mitigator=$MITIGATOR)"

    mkdir -p "$LOG_DIR"
    if ! "${DOCKER_RUN[@]}" python3 experiments/run_case.py \
            --case "$CASE" \
            --label "$LABEL" \
            --trial "$TRIAL" \
            --mitigator "$MITIGATOR" \
            >> "$LOG_DIR/sweep_driver.log" 2>&1; then
        echo "    RUN FAILED: $LABEL trial $TRIAL (see $LOG_DIR/sweep_driver.log)"
        FAILED=$((FAILED + 1))
        FAILED_RUNS+=("$LABEL trial $TRIAL")
    fi
done <<< "$PLAN"

echo
echo "sweep finished in $(( ($(date +%s) - STARTED) / 60 )) min"
if [ "$FAILED" -gt 0 ]; then
    echo "$FAILED run(s) failed:"
    for RUN in "${FAILED_RUNS[@]}"; do echo "  $RUN"; done
    exit 1
fi
echo "Analyse with: make analyze"
