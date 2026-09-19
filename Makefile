# Lantern — Graph-Based SDN Controller-Integrated IDS
#
# Every target runs inside the container; nothing in this project runs natively
# on macOS (no Mininet, no Open vSwitch, no Python 3.8).

IMAGE   := lantern-sdn-ids
CASE    ?= C1
TRIALS  ?= 1

# --privileged is required: Mininet creates network namespaces and veth pairs,
# and ovs-vswitchd needs to manipulate interfaces.
#
# --network none is deliberate: the experiment must not be able to reach, or be
# reached from, anything outside the container.
#
# No TTY is allocated for batch targets -- `docker run -it` fails outright when
# stdin is not a terminal, which would make `make test` unusable from a script
# or from CI. Only `make shell` asks for one.
DOCKER_BASE := docker run --rm --privileged \
	--network none \
	-v $(PWD):/opt/lantern \
	$(IMAGE)

DOCKER_RUN := $(DOCKER_BASE)
DOCKER_INTERACTIVE := docker run --rm -it --privileged \
	--network none \
	-v $(PWD):/opt/lantern \
	$(IMAGE)

.PHONY: build shell test datapath-check run-case run-all plan analyze clean clean-mn

build:
	docker build -f docker/Dockerfile -t $(IMAGE) .

shell: build
	$(DOCKER_INTERACTIVE) bash

## Unit tests only — no Mininet, no root networking, runs in seconds.
test: build
	$(DOCKER_RUN) python3 -m pytest tests/ -v

## Verification gate 1: does the userspace datapath work under this kernel?
datapath-check: build
	$(DOCKER_RUN) python3 topo/lantern_topo.py --self-test

run-case: build
	$(DOCKER_RUN) python3 experiments/run_case.py --case $(CASE) --trials $(TRIALS)

## The sweep driver runs on the HOST, not inside a container: it gives every
## run its own fresh container. Looping inside one container degrades after a
## few dozen Mininet start/stops and silently starves later runs.
run-all: build
	bash scripts/run_sweep.sh --trials $(TRIALS)

## Print the plan and a time estimate without running anything.
plan: build
	$(DOCKER_RUN) python3 experiments/run_all.py --dry-run --trials $(TRIALS)

analyze: build
	$(DOCKER_RUN) python3 experiments/analyze.py

## Clean up a wedged Mininet state inside a container (rarely needed since
## containers are --rm, but useful when shelled in).
clean-mn:
	$(DOCKER_RUN) mn -c

clean:
	rm -rf results/raw/* results/tables/* results/figs/*
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
