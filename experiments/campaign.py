"""Host-side campaign execution with immutable provenance and bounded retries."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from experiments.run_all import plan
from experiments.run_case import WARMUP_SECONDS
from experiments.validation import read_events

ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("IMAGE", "lantern-sdn-ids")


def command_output(command):
    return subprocess.check_output(command, cwd=str(ROOT), text=True).strip()


def git_metadata():
    try:
        return {
            "revision": command_output(["git", "rev-parse", "HEAD"]),
            "working_tree": command_output(["git", "status", "--porcelain"]),
        }
    except subprocess.CalledProcessError:
        return {"revision": None, "working_tree": "source archive (no Git metadata)"}


def source_files():
    # Explicit source inventory, including new files before a user commits.
    paths = []
    for directory in [
        "lantern",
        "experiments",
        "traffic",
        "topo",
        "tests",
        "scripts",
        "docker",
    ]:
        paths += [
            p
            for p in (ROOT / directory).rglob("*")
            if p.is_file()
            and "__pycache__" not in p.parts
            and p.suffix not in (".pyc",)
        ]
    paths += [
        ROOT / name
        for name in ["Makefile", ".gitignore", ".dockerignore"]
        if (ROOT / name).exists()
    ]
    return sorted(paths)


def source_hash():
    digest = hashlib.sha256()
    for path in source_files():
        digest.update(
            str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes() + b"\0"
        )
    return digest.hexdigest()


def container_command(run, raw, frozen=None):
    command = [
        "docker",
        "run",
        "--rm",
        "--privileged",
        "--network",
        "none",
        "-v",
        str(ROOT) + ":/opt/lantern",
        "-e",
        "LANTERN_RAW=" + str(raw.relative_to(ROOT)),
    ]
    if frozen:
        command += ["-e", "LANTERN_CONFIG=" + str(frozen.relative_to(ROOT))]
    command += [IMAGE, "python3", "-m", "experiments.run_case"]
    for key, value in run.items():
        if isinstance(value, bool):
            if value:
                command += ["--" + key]
        else:
            command += ["--" + key, str(value)]
    return command


def create(directory):
    directory.mkdir(parents=True, exist_ok=False)
    image = json.loads(command_output(["docker", "image", "inspect", IMAGE]))[0]
    dependencies = command_output(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "sh",
            IMAGE,
            "-c",
            "python3 -m pip freeze && dpkg-query -W",
        ]
    )
    manifest = dict(
        schema_version=2,
        created=datetime.now(timezone.utc).isoformat(),
        revision=git_metadata()["revision"],
        source_hash=source_hash(),
        working_tree=git_metadata()["working_tree"],
        image_id=image["Id"],
        image_digests=image.get("RepoDigests", []),
        platform=platform.platform(),
        machine=platform.machine(),
        python=sys.version,
        command=sys.argv,
        matrix=plan(),
        calibration_seeds=[11001, 11002, 11003],
        note="95 evaluation runs; the requested matrix arithmetic was corrected from 105.",
    )
    from lantern import config

    def convert(value):
        if isinstance(value, set):
            return sorted(value)
        raise TypeError(type(value).__name__)

    manifest["configuration"] = {
        k: v for k, v in vars(config).items() if k.isupper() and not k.startswith("_")
    }
    (directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2, default=convert) + "\n"
    )
    (directory / "dependencies.txt").write_text(dependencies + "\n")
    (directory / "source.sha256").write_text(manifest["source_hash"] + "\n")
    return manifest


def verify_source(directory, check_image=True):
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest["source_hash"] != source_hash():
        raise RuntimeError(
            "source changed since campaign creation; create a new campaign"
        )
    if check_image:
        current = json.loads(command_output(["docker", "image", "inspect", IMAGE]))[0][
            "Id"
        ]
        if current != manifest["image_id"]:
            raise RuntimeError("container image changed")
    return manifest


def execute(directory, runs, frozen=None):
    verify_source(directory)
    records = []
    for number, run in enumerate(runs, 1):
        verify_source(directory)
        success = False
        for attempt in range(1, 3):
            # Separate directories retain every attempt. Existing successful
            # attempts are resumable; a partially written attempt is never reused.
            raw = directory / run["phase"] / ("attempt-%d" % attempt) / "raw"
            log = raw / ("%s_trial%02d.jsonl" % (run["label"], run["trial"]))
            validity = log.with_suffix(".validity.json")
            if validity.exists() and json.loads(validity.read_text()).get("valid"):
                success = True
                break
            if raw.exists() and list(raw.glob(log.stem + "*")):
                continue
            raw.mkdir(parents=True, exist_ok=True)
            cmd = container_command(run, raw, frozen)
            print(
                "[%d/%d] %s trial %d attempt %d"
                % (number, len(runs), run["label"], run["trial"], attempt),
                flush=True,
            )
            started = time.time()
            with (raw.parent / (log.stem + ".driver.log")).open("x") as output:
                result = subprocess.run(
                    cmd, cwd=str(ROOT), stdout=output, stderr=subprocess.STDOUT
                )
            record = dict(
                run=run,
                attempt=attempt,
                command=cmd,
                seconds=time.time() - started,
                exit_code=result.returncode,
            )
            records.append(record)
            with (directory / "execution.jsonl").open("a") as handle:
                handle.write(json.dumps(record) + "\n")
            if (
                result.returncode == 0
                and validity.exists()
                and json.loads(validity.read_text()).get("valid")
            ):
                success = True
                break
            print("  invalid attempt retained", flush=True)
        if not success:
            raise RuntimeError("two attempts failed; inspect " + str(log))
    verify_source(directory)
    return records


def calibrate(directory):
    runs = [
        dict(
            case="C1",
            phase="calibration",
            mitigator="none",
            trial=i,
            seed=11000 + i,
            warmup=WARMUP_SECONDS,
            observation=600,
            label="calibration-C1-none",
        )
        for i in range(1, 4)
    ]
    execute(directory, runs)
    from experiments.analyze import discover_runs

    maxima = dict(
        PORTSCAN_PORTS=0.0,
        PORTSCAN_HOSTS=0.0,
        DOS_PPS=0.0,
        BRUTEFORCE_ATTEMPTS=0.0,
        GRAPH_SCORE_THRESHOLD=0.0,
    )
    rows = []
    for run in discover_runs(directory / "calibration"):
        path = Path(run["log"])
        if not json.loads(path.with_suffix(".validity.json").read_text())["valid"]:
            continue
        meta = json.loads(path.with_suffix(".meta.json").read_text())
        for event in read_events(path):
            if (
                event["kind"] != "detector_timing"
                or event.get("warming_up")
                or not meta["evaluation_start"]
                <= event["wall"]
                <= meta["recovery_start"]
            ):
                continue
            values = dict(
                event["baseline_features"],
                GRAPH_SCORE_THRESHOLD=event.get("top_score") or 0,
            )
            rows.append(dict(run=path.stem, window=event["window_index"], **values))
            for key, value in values.items():
                maxima[key] = max(maxima[key], value)
    if len(rows) < 150:
        raise RuntimeError("insufficient calibration observations")
    import math

    thresholds = {key: math.ceil(value * 1.25 + 1) for key, value in maxima.items()}
    path = directory / "thresholds.json"
    if path.exists():
        if json.loads(path.read_text()) != thresholds:
            raise RuntimeError("frozen thresholds would change")
    else:
        path.write_text(json.dumps(thresholds, indent=2) + "\n")
    (directory / "calibration.json").write_text(
        json.dumps(
            dict(
                rule="ceil(1.25 * maximum normal-only value + 1)",
                maxima=maxima,
                thresholds=thresholds,
                observations=rows,
                frozen_design="weights, variance floors, warmup and online profile policy unchanged",
            ),
            indent=2,
        )
        + "\n"
    )
    (directory / "thresholds.sha256").write_text(
        hashlib.sha256(path.read_bytes()).hexdigest() + "\n"
    )
    print("frozen thresholds: " + json.dumps(thresholds), flush=True)


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument(
        "action", choices=["create", "pilot", "calibrate", "evaluate", "all", "verify"]
    )
    parser.add_argument("--campaign", required=True)
    args = parser.parse_args()
    directory = (ROOT / args.campaign).resolve()
    if ROOT not in directory.parents:
        raise ValueError("campaign must be inside the checkout")
    if args.action in ("create", "all"):
        create(directory)
    if args.action == "verify":
        print(json.dumps(verify_source(directory), indent=2))
    if args.action in ("pilot", "all"):
        records = execute(
            directory,
            [
                dict(
                    case="C5",
                    phase="pilot",
                    mitigator="graph",
                    trial=1,
                    seed=9101,
                    warmup=WARMUP_SECONDS,
                    label="pilot-C5-graph",
                )
            ],
        )
        duration = records[-1]["seconds"] if records else None
        if duration:
            print(
                "Measured pilot %.1fs; 95 evaluation runs approximately %.1f hours (mixed cases take longer)."
                % (duration, duration * 95 / 3600),
                flush=True,
            )
    if args.action in ("calibrate", "all"):
        calibrate(directory)
    if args.action in ("evaluate", "all"):
        frozen = directory / "thresholds.json"
        if not frozen.exists():
            raise RuntimeError("calibrate before evaluation")
        if (
            hashlib.sha256(frozen.read_bytes()).hexdigest()
            != (directory / "thresholds.sha256").read_text().strip()
        ):
            raise RuntimeError("frozen threshold checksum changed")
        execute(directory, plan(), frozen)
        print("evaluation complete; analyze and package this campaign", flush=True)


if __name__ == "__main__":
    main()
