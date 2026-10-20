#!/usr/bin/env python3
"""OpenCTI ingestion benchmarks: one entry point for every scenario.

    python benchmarks/ingestion/run.py init
    python benchmarks/ingestion/run.py run relationships
    python benchmarks/ingestion/run.py run all --quick
    python benchmarks/ingestion/run.py show benchmarks/ingestion/results/<file>.json
    python benchmarks/ingestion/run.py data-shape --prefix opencti

See README.md next to this file for the methodology.
"""

import argparse
import datetime
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
GRAPHQL = REPO / "opencti-platform" / "opencti-graphql"
WORKER_SRC = REPO / "opencti-worker" / "src"
TOOLS = HERE / "tools"
RESULTS = HERE / "results"
VITEST_CONFIG = "vitest.config.bench.ts"
# Prefixes the benchmark refuses to use: init wipes everything under the prefix
PROTECTED_PREFIXES = {"", "opencti"}


@dataclass
class Scenario:
    name: str
    summary: str
    kind: (
        str  # "vitest" (runs inside a benchmark platform) or "python" (standalone tool)
    )
    params: dict
    quick: dict
    needs: list = field(default_factory=list)  # python modules the scenario needs


SCENARIOS = {
    s.name: s
    for s in [
        Scenario(
            "relationships",
            "Today's relationship write path vs the batch prototype, spread and on one shared entity",
            "vitest",
            {"n": 2000, "concurrency": 8, "chunk": 500},
            {"n": 200},
        ),
        Scenario(
            "batch-variants",
            "Batch prototype: chunk sizes and concurrent writers on one shared entity",
            "vitest",
            {"n": 2000},
            {"n": 300},
        ),
        Scenario(
            "reingest",
            "Re-ingesting the same relationships, unchanged and changed (upsert path)",
            "vitest",
            {"n": 500, "concurrency": 8},
            {"n": 100},
        ),
        Scenario(
            "feed-shaped",
            "Indicators with refs, ~12 indicates each to shared attack patterns, reports",
            "vitest",
            {"n": 300, "concurrency": 8, "chunk": 500},
            {"n": 30},
        ),
        Scenario(
            "worker-path",
            "pycti importing one-object bundles over HTTP, timed per GraphQL operation",
            "vitest",
            {"n": 500, "concurrency": 8},
            {"n": 50},
            needs=["pycti"],
        ),
        Scenario(
            "queue-loop",
            "Overhead of the worker's RabbitMQ consumer loop per message",
            "python",
            {"messages": 200},
            {"messages": 50},
            needs=["pika"],
        ),
    ]
}


# region helpers
def log(message):
    print(message, flush=True)


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def http_json(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return json.load(response)
    except (urllib.error.URLError, OSError, ValueError):
        return None


def platform_env(prefix):
    if prefix in PROTECTED_PREFIXES:
        fail(
            f"refusing prefix '{prefix}': init deletes every index, queue and key under the prefix"
        )
    return {
        **os.environ,
        "NODE_ENV": "test",
        "ELASTICSEARCH__INDEX_PREFIX": prefix,
        "REDIS__NAMESPACE": prefix,
        "RABBITMQ__QUEUE_PREFIX": prefix,
        "MINIO__BUCKET_NAME": f"{prefix}-bucket",
        "OPENCTI_BENCH_TIMING": "true",
    }


def check_python_modules(python, modules):
    for module in modules:
        probe = subprocess.run(
            [python, "-c", f"import {module}"], capture_output=True, check=False
        )
        if probe.returncode != 0:
            fail(
                f"'{python}' cannot import {module}. Use --python with an environment that has it "
                f"(see README: Prerequisites)."
            )


def is_initialized(es_url, prefix):
    indices = http_json(f"{es_url}/_cat/indices/{prefix}_*?format=json")
    return bool(indices)


def run_vitest(scenario_file, env, log_path):
    yarn = shutil.which("yarn")
    if not yarn:
        fail(
            "yarn not found: install the platform's Node.js dependencies first (see README)"
        )
    command = [
        yarn,
        "vitest",
        "run",
        "--config",
        VITEST_CONFIG,
        f"tests/bench/scenarios/{scenario_file}",
    ]
    with open(log_path, "w", encoding="utf-8") as log_file:
        process = subprocess.run(
            command,
            cwd=GRAPHQL,
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            check=False,
        )
    return process.returncode


def tail(path, lines=40):
    content = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(content[-lines:])


def git(*args):
    probe = subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, check=False
    )
    return probe.stdout.strip() if probe.returncode == 0 else None


def environment(args):
    es = http_json(args.es_url) or {}
    node = subprocess.run(
        ["node", "--version"], capture_output=True, text=True, check=False
    )
    package = json.loads((GRAPHQL / "package.json").read_text(encoding="utf-8"))
    return {
        "date": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "git_commit": git("rev-parse", "--short", "HEAD"),
        "git_branch": git("branch", "--show-current"),
        "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
        "opencti_version": package.get("version"),
        "search_engine": f"{es.get('version', {}).get('distribution', 'elasticsearch')} {es.get('version', {}).get('number', '?')}",
        "node": node.stdout.strip(),
        "python": args.python,
        "os": platform.platform(),
        "cpus": os.cpu_count(),
        "prefix": args.prefix,
    }


# endregion


# region commands
def command_init(args):
    env = platform_env(args.prefix)
    env["INIT_TEST_PLATFORM"] = "true"
    RESULTS.mkdir(exist_ok=True)
    log_path = RESULTS / f"init-{args.prefix}.log"
    log(
        f"Initializing the benchmark platform '{args.prefix}' (wipes everything under that prefix)..."
    )
    start = time.time()
    if run_vitest("init.scenario.ts", env, log_path) != 0:
        fail(f"initialization failed, see {log_path}\n{tail(log_path)}")
    log(f"Ready in {time.time() - start:.0f} s.")


def scenario_params(scenario, args):
    params = dict(scenario.params)
    if args.quick:
        params.update(scenario.quick)
    for key in ("n", "concurrency", "chunk", "messages"):
        value = getattr(args, key, None)
        if value is not None and key in params:
            params[key] = value
    return params


def run_one(scenario, args, stamp):
    params = scenario_params(scenario, args)
    base = RESULTS / f"{stamp}-{scenario.name}"
    out_path, log_path = base.with_suffix(".json"), base.with_suffix(".log")
    check_python_modules(args.python, scenario.needs)
    log(f"\n=== {scenario.name}: {scenario.summary}")
    log(f"    params {params}, log {log_path.relative_to(REPO)}")
    start = time.time()
    if scenario.kind == "python":
        command = [
            args.python,
            str(TOOLS / "queue_loop.py"),
            "--worker-src",
            str(WORKER_SRC),
            "--messages",
            str(params["messages"]),
            "--host",
            args.amqp_host,
            "--port",
            str(args.amqp_port),
            "--user",
            args.amqp_user,
            "--password",
            args.amqp_password,
            "--out",
            str(out_path),
        ]
        with open(log_path, "w", encoding="utf-8") as log_file:
            code = subprocess.run(
                command, stdout=log_file, stderr=subprocess.STDOUT, check=False
            ).returncode
    else:
        if not is_initialized(args.es_url, args.prefix):
            log(
                f"    benchmark platform '{args.prefix}' not found, initializing it first"
            )
            command_init(args)
        env = platform_env(args.prefix)
        env["SKIP_CLEANUP_PLATFORM"] = "true"
        env["BENCH_OUT"] = str(out_path)
        env["BENCH_PYTHON"] = args.python
        env["BENCH_WORKER_SCRIPT"] = str(TOOLS / "worker_path.py")
        for key, value in params.items():
            env[f"BENCH_{key.upper()}"] = str(value)
        code = run_vitest(f"{scenario.name}.scenario.ts", env, log_path)
    elapsed = time.time() - start
    if code != 0 or not out_path.exists():
        log(f"    FAILED after {elapsed:.0f} s, see {log_path}\n{tail(log_path)}")
        return False
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    payload["environment"] = environment(args)
    payload["params"] = params
    payload["duration_s"] = round(elapsed, 1)
    out_path.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    log(f"    done in {elapsed:.0f} s -> {out_path.relative_to(REPO)}")
    print_summary(payload, phases=args.phases)
    return True


def command_run(args):
    names = list(SCENARIOS) if "all" in args.scenarios else args.scenarios
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        fail(f"unknown scenario(s) {unknown}; available: {', '.join(SCENARIOS)} or all")
    RESULTS.mkdir(exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    failed = [name for name in names if not run_one(SCENARIOS[name], args, stamp)]
    if failed:
        fail(f"failed: {', '.join(failed)}")


def command_list(_args):
    for scenario in SCENARIOS.values():
        log(f"{scenario.name:16s}{scenario.summary}")
        log(f"{'':16s}defaults {scenario.params}, --quick {scenario.quick}")


def command_show(args):
    for path in args.files:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        log(f"\n=== {payload.get('scenario')} ({path})")
        print_summary(payload, phases=args.phases)


def command_data_shape(args):
    command = [
        sys.executable,
        str(TOOLS / "data_shape.py"),
        "--es-url",
        args.es_url,
        "--prefix",
        args.target,
    ]
    if args.out:
        command += ["--out", args.out]
    sys.exit(subprocess.run(command, check=False).returncode)


# endregion


# region summary
def fmt(value, unit=""):
    if value is None:
        return "-"
    if isinstance(value, float) and value >= 100:
        return f"{value:,.0f}{unit}"
    return f"{value:,}{unit}" if isinstance(value, int) else f"{value:,.1f}{unit}"


def print_table(header, rows):
    widths = [max(len(str(r[i])) for r in rows + [header]) for i in range(len(header))]

    def render(cells):
        return "  ".join(
            str(c).ljust(widths[i]) if i < 3 else str(c).rjust(widths[i])
            for i, c in enumerate(cells)
        )

    log("    " + render(header))
    for row in rows:
        log("    " + render(row))


def print_summary(payload, phases=False):
    results = payload.get("results", {})
    rows, loop_rows = [], []
    for name, value in results.items():
        if not isinstance(value, dict):
            continue
        if "loop_overhead_ms" in value:
            loop_rows.append(
                [
                    name,
                    fmt(value["messages"]),
                    f"{value['handler_ms']} ms",
                    fmt(value["throughput_per_s"]),
                    fmt(value["per_message_ms"], " ms"),
                    fmt(value["loop_overhead_ms"], " ms"),
                    fmt(value["messages"] - value["handled"]),
                ]
            )
        elif "throughput_per_s" in value:
            latency = value.get("latency_ms") or {}
            errors = value.get("errors")
            error_count = sum(errors.values()) if isinstance(errors, dict) else errors
            if "chunk_size" in value:
                shape = f"chunk {value['chunk_size']} x{value['writers']}"
            elif "concurrency" in value:
                shape = f"{value['concurrency']} at a time"
            else:
                shape = ""
            rows.append(
                [
                    name,
                    fmt(value.get("count")),
                    shape,
                    fmt(value["throughput_per_s"]),
                    fmt(latency.get("mean"), " ms"),
                    fmt(latency.get("p95"), " ms"),
                    fmt(error_count or 0),
                ]
            )
        elif "wall_ms" in value:
            rows.append(
                [
                    name,
                    fmt(value.get("objects")),
                    "one call",
                    "-",
                    fmt(value["wall_ms"], " ms"),
                    "-",
                    "0",
                ]
            )
    if rows:
        print_table(
            ["case", "items", "shape", "per second", "mean", "p95", "errors"], rows
        )
    if loop_rows:
        print_table(
            [
                "case",
                "messages",
                "handler",
                "per second",
                "per message",
                "loop overhead",
                "not handled",
            ],
            loop_rows,
        )
    for key in ("checks", "bulk_resolution_check"):
        if key in results:
            log(f"    {key}: {json.dumps(results[key])}")
    http = results.get("http_ms_by_operation")
    if http:
        log("    HTTP time per GraphQL operation (mean ms, calls):")
        for case, operations in http.items():
            parts = [
                f"{op} {s['mean']} ({s['n']})" for op, s in operations.items() if s
            ]
            log(f"      {case}: {', '.join(parts)}")
    if phases:
        for name, value in results.items():
            phase_map = value.get("phases_ms") if isinstance(value, dict) else None
            chunk_map = (
                value.get("per_chunk_mean_ms") if isinstance(value, dict) else None
            )
            if phase_map:
                log(
                    f"    phases {name}: "
                    + ", ".join(f"{k} {v['mean']}" for k, v in phase_map.items())
                )
            if chunk_map:
                log(
                    f"    per chunk {name}: "
                    + ", ".join(f"{k} {v}" for k, v in chunk_map.items())
                )


# endregion


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--prefix",
        default="bench",
        help="isolation prefix of the benchmark platform (default: bench)",
    )
    parser.add_argument(
        "--es-url",
        default=os.environ.get("ELASTICSEARCH__URL", "http://127.0.0.1:9200"),
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="interpreter with pycti and pika (default: this one)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser(
        "init", help="create (or wipe and recreate) the benchmark platform"
    )
    commands.add_parser("list", help="list the scenarios and their parameters")

    run = commands.add_parser("run", help="run one or more scenarios, or all")
    run.add_argument(
        "scenarios",
        nargs="+",
        metavar="scenario",
        help=f"{', '.join(SCENARIOS)} or all",
    )
    run.add_argument(
        "--quick",
        action="store_true",
        help="small sizes, to check the setup in a few minutes",
    )
    run.add_argument("--n", type=int, help="main size of the scenario (see list)")
    run.add_argument("--concurrency", type=int)
    run.add_argument("--chunk", type=int, help="batch prototype chunk size")
    run.add_argument("--messages", type=int, help="queue-loop messages per case")
    run.add_argument(
        "--phases", action="store_true", help="also print the platform phase timings"
    )
    run.add_argument("--amqp-host", default="localhost")
    run.add_argument("--amqp-port", type=int, default=5672)
    run.add_argument("--amqp-user", default="guest")
    run.add_argument("--amqp-password", default="guest")

    show = commands.add_parser("show", help="print the summary of result files")
    show.add_argument("files", nargs="+")
    show.add_argument("--phases", action="store_true")

    shape = commands.add_parser(
        "data-shape", help="read-only report of what a platform stores"
    )
    shape.add_argument(
        "--target",
        default="opencti",
        help="index prefix of the platform to inspect (default: opencti)",
    )
    shape.add_argument("--out", help="also write the report as JSON")

    args = parser.parse_args()
    handlers = {
        "init": command_init,
        "list": command_list,
        "run": command_run,
        "show": command_show,
        "data-shape": command_data_shape,
    }
    handlers[args.command](args)


if __name__ == "__main__":
    main()
