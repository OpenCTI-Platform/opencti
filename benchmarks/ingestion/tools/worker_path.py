"""Worker path benchmark: what the worker does for each queue message, without RabbitMQ.

For no_split single-object bundles, push_handler.py calls
api.stix2.import_bundle_from_json(raw, update, types, work_id, objects_max_refs). This script does the same
from a thread pool and times every HTTP request pycti sends, by GraphQL operation.

Every case runs twice, with the two ways of reporting an imported object to its work: "each" sends one
reportExpectation per object and waits for it, as pycti did before; "batched" counts successes and sends them
together from a background thread. Each way has its own work, expecting every object it imports; the run checks
that the work counted them all and completed.

Started by the worker-path scenario, which provides BENCH_OPENCTI_URL, BENCH_OPENCTI_TOKEN, BENCH_N,
BENCH_CONCURRENCY and BENCH_CLIENT_OUT.
"""

import json
import os
import statistics
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pycti
from pycti import OpenCTIApiClient
from pycti.entities.opencti_intrusion_set import IntrusionSet
from pycti.entities.opencti_malware import Malware
from pycti.entities.opencti_stix_core_relationship import StixCoreRelationship

URL = os.environ["BENCH_OPENCTI_URL"]
TOKEN = os.environ["BENCH_OPENCTI_TOKEN"]
N = int(os.environ.get("BENCH_N", "500"))
CONCURRENCY = int(os.environ.get("BENCH_CONCURRENCY", "8"))
OUTPUT = os.environ["BENCH_CLIENT_OUT"]
RUN_ID = str(int(time.time()))
CREATED = "2026-01-01T00:00:00.000Z"

# GraphQL operations recognised in request bodies, in match order
OPERATIONS = [
    "stixCoreRelationshipAdd",
    "intrusionSetAdd",
    "malwareAdd",
    "workEdit",
    "vocabularyCategories",
    "labels",
    "externalReferenceAdd",
    "about",
]

stats_lock = threading.Lock()
http_ms = {}
current = {"scenario": "setup", "reports": "batched"}
thread_local = threading.local()
clients = []


def summarize(values):
    if not values:
        return None
    ordered = sorted(values)
    return {
        "n": len(ordered),
        "mean": round(statistics.fmean(ordered), 2),
        "p50": round(ordered[len(ordered) // 2], 2),
        "p95": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))], 2),
        "max": round(ordered[-1], 2),
    }


def new_client():
    client = OpenCTIApiClient(
        URL,
        TOKEN,
        log_level="error",
        json_logging=True,
        provider="worker/" + pycti.__version__,
    )

    def timed(post, suffix=""):
        def timed_post(*args, **kwargs):
            body = kwargs.get("json") or {}
            query = body.get("query", "") if isinstance(body, dict) else ""
            operation = next((op for op in OPERATIONS if op in query), "other")
            start = time.perf_counter()
            response = post(*args, **kwargs)
            elapsed = (time.perf_counter() - start) * 1000
            with stats_lock:
                http_ms.setdefault(current["scenario"], {}).setdefault(
                    operation + suffix, []
                ).append(elapsed)
            return response

        return timed_post

    client.session.post = timed(client.session.post)
    # Batched reports go through their own session, off the import's path
    batcher = client.work.expectations
    batcher._session.post = timed(batcher._session.post, " (background)")
    batched = client.work.report_expectation_success

    def report_success(work_id):
        if current["reports"] == "each":
            client.work.report_expectation(work_id, None)
        else:
            batched(work_id)

    client.work.report_expectation_success = report_success
    with stats_lock:
        clients.append(client)
    return client


def thread_client():
    # One client per thread, as each worker queue has its own PushHandler client
    if not hasattr(thread_local, "client"):
        thread_local.client = new_client()
    return thread_local.client


def bundle(stix_object):
    return json.dumps(
        {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [stix_object]}
    )


def intrusion_set(name):
    return {
        "type": "intrusion-set",
        "spec_version": "2.1",
        "id": IntrusionSet.generate_id(name),
        "name": name,
        "created": CREATED,
        "modified": CREATED,
    }


def malware(name):
    return {
        "type": "malware",
        "spec_version": "2.1",
        "id": Malware.generate_id(name),
        "name": name,
        "is_family": True,
        "created": CREATED,
        "modified": CREATED,
    }


def uses(source_ref, target_ref):
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": StixCoreRelationship.generate_id("uses", source_ref, target_ref),
        "relationship_type": "uses",
        "source_ref": source_ref,
        "target_ref": target_ref,
        "created": CREATED,
        "modified": CREATED,
    }


def run(scenario, objects, concurrency, work_id):
    current["scenario"] = f"{scenario}_{current['reports']}"
    latencies = []
    errors = [0]
    latencies_lock = threading.Lock()

    def import_one(stix_object):
        client = thread_client()
        raw = bundle(stix_object)
        start = time.perf_counter()
        try:
            client.stix2.import_bundle_from_json(raw, False, None, work_id, 0)
        except Exception:  # pylint: disable=broad-except
            with latencies_lock:
                errors[0] += 1
        with latencies_lock:
            latencies.append((time.perf_counter() - start) * 1000)

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        list(executor.map(import_one, objects))
    wall = (time.perf_counter() - start) * 1000
    return {
        "count": len(objects),
        "concurrency": concurrency,
        "wall_ms": round(wall, 2),
        "throughput_per_s": round(len(objects) / wall * 1000, 2),
        "latency_ms": summarize(latencies),
        "errors": errors[0],
    }


def cases(reports):
    tag = f"{RUN_ID}-{reports}"
    spread_sources = [intrusion_set(f"py-{tag}-spread-src-{i}") for i in range(N)]
    spread_targets = [malware(f"py-{tag}-spread-dst-{i}") for i in range(N)]
    hub_sources = [intrusion_set(f"py-{tag}-hub-src-{i}") for i in range(N)]
    hub_concurrent_sources = [intrusion_set(f"py-{tag}-hubc-src-{i}") for i in range(N)]
    hub = malware(f"py-{tag}-hub")
    hub_concurrent = malware(f"py-{tag}-hubc")
    return [
        (
            "entities_concurrent",
            spread_sources
            + spread_targets
            + hub_sources
            + hub_concurrent_sources
            + [hub, hub_concurrent],
            CONCURRENCY,
        ),
        (
            "spread_sequential",
            [uses(s["id"], t["id"]) for s, t in zip(spread_sources, spread_targets)],
            1,
        ),
        ("hub_sequential", [uses(s["id"], hub["id"]) for s in hub_sources], 1),
        (
            "hub_concurrent",
            [uses(s["id"], hub_concurrent["id"]) for s in hub_concurrent_sources],
            CONCURRENCY,
        ),
    ]


def work_state(client, work_id):
    work = client.work.get_work(work_id)
    return {
        "status": work["status"],
        "expected": work["tracking"]["import_expected_number"],
        "processed": work["tracking"]["import_processed_number"],
        "errors": len(work["errors"] or []),
    }


def main():
    client = new_client()
    connectors = client.connector.list()
    connector = next(
        (c for c in connectors if c.get("connector_type") == "INTERNAL_IMPORT_FILE"),
        connectors[0],
    )
    results = {"pycti_version": pycti.__version__}
    checks = {}
    for reports in ("each", "batched"):
        current["reports"] = reports
        work_id = client.work.initiate_work(
            connector["id"], f"bench-{RUN_ID}-{reports}"
        )
        planned = cases(reports)
        expected = sum(len(objects) for _, objects, _ in planned)
        client.work.add_expectations(work_id, expected)
        for name, objects, concurrency in planned:
            results[f"{name}_{reports}"] = run(name, objects, concurrency, work_id)
        # What a stopping worker does: send what is still pending
        for each_client in clients:
            each_client.work.flush_expectations()
        state = work_state(client, work_id)
        checks[reports] = {**state, "imported": expected}
    results["checks"] = checks
    results["http_ms_by_operation"] = {
        scenario: {
            operation: summarize(values) for operation, values in operations.items()
        }
        for scenario, operations in http_ms.items()
    }
    with open(OUTPUT, "w", encoding="utf-8") as output:
        json.dump(results, output, indent=1)
    failed = {
        reports: state
        for reports, state in checks.items()
        if state["processed"] != state["imported"] or state["status"] != "complete"
    }
    if failed:
        raise SystemExit(f"Work reports incomplete: {json.dumps(failed)}")


if __name__ == "__main__":
    main()
