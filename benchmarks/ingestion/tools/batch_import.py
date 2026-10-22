"""Batch import benchmark: chunks of objects sent over HTTP to the lockfreeImport mutation.

Each request carries a chunk of inputs, as the *Add mutations take them, and the platform writes the chunk with the
lock-free path. Cases: entities with refs, then relationships with refs all on one malware (a busy entity), with
chunks of 1, 100 and 500 and 1 or 4 clients at once. After the relationships, the run waits until the platform
lists all of them on the malware.

Started by the batch-import scenario, which provides BENCH_OPENCTI_URL, BENCH_OPENCTI_TOKEN, BENCH_N and
BENCH_CLIENT_OUT.
"""

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from pycti import OpenCTIApiClient
from pycti.entities.opencti_intrusion_set import IntrusionSet
from pycti.entities.opencti_malware import Malware

URL = os.environ["BENCH_OPENCTI_URL"]
TOKEN = os.environ["BENCH_OPENCTI_TOKEN"]
N = int(os.environ.get("BENCH_N", "4000"))
OUTPUT = os.environ["BENCH_CLIENT_OUT"]
RUN_ID = str(int(time.time()))
TLP_GREEN = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
IMPORT = """
    mutation LockfreeImport($entities: [LockfreeEntityInput!], $relationships: [JSON!]) {
        lockfreeImport(entities: $entities, relationships: $relationships) { status id error }
    }
"""

thread_local = threading.local()


def new_client():
    return OpenCTIApiClient(URL, TOKEN, log_level="error", json_logging=True)


def thread_client():
    if not hasattr(thread_local, "client"):
        thread_local.client = new_client()
    return thread_local.client


def send(client, entities=None, relationships=None):
    result = client.query(
        IMPORT, {"entities": entities or [], "relationships": relationships or []}
    )
    return result["data"]["lockfreeImport"]


def wait_until_ready(client):
    deadline = time.time() + 300
    while True:
        try:
            send(client)
            return
        except ValueError as err:
            if time.time() > deadline:
                raise SystemExit(f"lockfreeImport never ready: {err}") from err
            time.sleep(1)


def run(items, chunk, clients, as_relationships=False):
    chunks = [items[i : i + chunk] for i in range(0, len(items), chunk)]
    statuses = {}
    errors = {}
    lock = threading.Lock()

    def send_chunk(part):
        client = thread_client()
        results = (
            send(client, relationships=part)
            if as_relationships
            else send(client, entities=part)
        )
        with lock:
            for result in results:
                statuses[result["status"]] = statuses.get(result["status"], 0) + 1
                if result["error"]:
                    errors[result["error"]] = errors.get(result["error"], 0) + 1

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=clients) as executor:
        list(executor.map(send_chunk, chunks))
    wall = time.perf_counter() - start
    return {
        "count": len(items),
        "chunk_size": chunk,
        "writers": clients,
        "wall_ms": round(wall * 1000, 2),
        "throughput_per_s": round(len(items) / wall, 2),
        "statuses": statuses,
        "errors": errors,
    }


def main():
    client = new_client()
    wait_until_ready(client)
    # Refs, created through today's path as a connector's would be
    author = client.identity.create(type="Organization", name=f"bi-{RUN_ID}-author")
    labels = [client.label.create(value=f"bi-{RUN_ID}-label-{i}") for i in range(3)]
    refs = {
        "createdBy": author["id"],
        "objectMarking": [TLP_GREEN],
        "objectLabel": [label["id"] for label in labels],
    }

    def entities(tag, count):
        return [
            {
                "type": "Intrusion-Set",
                "input": {
                    "name": f"bi-{RUN_ID}-{tag}-{i}",
                    "description": "benchmark",
                    **refs,
                },
            }
            for i in range(count)
        ]

    results = {}
    for chunk, clients in ((1, 8), (100, 1), (500, 1), (500, 4)):
        tag = f"e{chunk}x{clients}"
        count = min(N, 1000) if chunk == 1 else N
        results[f"entities_chunk{chunk}_x{clients}"] = run(
            entities(tag, count), chunk, clients
        )

    hub_name = f"bi-{RUN_ID}-hub"
    [hub] = send(
        client,
        entities=[
            {
                "type": "Malware",
                "input": {"name": hub_name, "is_family": True, **refs},
            }
        ],
    )
    hub_ref = Malware.generate_id(hub_name)
    expected = 0
    for chunk, clients in ((1, 8), (100, 1), (500, 1), (500, 4)):
        tag = f"e{chunk}x{clients}"
        count = min(N, 1000) if chunk == 1 else N
        relationships = [
            {
                "relationship_type": "uses",
                "fromId": IntrusionSet.generate_id(f"bi-{RUN_ID}-{tag}-{i}"),
                "toId": hub_ref,
                "description": "benchmark",
                **refs,
            }
            for i in range(count)
        ]
        results[f"relations_hub_chunk{chunk}_x{clients}"] = run(
            relationships, chunk, clients, as_relationships=True
        )
        expected += count

    # Every relationship listed by the platform on the hub (settled and searchable)
    start = time.perf_counter()
    listed = 0
    while time.perf_counter() - start < 120:
        page = client.stix_core_relationship.list(
            toId=hub["id"], relationship_type="uses", first=1, withPagination=True
        )
        listed = page["pagination"]["globalCount"]
        if listed >= expected:
            break
        time.sleep(0.5)
    results["checks"] = {
        "hub_relationships_expected": expected,
        "hub_relationships_listed": listed,
        "listed_after_last_write_ms": round((time.perf_counter() - start) * 1000),
    }
    with open(OUTPUT, "w", encoding="utf-8") as output:
        json.dump(results, output, indent=1)
    failed = [
        name
        for name, value in results.items()
        if isinstance(value, dict) and value.get("errors")
    ]
    if failed or listed < expected:
        raise SystemExit(
            f"Batch import incomplete: errors in {failed}, {listed} of {expected} listed"
        )


if __name__ == "__main__":
    main()
