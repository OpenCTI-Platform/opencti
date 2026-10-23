"""Full-flow benchmark: a connector-shaped bundle imported by pycti, one object per request and in batch mode.

The bundle: an author, TLP:GREEN and labels on everything; attack patterns with kill chain phases and external
references; intrusion sets that all `use` one malware; IPv4 observables `related-to` that malware; one report that
contains every object. Each mode imports its own copy (names carry the mode) under its own work, which expects every
object, as the worker does it (import_bundle with the work id header). Then the platform is asked, for both
copies, how many objects of each kind it stores and how many refs they carry: the two must be equal, and both works
complete with every object counted.

    python full_flow.py --url http://localhost:4100 --token <token> --n 1000

Also started by the full-flow scenario (BENCH_OPENCTI_URL, BENCH_OPENCTI_TOKEN, BENCH_N, BENCH_CLIENT_OUT).
"""

import argparse
import json
import os
import time
import uuid

from pycti import OpenCTIApiClient
from pycti.entities.opencti_attack_pattern import AttackPattern
from pycti.entities.opencti_identity import Identity
from pycti.entities.opencti_intrusion_set import IntrusionSet
from pycti.entities.opencti_malware import Malware
from pycti.entities.opencti_report import Report
from pycti.entities.opencti_stix_core_relationship import StixCoreRelationship

TLP_GREEN = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
CREATED = "2026-01-01T00:00:00.000Z"


def build_bundle(tag, n):
    author = {
        "type": "identity",
        "spec_version": "2.1",
        "id": Identity.generate_id(f"ff-{tag}-author", "organization"),
        "name": f"ff-{tag}-author",
        "identity_class": "organization",
    }
    refs = {
        "created_by_ref": author["id"],
        "object_marking_refs": [TLP_GREEN],
        "labels": [f"ff-{tag}-a", f"ff-{tag}-b"],
        "created": CREATED,
        "modified": CREATED,
    }
    hub_name = f"ff-{tag}-malware"
    hub = {
        "type": "malware",
        "spec_version": "2.1",
        "id": Malware.generate_id(hub_name),
        "name": hub_name,
        "is_family": True,
        **refs,
    }
    attack_patterns = []
    for i in range(max(1, n // 10)):
        name = f"ff-{tag}-technique-{i}"
        external_id = f"T{tag[-4:]}{i:04d}"
        attack_patterns.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": AttackPattern.generate_id(name, external_id),
                "name": name,
                "x_mitre_id": external_id,
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": ["execution", "persistence", "discovery"][i % 3],
                    }
                ],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": external_id,
                        "url": f"https://attack.example/{tag}/{external_id}",
                    },
                    {
                        "source_name": "article",
                        "url": f"https://blog.example/{tag}/{i}",
                        "description": "analysis",
                    },
                ],
                **refs,
            }
        )
    sets = [
        {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": IntrusionSet.generate_id(f"ff-{tag}-set-{i}"),
            "name": f"ff-{tag}-set-{i}",
            **refs,
        }
        for i in range(n)
    ]
    observables = [
        {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": f"ipv4-addr--{uuid.uuid5(uuid.NAMESPACE_URL, f'{tag}-{i}')}",
            "value": f"10.{int(tag) % 200}.{i // 250}.{i % 250}",
            **refs,
        }
        for i in range(max(1, n // 10))
    ]

    def rel(kind, source, target):
        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": StixCoreRelationship.generate_id(kind, source["id"], target["id"]),
            "relationship_type": kind,
            "source_ref": source["id"],
            "target_ref": target["id"],
            **refs,
        }

    relationships = [rel("uses", s, hub) for s in sets]
    relationships += [rel("uses", hub, ap) for ap in attack_patterns]
    relationships += [rel("related-to", o, hub) for o in observables]
    contained = [hub, *attack_patterns, *sets, *observables, *relationships]
    report_name = f"ff-{tag}-report"
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": Report.generate_id(report_name, CREATED),
        "name": report_name,
        "published": CREATED,
        "report_types": ["threat-report"],
        "object_refs": [o["id"] for o in contained],
        **refs,
    }
    objects = [author, *contained, report]
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }, report_name


def stored_shape(client, tag):
    """What the platform stores for a copy: counts per kind and refs carried, read through its API"""

    def name_filter(prefix):
        return {
            "mode": "and",
            "filters": [{"key": "name", "values": [prefix], "operator": "starts_with"}],
            "filterGroups": [],
        }

    def count(lister, prefix):
        page = lister.list(filters=name_filter(prefix), first=1, withPagination=True)
        return page["pagination"]["globalCount"]

    report = client.report.read(filters=name_filter(f"ff-{tag}-report"))
    techniques = client.attack_pattern.list(
        filters=name_filter(f"ff-{tag}-technique"), first=1000
    )
    a_set = client.intrusion_set.read(filters=name_filter(f"ff-{tag}-set-0"))
    malware = client.malware.read(filters=name_filter(f"ff-{tag}-malware"))
    rel_count = (
        client.stix_core_relationship.list(
            fromOrToId=malware["id"], first=1, withPagination=True
        )["pagination"]["globalCount"]
        if malware
        else 0
    )
    return {
        "intrusion_sets": count(client.intrusion_set, f"ff-{tag}-set-"),
        "attack_patterns": len(techniques),
        "kill_chain_phases_on_techniques": sum(
            len(t.get("killChainPhases") or []) for t in techniques
        ),
        "external_references_on_techniques": sum(
            len(t.get("externalReferences") or []) for t in techniques
        ),
        "relationships_of_malware": rel_count,
        "report_objects": len(report.get("objectsIds") or []) if report else 0,
        "set_refs": {
            "author": bool(a_set and a_set.get("createdBy")),
            "markings": len(a_set.get("objectMarking") or []) if a_set else 0,
            "labels": len(a_set.get("objectLabel") or []) if a_set else 0,
        },
    }


def settled_shape(client, tag, report_objects, timeout=30):
    """The stored shape once the report lists every object: lock-free writes are searchable at the next refresh
    (about 1 s, longer when Elasticsearch is busy), not when the write returns"""
    deadline = time.time() + timeout
    while True:
        shape = stored_shape(client, tag)
        settled = (
            shape["report_objects"] >= report_objects
            and shape["relationships_of_malware"] > 0
        )
        if settled or time.time() > deadline:
            return shape
        time.sleep(1)


def run(client, connector_id, n, batch):
    tag = str(int(time.time() * 1000))[-9:]
    bundle, _ = build_bundle(tag, n)
    work_id = client.work.initiate_work(
        connector_id, f"full flow {'batch' if batch else 'one by one'} {tag}"
    )
    client.work.add_expectations(work_id, len(bundle["objects"]))
    client.set_work_id(work_id)
    client.batch_import_enabled = batch
    client.batch_chunk_size = int(os.environ.get("BENCH_CHUNK", "1000"))
    start = time.perf_counter()
    imported, rejected = client.stix2.import_bundle(bundle, False, None, work_id)
    elapsed = time.perf_counter() - start
    client.work.flush_expectations()
    client.batch_import_enabled = False
    deadline = time.time() + 60
    while True:
        work = client.work.get_work(work_id)
        if work["status"] == "complete" or time.time() > deadline:
            break
        time.sleep(0.5)
    return {
        "objects": len(bundle["objects"]),
        "seconds": round(elapsed, 2),
        "throughput_per_s": round(len(bundle["objects"]) / elapsed, 1),
        "imported": len(imported),
        "rejected": len(rejected),
        "imported_again_on_their_own": client.stix2.last_batch_retried if batch else 0,
        "work": {
            "status": work["status"],
            **(work.get("tracking") or {}),
            "errors": len(work.get("errors") or []),
        },
        "stored": settled_shape(client, tag, len(bundle["objects"]) - 2),
    }


QUEUE_CONNECTOR_ID = "5f1e3c7a-9b2d-4e8f-a6c1-0d4b7e9f2a35"


def register_connector(client):
    """The connector whose queue the bundle goes through, registered as any external import connector"""
    from pycti import OpenCTIConnector

    client.connector.register(
        OpenCTIConnector(
            QUEUE_CONNECTOR_ID,
            "Full flow",
            "EXTERNAL_IMPORT",
            "",
            True,
            False,
            False,
            False,
            "none",
        )
    )
    return QUEUE_CONNECTOR_ID


def run_queue(client, n):
    """The whole flow: the bundle pushed to a connector queue (split as connectors send it), imported by the
    running worker(s), until the work is complete"""
    connector_id = register_connector(client)
    tag = str(int(time.time() * 1000))[-9:]
    bundle, _ = build_bundle(tag, n)
    work_id = client.work.initiate_work(connector_id, f"full flow queue {tag}")
    start = time.perf_counter()
    client.send_bundle_to_api(
        connector_id=connector_id, bundle=json.dumps(bundle), work_id=work_id
    )
    while True:
        work = client.work.get_work(work_id)
        if work["status"] == "complete":
            break
        if time.perf_counter() - start > 1800:
            raise SystemExit(f"Queue import timed out: {work.get('tracking')}")
        time.sleep(0.2)
    elapsed = time.perf_counter() - start
    return {
        "objects": len(bundle["objects"]),
        "seconds": round(elapsed, 2),
        "throughput_per_s": round(len(bundle["objects"]) / elapsed, 1),
        "work": {
            "status": work["status"],
            **(work.get("tracking") or {}),
            "errors": len(work.get("errors") or []),
        },
        "stored": settled_shape(client, tag, len(bundle["objects"]) - 2),
    }


def wait_complete(client, work_ids, start, timeout=3600):
    pending = set(work_ids)
    works = {}
    while pending:
        for work_id in list(pending):
            work = client.work.get_work(work_id)
            if work["status"] == "complete":
                works[work_id] = work
                pending.discard(work_id)
        if pending and time.perf_counter() - start > timeout:
            raise SystemExit(f"Queue import timed out: {len(pending)} works pending")
        if pending:
            time.sleep(0.5)
    return works


def error_kinds(works):
    """How many errors the works recorded, by message and by type of the object that failed"""
    kinds = {}
    for work in works:
        for error in work.get("errors") or []:
            try:
                kind = json.loads(error.get("source") or "{}").get("type", "?")
            except ValueError:
                kind = "?"
            message = str(error.get("message") or "")
            for marker in (
                "MISSING_REFERENCE_ERROR",
                "LOCK_ERROR",
                "Element(s) not found",
                "DUPLICATE",
            ):
                if marker in message:
                    message = marker
                    break
            key = f"{kind}: {message[:80]}"
            kinds[key] = kinds.get(key, 0) + 1
    return kinds


def stored_counts(client, tag, expected, timeout=60):
    """Indicators and reports the run stored (searchable at the next refresh): polled until they match"""

    def count(lister, prefix):
        page = lister.list(
            filters={
                "mode": "and",
                "filters": [
                    {"key": "name", "values": [prefix], "operator": "starts_with"}
                ],
                "filterGroups": [],
            },
            first=1,
            withPagination=True,
        )
        return page["pagination"]["globalCount"]

    deadline = time.time() + timeout
    while True:
        counts = {"indicator": count(client.indicator, f"ff-{tag}-indicator-")}
        if expected.get("report"):
            counts["report"] = count(client.report, f"ff-{tag}-")
        if (
            all(counts[k] >= expected.get(k, 0) for k in counts)
            or time.time() > deadline
        ):
            return counts
        time.sleep(1)


def run_feed(client, profile, n, resend):
    """A feed's bundles pushed to a connector queue one after the other, as its connector sends them (one work per
    bundle), imported by the running worker(s) until every work is complete; then, with resend, the same bundles
    twice again, all of them already stored, as a feed that sends its full lists on every run"""
    from feeds import FEEDS, distinct_counts

    connector_id = register_connector(client)
    tag = str(int(time.time() * 1000))[-9:]
    bundles = FEEDS[profile](tag, n)
    expected = distinct_counts(bundles)
    sent = sum(len(b["objects"]) for b in bundles)
    results = {
        "profile": profile,
        "bundles": len(bundles),
        "objects_sent": sent,
        "objects_distinct": sum(expected.values()),
        "expected": expected,
    }
    phases = ["fresh", "resend", "resend_again"] if resend else ["fresh"]
    for name in phases:
        start = time.perf_counter()
        work_ids = []
        for i, bundle in enumerate(bundles):
            work_id = client.work.initiate_work(
                connector_id, f"{profile} {name} {tag} {i}"
            )
            client.send_bundle_to_api(
                connector_id=connector_id, bundle=json.dumps(bundle), work_id=work_id
            )
            work_ids.append(work_id)
        sent_after = time.perf_counter() - start
        works = wait_complete(client, work_ids, start)
        elapsed = time.perf_counter() - start
        results[name] = {
            "seconds": round(elapsed, 2),
            "sending_seconds": round(sent_after, 2),
            "throughput_per_s": round(sent / elapsed, 1),
            "works_complete": len(works),
            "processed": sum(
                (w.get("tracking") or {}).get("import_processed_number") or 0
                for w in works.values()
            ),
            "errors": sum(len(w.get("errors") or []) for w in works.values()),
            "error_kinds": error_kinds(works.values()),
        }
    results["stored"] = stored_counts(client, tag, expected)
    results["checks"] = {
        "works_complete": all(
            results[p]["works_complete"] == len(bundles)
            for p in phases
        ),
        "no_errors": all(
            results[p]["errors"] == 0 for p in phases
        ),
        "stored": all(
            results["stored"][k] == expected.get(k, 0) for k in results["stored"]
        ),
    }
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--url", default=os.environ.get("BENCH_OPENCTI_URL", "http://localhost:4100")
    )
    parser.add_argument("--token", default=os.environ.get("BENCH_OPENCTI_TOKEN"))
    parser.add_argument("--n", type=int, default=int(os.environ.get("BENCH_N", "1000")))
    parser.add_argument("--out", default=os.environ.get("BENCH_CLIENT_OUT"))
    parser.add_argument(
        "--register", action="store_true", help="register the queue connector and exit"
    )
    parser.add_argument(
        "--queue",
        action="store_true",
        help="push through the queue to the running worker(s)",
    )
    parser.add_argument(
        "--profile",
        default=os.environ.get("BENCH_FEED"),
        help="with --queue: a feed-shaped list of bundles (alienvault, recorded-future, misp) instead of one bundle",
    )
    parser.add_argument(
        "--resend",
        action="store_true",
        default=os.environ.get("BENCH_RESEND") == "true",
        help="with --profile: send the same bundles twice again once stored",
    )
    args = parser.parse_args()
    client = OpenCTIApiClient(
        args.url, args.token, log_level="error", json_logging=True
    )
    if args.register:
        register_connector(client)
        return
    if args.queue and args.profile:
        results = run_feed(client, args.profile, args.n, args.resend)
        print(json.dumps(results, indent=1))
        if args.out:
            with open(args.out, "w", encoding="utf-8") as output:
                json.dump(results, output, indent=1)
        # Errors are a result (today's flow loses objects whose reference another worker is still importing):
        # reported, not failed on
        failed = {
            k: v for k, v in results["checks"].items() if k != "no_errors" and not v
        }
        if failed:
            raise SystemExit(f"Feed checks failed: {failed}")
        return
    if args.queue:
        results = {"queue": run_queue(client, args.n)}
        print(json.dumps(results, indent=1))
        if args.out:
            with open(args.out, "w", encoding="utf-8") as output:
                json.dump(results, output, indent=1)
        work = results["queue"]["work"]
        if work["status"] != "complete" or work["errors"] > 0:
            raise SystemExit("Queue import incomplete")
        return
    connector = (
        next(
            (
                c
                for c in client.connector.list()
                if c.get("connector_type") == "INTERNAL_IMPORT_FILE"
            ),
            None,
        )
        or client.connector.list()[0]
    )
    results = {
        "one_by_one": run(client, connector["id"], args.n, batch=False),
        "batch": run(client, connector["id"], args.n, batch=True),
    }
    one, batch = results["one_by_one"], results["batch"]
    results["checks"] = {
        "same_stored_shape": one["stored"] == batch["stored"],
        "works_complete": all(
            r["work"]["status"] == "complete"
            and r["work"].get("import_processed_number") == r["objects"]
            for r in (one, batch)
        ),
        "no_errors": all(
            r["work"]["errors"] == 0 and r["rejected"] == 0 for r in (one, batch)
        ),
    }
    print(json.dumps(results, indent=1))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as output:
            json.dump(results, output, indent=1)
    if not all(results["checks"].values()):
        raise SystemExit("Full flow checks failed")


if __name__ == "__main__":
    main()
