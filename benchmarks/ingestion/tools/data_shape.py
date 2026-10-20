"""Data shape report: what an existing OpenCTI platform stores, read from Elasticsearch or OpenSearch.

Read-only. Counts entities, relationships and embedded refs by type, and lists the entities at the end of the
most core relationships (the candidates for lock contention). Useful to pick benchmark parameters that look
like your own data.
"""

import argparse
import base64
import json
import urllib.error
import urllib.request

INDICES = [
    "stix_domain_objects",
    "stix_cyber_observables",
    "stix_meta_objects",
    "stix_core_relationships",
    "stix_sighting_relationships",
    "stix_meta_relationships",
]


class Engine:
    def __init__(self, url, user=None, password=None):
        self.url = url.rstrip("/")
        self.headers = {"content-type": "application/json"}
        if user:
            token = base64.b64encode(f"{user}:{password or ''}".encode()).decode()
            self.headers["authorization"] = f"Basic {token}"

    def call(self, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"{self.url}/{path}", data=data, headers=self.headers
        )
        with urllib.request.urlopen(request) as response:
            return json.load(response)


def top_types(engine, index, size=12):
    body = {
        "size": 0,
        "aggs": {"t": {"terms": {"field": "entity_type.keyword", "size": size}}},
    }
    result = engine.call(f"{index}/_search", body)
    return {b["key"]: b["doc_count"] for b in result["aggregations"]["t"]["buckets"]}


def most_connected(engine, index, size=10):
    body = {
        "size": 0,
        "aggs": {
            "c": {
                "nested": {"path": "connections"},
                "aggs": {
                    "top": {
                        "terms": {
                            "field": "connections.internal_id.keyword",
                            "size": size,
                        },
                        "aggs": {
                            "type": {
                                "terms": {
                                    "field": "connections.types.keyword",
                                    "size": 1,
                                }
                            },
                            "role": {
                                "terms": {
                                    "field": "connections.role.keyword",
                                    "size": 4,
                                }
                            },
                        },
                    }
                },
            }
        },
    }
    result = engine.call(f"{index}/_search", body)
    rows = []
    for bucket in result["aggregations"]["c"]["top"]["buckets"]:
        types = bucket["type"]["buckets"]
        rows.append(
            {
                "internal_id": bucket["key"],
                "type": types[0]["key"] if types else None,
                "relationships": bucket["doc_count"],
                "by_role": {
                    r["key"]: r["doc_count"] for r in bucket["role"]["buckets"]
                },
            }
        )
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--es-url", default="http://127.0.0.1:9200")
    parser.add_argument("--es-user")
    parser.add_argument("--es-password")
    parser.add_argument(
        "--prefix", default="opencti", help="the platform's elasticsearch:index_prefix"
    )
    parser.add_argument("--out", help="also write the report as JSON")
    args = parser.parse_args()

    engine = Engine(args.es_url, args.es_user, args.es_password)
    report = {"prefix": args.prefix, "counts": {}, "types": {}}
    for name in INDICES:
        index = f"{args.prefix}_{name}"
        try:
            # _count, not _cat/indices: the latter also counts nested documents
            report["counts"][name] = engine.call(f"{index}/_count")["count"]
        except urllib.error.HTTPError:
            report["counts"][name] = 0
            continue
        if report["counts"][name] > 0:
            report["types"][name] = top_types(engine, index)
    if report["counts"].get("stix_core_relationships"):
        report["most_connected"] = most_connected(
            engine, f"{args.prefix}_stix_core_relationships"
        )

    entities = sum(report["counts"].get(i, 0) for i in INDICES[:3])
    relationships = report["counts"].get("stix_core_relationships", 0) + report[
        "counts"
    ].get("stix_sighting_relationships", 0)
    print(f"Platform '{args.prefix}' on {args.es_url}")
    print(f"  entities (domain, observables, meta): {entities:,}")
    print(f"  relationships (core, sightings):      {relationships:,}")
    print(
        f"  embedded refs (meta relationships):   {report['counts'].get('stix_meta_relationships', 0):,}"
    )
    if entities:
        print(f"  relationships per entity:             {relationships / entities:.1f}")
    for name, types in report["types"].items():
        print(f"\n  {name}")
        for entity_type, count in types.items():
            print(f"    {entity_type:34s}{count:>12,}")
    if report.get("most_connected"):
        print("\n  most connected entities (core relationships)")
        for row in report["most_connected"]:
            print(
                f"    {row['internal_id']}  {row['type'] or '?':22s}{row['relationships']:>8,}  {row['by_role']}"
            )
    if args.out:
        with open(args.out, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=1)


if __name__ == "__main__":
    main()
