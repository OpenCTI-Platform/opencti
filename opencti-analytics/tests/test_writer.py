import threading
from typing import Any, Dict, List, Tuple

import pytest
from factories import build_graph, clique, edge, settings

from opencti_analytics import __version__
from opencti_analytics.algorithms import AnalysisResult, analyze
from opencti_analytics.classification import Cluster, ClusterFeature
from opencti_analytics.client import RunCancelled
from opencti_analytics.engines import NetworkxEngine
from opencti_analytics.graph import AnalysisGraph
from opencti_analytics.writer import (
    ResultWriter,
    build_payloads,
    cluster_payload,
    metric_entries,
    plan_batches,
)


class RecordingClient:
    def __init__(self, stop_after: int = -1, stop_event: Any = None) -> None:
        self.payloads: List[Dict[str, Any]] = []
        self.stop_after = stop_after
        self.stop_event = stop_event

    def upsert_metrics(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.payloads.append(payload)
        if len(self.payloads) == self.stop_after:
            self.stop_event.set()
        return {
            "run_id": payload["run_id"],
            "updated_entities": len(payload["metrics"]),
            "skipped_entities": 0,
            "upserted_clusters": len(payload["clusters"]),
            "removed_clusters": 2 if payload["complete"] else 0,
        }


def analyzed_graph() -> Tuple[AnalysisGraph, AnalysisResult]:
    """Two clusters, and 15 isolated pairs that belong to no cluster."""
    records = clique("m", 5, "Malware") + clique("d", 4, "Domain-Name")
    records += [edge((f"u-{i}", "Url"), (f"v-{i}", "Url")) for i in range(15)]
    graph = build_graph(records)
    return graph, analyze(graph, NetworkxEngine(), settings())


class TestPlanBatches:
    def test_chunk_sizes_and_pairing(self) -> None:
        metrics = [{"entity_id": str(i)} for i in range(11)]
        clusters = [{"cluster_id": str(i)} for i in range(7)]
        batches = plan_batches(metrics, clusters, 4, 2)
        assert [len(m) for m, _ in batches] == [4, 4, 3, 0]
        assert [len(c) for _, c in batches] == [2, 2, 2, 1]

    def test_platform_limits_are_enforced(self) -> None:
        metrics = [{"entity_id": str(i)} for i in range(5001)]
        batches = plan_batches(metrics, [], 10000, 10000)
        assert [len(m) for m, _ in batches] == [5000, 1]

    def test_empty_run_still_completes(self) -> None:
        payloads = build_payloads("run", "1.0", plan_batches([], [], 10, 10))
        assert payloads == [
            {
                "run_id": "run",
                "process_version": "1.0",
                "metrics": [],
                "clusters": [],
                "complete": True,
            }
        ]

    def test_duplicate_entities_are_rejected(self) -> None:
        batches = plan_batches([{"entity_id": "a"}, {"entity_id": "a"}], [], 1, 1)
        with pytest.raises(ValueError):
            build_payloads("run", "1.0", batches)


class TestMetricEntries:
    def test_every_node_once_with_run_owned_metrics(self) -> None:
        graph, result = analyzed_graph()
        entries = metric_entries(graph, result)
        assert [e["entity_id"] for e in entries] == graph.ids
        for node, entry in enumerate(entries):
            assert "betweenness_approx" in entry
            cluster = result.cluster_of.get(node)
            if cluster is None:
                # explicit nulls: the platform detaches the entity from its old cluster
                assert entry["cluster_id"] is None
                assert entry["cluster_kind"] is None
                assert entry["cluster_size"] is None
            else:
                assert entry["cluster_id"] == cluster.cluster_id
                assert entry["cluster_kind"] == cluster.kind
                assert entry["cluster_size"] == cluster.members_count

    def test_cluster_payload_truncation(self) -> None:
        cluster = Cluster(
            cluster_id="id",
            kind="campaign",
            anchor="a",
            members=tuple(range(30)),
            representative_ids=tuple(str(i) for i in range(25)),
            features=(ClusterFeature("techniques", tuple(str(i) for i in range(70))),),
        )
        payload = cluster_payload(cluster)
        assert payload["members_count"] == 30
        assert len(payload["representative_ids"]) == 20
        assert len(payload["features"][0]["ids"]) == 50


class TestResultWriter:
    def test_batches_share_run_and_complete_last(self) -> None:
        graph, result = analyzed_graph()
        client = RecordingClient()
        writer = ResultWriter(client, _Logger(), __version__, 7, 1)
        summary = writer.write("run-1", graph, result)
        payloads = client.payloads
        assert len(payloads) == -(-graph.node_count // 7)
        assert all(len(p["metrics"]) <= 7 for p in payloads)
        assert all(len(p["clusters"]) <= 1 for p in payloads)
        assert {p["run_id"] for p in payloads} == {"run-1"}
        assert {p["process_version"] for p in payloads} == {__version__}
        assert [p["complete"] for p in payloads] == [False] * (len(payloads) - 1) + [
            True
        ]
        written = [m["entity_id"] for p in payloads for m in p["metrics"]]
        assert sorted(written) == sorted(set(written)) == sorted(graph.ids)
        assert sum(len(p["clusters"]) for p in payloads) == len(result.clusters) == 2
        assert summary.updated_entities == graph.node_count
        assert summary.upserted_clusters == 2
        assert summary.removed_clusters == 2
        assert summary.calls == len(payloads)

    def test_shutdown_never_completes_a_partial_run(self) -> None:
        graph, result = analyzed_graph()
        stop_event = threading.Event()
        client = RecordingClient(stop_after=1, stop_event=stop_event)
        writer = ResultWriter(client, _Logger(), __version__, 5, 5, stop_event)
        with pytest.raises(RunCancelled):
            writer.write("run-1", graph, result)
        assert len(client.payloads) == 1
        assert not client.payloads[0]["complete"]


class _Logger:
    def debug(self, message: str, meta: Any = None) -> None:
        pass
