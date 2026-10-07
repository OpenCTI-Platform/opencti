"""Write-back of a run through graphAnalyticsUpsertMetrics.

Every node of the analyzed graph gets exactly one entry carrying all its
run-owned metrics: an entity outside any cluster carries explicit null cluster
fields, so the platform detaches it from the cluster it belonged to. All the
calls share the run id; the last one carries `complete: true`, which makes the
platform drop the clusters and assignments of older runs.
"""

import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, TypeVar

from opencti_analytics.algorithms import AnalysisResult
from opencti_analytics.classification import MAX_FEATURE_IDS, Cluster
from opencti_analytics.client import AnalyticsClient, Logger, RunCancelled
from opencti_analytics.config import MAX_UPSERT_CLUSTERS, MAX_UPSERT_METRICS
from opencti_analytics.graph import AnalysisGraph

# The platform keeps at most 20 representatives per cluster
MAX_REPRESENTATIVE_IDS = 20

T = TypeVar("T")
Batch = Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]


@dataclass
class UpsertSummary:
    calls: int = 0
    metrics: int = 0
    clusters: int = 0
    updated_entities: int = 0
    skipped_entities: int = 0
    upserted_clusters: int = 0
    removed_clusters: int = 0

    def add(self, result: Dict[str, Any]) -> None:
        self.calls += 1
        self.updated_entities += int(result.get("updated_entities") or 0)
        self.skipped_entities += int(result.get("skipped_entities") or 0)
        self.upserted_clusters += int(result.get("upserted_clusters") or 0)
        self.removed_clusters += int(result.get("removed_clusters") or 0)


def metric_entries(
    graph: AnalysisGraph, result: AnalysisResult
) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for node in range(graph.node_count):
        entry: Dict[str, Any] = {"entity_id": graph.ids[node]}
        if result.betweenness is not None:
            entry["betweenness_approx"] = result.betweenness[node]
        cluster = result.cluster_of.get(node)
        entry["cluster_id"] = cluster.cluster_id if cluster else None
        entry["cluster_size"] = cluster.members_count if cluster else None
        entry["cluster_kind"] = cluster.kind if cluster else None
        entries.append(entry)
    return entries


def cluster_payload(cluster: Cluster) -> Dict[str, Any]:
    return {
        "cluster_id": cluster.cluster_id,
        "cluster_kind": cluster.kind,
        "members_count": cluster.members_count,
        "representative_ids": list(cluster.representative_ids[:MAX_REPRESENTATIVE_IDS]),
        "features": [
            {"family": feature.family, "ids": list(feature.ids[:MAX_FEATURE_IDS])}
            for feature in cluster.features
        ],
    }


def chunked(items: Sequence[T], size: int) -> List[List[T]]:
    return [list(items[i : i + size]) for i in range(0, len(items), size)]


def plan_batches(
    metrics: Sequence[Dict[str, Any]],
    clusters: Sequence[Dict[str, Any]],
    batch_size: int,
    cluster_batch_size: int,
) -> List[Batch]:
    """Pair metric and cluster chunks; always at least one (possibly empty) call
    so that a run over an empty graph still completes."""
    metric_chunks = chunked(metrics, min(batch_size, MAX_UPSERT_METRICS))
    cluster_chunks = chunked(clusters, min(cluster_batch_size, MAX_UPSERT_CLUSTERS))
    count = max(len(metric_chunks), len(cluster_chunks), 1)
    return [
        (
            metric_chunks[i] if i < len(metric_chunks) else [],
            cluster_chunks[i] if i < len(cluster_chunks) else [],
        )
        for i in range(count)
    ]


def build_payloads(
    run_id: str, process_version: str, batches: Sequence[Batch]
) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    payloads: List[Dict[str, Any]] = []
    for index, (metrics, clusters) in enumerate(batches):
        for entry in metrics:
            if entry["entity_id"] in seen:
                raise ValueError(f"Duplicate metric entry: {entry['entity_id']}")
            seen.add(entry["entity_id"])
        payloads.append(
            {
                "run_id": run_id,
                "process_version": process_version,
                "metrics": metrics,
                "clusters": clusters,
                "complete": index == len(batches) - 1,
            }
        )
    return payloads


class ResultWriter:  # pylint: disable=too-few-public-methods
    def __init__(
        self,
        client: AnalyticsClient,
        logger: Logger,
        process_version: str,
        batch_size: int,
        cluster_batch_size: int,
        stop_event: Optional[threading.Event] = None,
    ) -> None:
        self.client = client
        self.logger = logger
        self.process_version = process_version
        self.batch_size = batch_size
        self.cluster_batch_size = cluster_batch_size
        self.stop_event = stop_event or threading.Event()

    def write(
        self, run_id: str, graph: AnalysisGraph, result: AnalysisResult
    ) -> UpsertSummary:
        metrics = metric_entries(graph, result)
        clusters = [cluster_payload(cluster) for cluster in result.clusters]
        batches = plan_batches(
            metrics, clusters, self.batch_size, self.cluster_batch_size
        )
        payloads = build_payloads(run_id, self.process_version, batches)
        summary = UpsertSummary(metrics=len(metrics), clusters=len(clusters))
        for index, payload in enumerate(payloads):
            if self.stop_event.is_set():
                # never complete a partially written run
                raise RunCancelled("graphAnalyticsUpsertMetrics")
            response = self.client.upsert_metrics(payload)
            summary.add(response)
            self.logger.debug(
                "Graph analytics batch written",
                {
                    "run_id": run_id,
                    "batch": index + 1,
                    "batches": len(payloads),
                    "metrics": len(payload["metrics"]),
                    "clusters": len(payload["clusters"]),
                    "complete": payload["complete"],
                },
            )
        return summary
