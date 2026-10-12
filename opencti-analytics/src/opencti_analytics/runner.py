"""One analytics run: count, fetch, analyze, write back."""

import threading
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from opencti_analytics import __version__
from opencti_analytics.algorithms import analyze
from opencti_analytics.client import AnalyticsClient, Logger, RunCancelled
from opencti_analytics.config import Settings
from opencti_analytics.engines import GraphEngine
from opencti_analytics.graph import AnalysisGraph, GraphBuilder
from opencti_analytics.telemetry import Telemetry
from opencti_analytics.writer import ResultWriter, UpsertSummary

STATUS_SUCCESS = "success"
STATUS_SKIPPED = "skipped"
STATUS_DISABLED = "disabled"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"


@dataclass
class RunReport:  # pylint: disable=too-many-instance-attributes
    run_id: str
    status: str
    reason: str = ""
    duration: float = 0.0
    platform_edges: int = 0
    fetched_edges: int = 0
    nodes: int = 0
    edges: int = 0
    clusters: int = 0
    summary: Optional[UpsertSummary] = None


class AnalyticsRunner:  # pylint: disable=too-few-public-methods
    def __init__(
        self,
        settings: Settings,
        client: AnalyticsClient,
        logger: Logger,
        engine: GraphEngine,
        telemetry: Optional[Telemetry] = None,
        stop_event: Optional[threading.Event] = None,
        process_version: str = __version__,
    ) -> None:
        self.settings = settings
        self.client = client
        self.logger = logger
        self.engine = engine
        self.telemetry = telemetry
        self.stop_event = stop_event or threading.Event()
        self.writer = ResultWriter(
            client,
            logger,
            process_version,
            settings.batch_size,
            settings.cluster_batch_size,
            self.stop_event,
        )

    def run_once(self) -> RunReport:
        run_id = str(uuid.uuid4())
        started = time.monotonic()
        if not self.settings.enabled:
            self.logger.info("Graph analytics disabled (analytics.enabled is false)")
            return RunReport(run_id=run_id, status=STATUS_DISABLED)
        self.logger.info(
            "Graph analytics run started",
            {"run_id": run_id, "engine": self.engine.name},
        )
        try:
            report = self._run(run_id)
        except RunCancelled as e:
            self.logger.warning(
                "Graph analytics run cancelled by shutdown",
                {"run_id": run_id, "operation": str(e)},
            )
            report = RunReport(run_id=run_id, status=STATUS_CANCELLED, reason=str(e))
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(
                "Graph analytics run failed",
                {"run_id": run_id, "error": type(e).__name__, "reason": str(e)},
            )
            report = RunReport(run_id=run_id, status=STATUS_FAILED, reason=str(e))
        report.duration = time.monotonic() - started
        self._record(report)
        return report

    def _record(self, report: RunReport) -> None:
        if self.telemetry is None:
            return
        try:
            self.telemetry.record_run(
                report.status,
                report.duration,
                nodes=report.nodes,
                edges=report.edges,
                clusters=report.clusters,
                updated_entities=(
                    report.summary.updated_entities if report.summary else 0
                ),
            )
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(
                "Graph analytics telemetry failed",
                {"run_id": report.run_id, "reason": str(e)},
            )

    def _log_platform_status(self, run_id: str) -> None:
        try:
            status = self.client.status()
        except RunCancelled:
            raise
        except Exception as e:  # pylint: disable=broad-except
            self.logger.warning(
                "Graph analytics status unavailable",
                {"run_id": run_id, "reason": str(e)},
            )
            return
        self.logger.info(
            "Graph analytics platform status", {"run_id": run_id, **status}
        )

    def _fetch(
        self, run_id: str, counts: Dict[str, int]
    ) -> Tuple[AnalysisGraph, int, bool]:
        settings = self.settings
        builder = GraphBuilder(settings.max_container_size)
        fetched = 0
        capped = False
        for relationship_type in settings.relationship_types:
            if capped:
                break
            if counts.get(relationship_type, 0) == 0:
                continue
            started = time.monotonic()
            type_fetched = 0
            for edge in self.client.iter_edges(
                relationship_type, settings.include_inferred
            ):
                if fetched >= settings.max_edges:
                    capped = True
                    break
                builder.add(edge)
                fetched += 1
                type_fetched += 1
            self.logger.info(
                "Graph analytics edges fetched",
                {
                    "run_id": run_id,
                    "relationship_type": relationship_type,
                    "edges": type_fetched,
                    "duration_seconds": round(time.monotonic() - started, 3),
                },
            )
        return builder.build(), fetched, capped

    def _too_large(self, run_id: str, edges: int, fetched: int) -> RunReport:
        # Completing a run on a truncated graph would detach every entity and
        # remove every cluster outside the loaded part: never write it.
        self.logger.error(
            "Graph analytics run aborted: the graph exceeds analytics.max_edges, "
            "raise it or narrow analytics.relationship_types",
            {
                "run_id": run_id,
                "edges": edges,
                "fetched_edges": fetched,
                "max_edges": self.settings.max_edges,
            },
        )
        return RunReport(
            run_id=run_id,
            status=STATUS_FAILED,
            reason="max_edges_reached",
            platform_edges=edges,
            fetched_edges=fetched,
        )

    def _run(self, run_id: str) -> RunReport:
        settings = self.settings
        self._log_platform_status(run_id)
        counts = self.client.count_edges(
            settings.relationship_types, settings.include_inferred
        )
        total = sum(counts.values())
        self.logger.info(
            "Graph analytics edge count",
            {
                "run_id": run_id,
                "edges": total,
                "edges_by_type": counts,
                "min_edges": settings.min_edges,
                "force": settings.force,
            },
        )
        if total < settings.min_edges and not settings.force:
            self.logger.info(
                "Graph analytics run skipped: the platform graph analytics manager "
                "covers platforms below analytics.min_edges",
                {"run_id": run_id, "edges": total, "min_edges": settings.min_edges},
            )
            return RunReport(
                run_id=run_id,
                status=STATUS_SKIPPED,
                reason="below_min_edges",
                platform_edges=total,
            )

        if total > settings.max_edges:
            return self._too_large(run_id, total, 0)

        started = time.monotonic()
        graph, fetched, capped = self._fetch(run_id, counts)
        if capped:
            # the graph grew between the count and the fetch
            return self._too_large(run_id, total, fetched)
        stats = graph.stats
        self.logger.info(
            "Graph analytics graph built",
            {
                "run_id": run_id,
                "fetched_edges": fetched,
                "nodes": graph.node_count,
                "edges": graph.edge_count,
                "self_loops": stats.self_loops,
                "relationship_refs": stats.relationship_refs,
                "containment_edges": stats.containment_edges,
                "oversized_containers": stats.oversized_containers,
                "dropped_containment_edges": stats.dropped_containment_edges,
                "duration_seconds": round(time.monotonic() - started, 3),
            },
        )

        result = analyze(graph, self.engine, settings)
        self.logger.info(
            "Graph analytics graph analyzed",
            {
                "run_id": run_id,
                "engine": self.engine.name,
                "components": result.components,
                "largest_component": result.largest_component,
                "hubs": result.hubs,
                "communities": result.clustering.communities,
                "communities_too_small": result.clustering.too_small,
                "communities_too_large": result.clustering.too_large,
                "clusters": result.clustering.clusters,
                "clustered_entities": len(result.cluster_of),
                "betweenness_sources": result.betweenness_sources,
                "durations_seconds": {
                    key: round(value, 3) for key, value in result.durations.items()
                },
            },
        )

        started = time.monotonic()
        summary = self.writer.write(run_id, graph, result)
        self.logger.info(
            "Graph analytics results written",
            {
                "run_id": run_id,
                "calls": summary.calls,
                "metrics": summary.metrics,
                "clusters": summary.clusters,
                "updated_entities": summary.updated_entities,
                "skipped_entities": summary.skipped_entities,
                "upserted_clusters": summary.upserted_clusters,
                "removed_clusters": summary.removed_clusters,
                "duration_seconds": round(time.monotonic() - started, 3),
            },
        )
        return RunReport(
            run_id=run_id,
            status=STATUS_SUCCESS,
            platform_edges=total,
            fetched_edges=fetched,
            nodes=graph.node_count,
            edges=graph.edge_count,
            clusters=len(result.clusters),
            summary=summary,
        )
