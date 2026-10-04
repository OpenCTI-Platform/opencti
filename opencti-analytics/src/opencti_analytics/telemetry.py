"""Optional Prometheus telemetry, exposed through OpenTelemetry like the worker.

Instruments are created against the global meter: they are no-ops until
`start_telemetry` installs the Prometheus-backed meter provider.
"""

from typing import Any, Optional, Tuple

from opentelemetry import metrics
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from prometheus_client import start_http_server

meter = metrics.get_meter(__name__)
runs_counter = meter.create_counter(
    name="opencti_analytics_runs",
    description="number of analytics runs, by status (success, skipped, failed)",
)
failures_counter = meter.create_counter(
    name="opencti_analytics_failures",
    description="number of failed analytics runs",
)
run_duration_histogram = meter.create_histogram(
    name="opencti_analytics_run_duration",
    unit="s",
    description="duration of analytics runs",
)
nodes_gauge = meter.create_gauge(
    name="opencti_analytics_nodes",
    description="number of nodes of the last analyzed graph",
)
edges_gauge = meter.create_gauge(
    name="opencti_analytics_edges",
    description="number of edges of the last analyzed graph",
)
clusters_gauge = meter.create_gauge(
    name="opencti_analytics_clusters",
    description="number of clusters written by the last run",
)
entities_updated_gauge = meter.create_gauge(
    name="opencti_analytics_entities_updated",
    description="number of entities updated by the last run",
)


class Telemetry:
    def __init__(self) -> None:
        self._server: Optional[Tuple[Any, Any]] = None

    def start(self, port: int, host: str) -> None:
        server, thread = start_http_server(port=port, addr=host)
        self._server = (server, thread)
        provider = MeterProvider(
            resource=Resource(attributes={SERVICE_NAME: "opencti-analytics"}),
            metric_readers=[PrometheusMetricReader()],
        )
        metrics.set_meter_provider(provider)

    def stop(self) -> None:
        if self._server is None:
            return
        server, thread = self._server
        server.shutdown()
        server.server_close()
        thread.join()
        self._server = None

    @staticmethod
    def record_run(
        status: str,
        duration: float,
        nodes: int = 0,
        edges: int = 0,
        clusters: int = 0,
        updated_entities: int = 0,
    ) -> None:
        runs_counter.add(1, {"status": status})
        run_duration_histogram.record(duration, {"status": status})
        if status == "failed":
            failures_counter.add(1)
        if status == "success":
            nodes_gauge.set(nodes)
            edges_gauge.set(edges)
            clusters_gauge.set(clusters)
            entities_updated_gauge.set(updated_entities)
