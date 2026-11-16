"""Unit tests for the worker telemetry instrumentation.

They check that the instruments are bound to the MeterProvider configured by
the worker, that the ingestion units gauges reflect the pool selector state at
collection time, and that bundle processing time keeps sub-second precision.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict
from unittest.mock import MagicMock, patch

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from test_push_handler_resilience import encode_message, make_push_handler

import worker as worker_module
from thread_pool_selector import ThreadPoolSelector


def collect_values(reader: InMemoryMetricReader) -> Dict[str, list]:
    values: Dict[str, list] = {}
    metrics_data = reader.get_metrics_data()
    if metrics_data is None:
        return values
    for resource_metrics in metrics_data.resource_metrics:
        for scope_metrics in resource_metrics.scope_metrics:
            for metric in scope_metrics.metrics:
                # Histogram points expose a sum, counter and gauge points a value
                values[metric.name] = [
                    point.sum if hasattr(point, "sum") else point.value
                    for point in metric.data.data_points
                ]
    return values


class TestWorkerInstrumentsBinding:
    def test_bundle_instruments_are_exported_by_configured_reader(self, monkeypatch):
        reader = InMemoryMetricReader()
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("WORKER_TELEMETRY_ENABLED", "true")
        with patch.object(
            worker_module, "start_http_server", return_value=(MagicMock(), MagicMock())
        ), patch.object(
            worker_module, "PrometheusMetricReader", return_value=reader
        ), patch.object(
            worker_module.metrics, "set_meter_provider"
        ), patch.object(
            worker_module, "OpenCTIApiClient"
        ):
            worker = worker_module.Worker()

        worker.bundles_global_counter.add(3)
        worker.bundles_processing_time_gauge.record(0.25)

        values = collect_values(reader)
        assert values["opencti_bundles_global_counter"] == [3]
        assert values["opencti_bundles_processing_time_gauge"] == [0.25]

    def test_instruments_are_noop_when_telemetry_disabled(self, monkeypatch):
        monkeypatch.setenv("OPENCTI_URL", "http://localhost:4000")
        monkeypatch.setenv("OPENCTI_TOKEN", "test-token")
        monkeypatch.setenv("WORKER_TELEMETRY_ENABLED", "false")
        with patch.object(
            worker_module, "start_http_server"
        ) as start_http_server, patch.object(worker_module, "OpenCTIApiClient"):
            worker = worker_module.Worker()

        start_http_server.assert_not_called()
        # Recording must not fail even though nothing is exported
        worker.bundles_global_counter.add(1)
        worker.bundles_processing_time_gauge.record(0.1)


class TestIngestionUnitsGauges:
    def test_gauges_reflect_both_pools_at_collection_time(self):
        reader = InMemoryMetricReader()
        meter = MeterProvider(metric_readers=[reader]).get_meter("test")
        default_pool = ThreadPoolExecutor(max_workers=3)
        realtime_pool = ThreadPoolExecutor(max_workers=2)
        selector = ThreadPoolSelector(3, default_pool, 2, realtime_pool)
        worker_module.register_ingestion_units_gauges(meter, selector)

        release = threading.Event()
        try:
            selector.submit(False, release.wait)
            selector.submit(True, release.wait)
            values = collect_values(reader)
            assert values["opencti_max_ingestion_units"] == [5]
            assert values["opencti_running_ingestion_units"] == [2]
        finally:
            release.set()
            # Future.result() can return before the done callbacks that
            # decrement the selector counters have run. Shutting the pools
            # down joins their threads, which also waits for those callbacks.
            default_pool.shutdown(wait=True)
            realtime_pool.shutdown(wait=True)

        values = collect_values(reader)
        assert values["opencti_running_ingestion_units"] == [0]


class TestBundleProcessingTime:
    def test_sub_second_processing_time_is_not_truncated(self):
        handler = make_push_handler()

        def slow_import(*_args, **_kwargs):
            time.sleep(0.05)
            return ([], [])

        handler.api.stix2.import_bundle_from_json.side_effect = slow_import
        bundle = {
            "type": "bundle",
            "objects": [{"type": "malware", "id": "malware--1"}],
        }

        assert handler.handle_message(encode_message(bundle)) == "ack"

        recorded = handler.bundles_processing_time_gauge.record.call_args[0][0]
        assert isinstance(recorded, float)
        assert 0 < recorded < 1
