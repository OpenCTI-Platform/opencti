from typing import Any, Dict, Iterator, List, Optional, Sequence
from unittest.mock import MagicMock

from factories import clique, edge, settings

from opencti_analytics import __version__
from opencti_analytics.engines import NetworkxEngine
from opencti_analytics.graph import EdgeRecord
from opencti_analytics.runner import AnalyticsRunner


class FakeClient:
    def __init__(
        self,
        edges_by_type: Dict[str, List[EdgeRecord]],
        counts: Optional[Dict[str, int]] = None,
        fail_upsert: bool = False,
    ) -> None:
        self.edges_by_type = edges_by_type
        self.counts = counts
        self.fail_upsert = fail_upsert
        self.fetched_types: List[str] = []
        self.payloads: List[Dict[str, Any]] = []

    def status(self) -> Dict[str, Any]:
        return {"manager_enabled": True}

    def count_edges(
        self, relationship_types: Sequence[str], include_inferred: bool
    ) -> Dict[str, int]:
        if self.counts is not None:
            return {t: self.counts.get(t, 0) for t in relationship_types}
        return {t: len(self.edges_by_type.get(t, [])) for t in relationship_types}

    def iter_edges(
        self, relationship_type: str, include_inferred: bool
    ) -> Iterator[EdgeRecord]:
        self.fetched_types.append(relationship_type)
        yield from self.edges_by_type.get(relationship_type, [])

    def upsert_metrics(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self.fail_upsert:
            raise ValueError({"name": "DATABASE_ERROR"})
        self.payloads.append(payload)
        return {"updated_entities": len(payload["metrics"]), "upserted_clusters": 1}


def platform_edges() -> Dict[str, List[EdgeRecord]]:
    uses = clique("is", 4, "Intrusion-Set")
    uses = [
        EdgeRecord(e.id, "uses", e.from_id, e.from_type, e.to_id, e.to_type)
        for e in uses
    ]
    report = ("report", "Report")
    objects = [edge(report, (f"ip-{i}", "IPv4-Addr"), "object") for i in range(3)]
    return {"uses": uses, "object": objects}


def make_runner(client: FakeClient, **overrides: Any) -> AnalyticsRunner:
    return AnalyticsRunner(settings(**overrides), client, MagicMock(), NetworkxEngine())


class TestSmallPlatform:
    def test_skipped_below_min_edges(self) -> None:
        client = FakeClient(platform_edges())
        report = make_runner(client, min_edges=1000).run_once()
        assert report.status == "skipped"
        assert report.platform_edges == 9
        assert client.fetched_types == []
        assert client.payloads == []

    def test_force_bypasses_min_edges(self) -> None:
        client = FakeClient(platform_edges())
        report = make_runner(client, min_edges=1000, force=True).run_once()
        assert report.status == "success"
        assert client.payloads[-1]["complete"] is True

    def test_large_platform_runs(self) -> None:
        client = FakeClient(platform_edges())
        report = make_runner(client, min_edges=9).run_once()
        assert report.status == "success"


class TestRun:
    def test_end_to_end(self) -> None:
        client = FakeClient(platform_edges())
        report = make_runner(client).run_once()
        assert report.status == "success"
        assert report.nodes == 8
        assert report.clusters == 2
        assert report.summary is not None and report.summary.calls == 1
        (payload,) = client.payloads
        assert payload["complete"] is True
        assert payload["process_version"] == __version__
        assert payload["run_id"] == report.run_id
        assert len(payload["metrics"]) == 8
        assert sorted(c["cluster_kind"] for c in payload["clusters"]) == [
            "campaign",
            "infrastructure",
        ]

    def test_types_without_edges_are_not_fetched(self) -> None:
        client = FakeClient(platform_edges())
        make_runner(client).run_once()
        assert client.fetched_types == ["uses", "object"]

    def test_graph_above_max_edges_is_never_loaded_nor_written(self) -> None:
        client = FakeClient(platform_edges())
        runner = make_runner(client, max_edges=5)
        report = runner.run_once()
        assert report.status == "failed"
        assert report.reason == "max_edges_reached"
        assert client.fetched_types == []
        assert client.payloads == []
        runner.logger.error.assert_called()

    def test_graph_growing_past_max_edges_during_the_fetch_is_not_written(
        self,
    ) -> None:
        # the counts are below the limit, the fetch is not
        client = FakeClient(platform_edges(), counts={"uses": 2, "object": 1})
        runner = make_runner(client, max_edges=5)
        report = runner.run_once()
        assert report.status == "failed"
        assert report.reason == "max_edges_reached"
        assert report.fetched_edges == 5
        assert client.payloads == []

    def test_failure_is_reported_not_raised(self) -> None:
        client = FakeClient(platform_edges(), fail_upsert=True)
        runner = make_runner(client)
        report = runner.run_once()
        assert report.status == "failed"
        runner.logger.error.assert_called()

    def test_disabled(self) -> None:
        client = FakeClient(platform_edges())
        report = make_runner(client, enabled=False).run_once()
        assert report.status == "disabled"
        assert client.fetched_types == []

    def test_telemetry_is_recorded_and_never_breaks_a_run(self) -> None:
        client = FakeClient(platform_edges())
        telemetry = MagicMock()
        telemetry.record_run.side_effect = RuntimeError("exporter down")
        runner = AnalyticsRunner(
            settings(), client, MagicMock(), NetworkxEngine(), telemetry
        )
        report = runner.run_once()
        assert report.status == "success"
        telemetry.record_run.assert_called_once()
        assert telemetry.record_run.call_args[0][0] == "success"
