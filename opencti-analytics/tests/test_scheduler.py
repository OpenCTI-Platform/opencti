from typing import Any, Callable, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from opencti_analytics import app
from opencti_analytics.runner import RunReport
from opencti_analytics.scheduler import Scheduler


class FakeEvent:
    """threading.Event stand-in: records waits, never sleeps."""

    def __init__(self, stop_after_waits: int = 1_000) -> None:
        self.waits: List[float] = []
        self.stopped = False
        self.stop_after_waits = stop_after_waits

    def is_set(self) -> bool:
        return self.stopped

    def set(self) -> None:
        self.stopped = True

    def wait(self, timeout: Optional[float] = None) -> bool:
        self.waits.append(timeout or 0.0)
        if len(self.waits) >= self.stop_after_waits:
            self.stopped = True
        return self.stopped


def runs(statuses: List[str], event: FakeEvent) -> Callable[[], RunReport]:
    remaining = list(statuses)

    def run() -> RunReport:
        status = remaining.pop(0)
        if not remaining:
            event.set()
        return RunReport(run_id="r", status=status)

    return run


def make_scheduler(
    run: Callable[[], RunReport], event: FakeEvent, run_on_start: bool = True
) -> Scheduler:
    return Scheduler(run, 3600.0, run_on_start, MagicMock(), event, 60.0)


class TestScheduler:
    def test_once_runs_a_single_analysis(self) -> None:
        event = FakeEvent()
        run = MagicMock(return_value=RunReport(run_id="r", status="success"))
        report = make_scheduler(run, event).run_once()
        assert report.status == "success"
        run.assert_called_once()
        assert event.waits == []

    def test_once_reports_crashes_as_failures(self) -> None:
        run = MagicMock(side_effect=RuntimeError("boom"))
        assert make_scheduler(run, FakeEvent()).run_once().status == "failed"

    def test_run_on_start_then_interval(self) -> None:
        event = FakeEvent()
        scheduler = make_scheduler(
            runs(["success", "skipped", "success"], event), event
        )
        scheduler.run_forever()
        assert event.waits == [3600.0, 3600.0]

    def test_first_run_waits_without_run_on_start(self) -> None:
        event = FakeEvent()
        scheduler = make_scheduler(runs(["success"], event), event, run_on_start=False)
        scheduler.run_forever()
        assert event.waits == [3600.0]

    def test_failures_are_retried_with_backoff(self) -> None:
        event = FakeEvent()
        statuses = [
            "failed",
            "failed",
            "failed",
            "failed",
            "failed",
            "failed",
            "success",
        ]
        make_scheduler(runs(statuses, event), event).run_forever()
        assert event.waits == [60.0, 120.0, 240.0, 480.0, 960.0, 1920.0]

    def test_a_crash_does_not_stop_the_loop(self) -> None:
        event = FakeEvent(stop_after_waits=2)
        run = MagicMock(side_effect=RuntimeError("boom"))
        make_scheduler(run, event).run_forever()
        assert run.call_count == 2
        assert event.waits == [60.0, 120.0]

    def test_shutdown_during_the_wait(self) -> None:
        event = FakeEvent(stop_after_waits=1)
        run = MagicMock(return_value=RunReport(run_id="r", status="success"))
        make_scheduler(run, event).run_forever()
        run.assert_called_once()

    def test_cancelled_run_stops_the_loop(self) -> None:
        event = FakeEvent()
        run = MagicMock(return_value=RunReport(run_id="r", status="cancelled"))
        make_scheduler(run, event).run_forever()
        run.assert_called_once()
        assert event.waits == []

    def test_backoff_never_exceeds_the_interval(self) -> None:
        scheduler = make_scheduler(MagicMock(), FakeEvent())
        failed = RunReport(run_id="r", status="failed")
        assert scheduler.next_delay(failed, 10) == 3600.0

    def test_backoff_survives_any_number_of_failures(self) -> None:
        scheduler = make_scheduler(MagicMock(), FakeEvent())
        failed = RunReport(run_id="r", status="failed")
        assert scheduler.next_delay(failed, 5000) == 3600.0
        assert scheduler.next_delay(failed, 10**9) == 3600.0


class FakeApi:
    def __init__(self, responses: List[Dict[str, Any]]) -> None:
        self.responses = responses
        self.logger_class = MagicMock()

    def query(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Any:
        return self.responses.pop(0)


def count_page(total: int) -> Dict[str, Any]:
    connection = {
        "pageInfo": {"endCursor": None, "hasNextPage": False, "globalCount": total},
        "edges": [],
    }
    return {"data": {"graphAnalyticsEdges": connection}}


class TestMain:
    @pytest.fixture(autouse=True)
    def environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENCTI_URL", "http://opencti:8080")
        monkeypatch.setenv("OPENCTI_TOKEN", "token")
        monkeypatch.setenv("ANALYTICS_RELATIONSHIP_TYPES", "uses")
        monkeypatch.setenv("ANALYTICS_ENGINE", "networkx")
        monkeypatch.setattr(app.signal, "signal", lambda *_: None)

    def test_once_skips_a_small_platform(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        api = FakeApi([{"data": {"graphAnalyticsStatus": {}}}, count_page(10)])
        monkeypatch.setattr(app, "build_api_client", lambda _settings: api)
        config = str(tmp_path / "missing.yml")
        assert app.main(["--once", "--config", config]) == app.EXIT_OK
        assert api.responses == []

    def test_once_with_force_runs_and_completes(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        upsert = {"data": {"graphAnalyticsUpsertMetrics": {"updated_entities": 0}}}
        api = FakeApi([{"data": {"graphAnalyticsStatus": {}}}, count_page(0), upsert])
        monkeypatch.setattr(app, "build_api_client", lambda _settings: api)
        config = str(tmp_path / "missing.yml")
        assert app.main(["--once", "--force", "--config", config]) == app.EXIT_OK
        assert api.responses == []

    def test_configuration_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        monkeypatch.setenv("ANALYTICS_BATCH_SIZE", "9000")
        config = str(tmp_path / "missing.yml")
        assert app.main(["--once", "--config", config]) == app.EXIT_CONFIG_ERROR
