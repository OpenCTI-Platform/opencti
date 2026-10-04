import threading
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest
from factories import FakeApi

from opencti_analytics.client import (
    AnalyticsClient,
    EdgesPaginationError,
    RetryPolicy,
    RunCancelled,
    error_name,
)


def page(
    edge_ids: List[str], end_cursor: Optional[str], has_next: bool, total: int = 0
) -> Dict[str, Any]:
    return {
        "data": {
            "graphAnalyticsEdges": {
                "pageInfo": {
                    "endCursor": end_cursor,
                    "hasNextPage": has_next,
                    "globalCount": total,
                },
                "edges": [
                    {
                        "node": {
                            "id": edge_id,
                            "relationship_type": "uses",
                            "from_id": f"from-{edge_id}",
                            "from_type": "Intrusion-Set",
                            "to_id": f"to-{edge_id}",
                            "to_type": "Malware",
                        }
                    }
                    for edge_id in edge_ids
                ],
            }
        }
    }


class WaitRecorder:
    def __init__(self) -> None:
        self.waits: List[float] = []

    def __call__(self, seconds: float) -> bool:
        self.waits.append(seconds)
        return False


def make_client(api: Any, **kwargs: Any) -> AnalyticsClient:
    return AnalyticsClient(api, MagicMock(), wait=WaitRecorder(), **kwargs)


def waits_of(client: AnalyticsClient) -> List[float]:
    recorder = client._wait  # pylint: disable=protected-access
    assert isinstance(recorder, WaitRecorder)
    return recorder.waits


class TestPagination:
    def test_follows_cursors_until_last_page(self) -> None:
        api = FakeApi(
            [
                page(["e1", "e2"], "c1", True),
                page(["e3"], "c2", True),
                page(["e4"], "c3", False),
            ]
        )
        client = make_client(api)
        edges = list(client.iter_edges("uses", True, page_size=2))
        assert [e.id for e in edges] == ["e1", "e2", "e3", "e4"]
        assert edges[0].from_id == "from-e1"
        assert edges[0].to_type == "Malware"
        assert [call[1]["after"] for call in api.calls] == [None, "c1", "c2"]
        assert {call[1]["first"] for call in api.calls} == {2}
        assert all(call[1]["includeInferred"] is True for call in api.calls)
        assert all(call[1]["relationshipTypes"] == ["uses"] for call in api.calls)

    def test_continues_after_an_empty_page_when_the_cursor_moves(self) -> None:
        api = FakeApi(
            [
                page(["e1"], "c1", True),
                page([], "c2", True),
                page(["e3"], "c3", False),
            ]
        )
        edges = list(make_client(api).iter_edges("uses", False))
        assert [e.id for e in edges] == ["e1", "e3"]

    def test_fails_when_the_cursor_does_not_move(self) -> None:
        api = FakeApi([page(["e1"], "c1", True), page(["e2"], "c1", True)])
        with pytest.raises(EdgesPaginationError):
            list(make_client(api).iter_edges("uses", False))

    def test_fails_when_more_pages_are_announced_without_cursor(self) -> None:
        api = FakeApi([page(["e1"], None, True)])
        with pytest.raises(EdgesPaginationError):
            list(make_client(api).iter_edges("uses", False))

    def test_empty_connection(self) -> None:
        api = FakeApi([{"data": {"graphAnalyticsEdges": None}}])
        assert list(make_client(api).iter_edges("uses", False)) == []

    def test_count_edges_reads_global_count_per_type(self) -> None:
        api = FakeApi([page(["e"], "c", True, 120), page([], None, False, 0)])
        counts = make_client(api).count_edges(["uses", "object"], False)
        assert counts == {"uses": 120, "object": 0}
        assert [call[1]["first"] for call in api.calls] == [1, 1]
        assert [call[1]["relationshipTypes"] for call in api.calls] == [
            ["uses"],
            ["object"],
        ]


class TestRetries:
    def test_transient_errors_are_retried_with_backoff(self) -> None:
        api = FakeApi(
            [
                ValueError({"name": "DATABASE_ERROR", "error_message": "timeout"}),
                ConnectionError("reset"),
                {"data": {"graphAnalyticsStatus": {"manager_enabled": True}}},
            ]
        )
        client = make_client(api, retry=RetryPolicy(5, 1.0, 60.0))
        assert client.status() == {"manager_enabled": True}
        assert waits_of(client) == [1.0, 2.0]

    def test_backoff_is_capped(self) -> None:
        errors: List[Any] = [ConnectionError("down")] * 4
        api = FakeApi(errors + [{"data": {"graphAnalyticsStatus": {}}}])
        client = make_client(api, retry=RetryPolicy(5, 10.0, 25.0))
        client.status()
        assert waits_of(client) == [10.0, 20.0, 25.0, 25.0]

    def test_non_retryable_errors_fail_fast(self) -> None:
        api = FakeApi([ValueError({"name": "FORBIDDEN_ACCESS"}), {"data": {}}])
        client = make_client(api)
        with pytest.raises(ValueError):
            client.status()
        assert len(api.calls) == 1

    def test_gives_up_after_the_last_attempt(self) -> None:
        api = FakeApi([ConnectionError("down")] * 3)
        client = make_client(api, retry=RetryPolicy(3, 1.0, 1.0))
        with pytest.raises(ConnectionError):
            client.status()
        assert len(api.calls) == 3

    def test_empty_response_is_an_error(self) -> None:
        api = FakeApi([{"errors": []}, {"data": {"graphAnalyticsStatus": {}}}])
        assert make_client(api).status() == {}
        assert len(api.calls) == 2

    def test_shutdown_interrupts_the_wait(self) -> None:
        api = FakeApi([ConnectionError("down"), {"data": {}}])
        client = AnalyticsClient(api, MagicMock(), wait=lambda _: True)
        with pytest.raises(RunCancelled):
            client.status()

    def test_no_call_after_shutdown(self) -> None:
        stop_event = threading.Event()
        stop_event.set()
        api = FakeApi([])
        client = AnalyticsClient(api, MagicMock(), stop_event=stop_event)
        with pytest.raises(RunCancelled):
            client.status()
        assert api.calls == []


def test_upsert_sends_the_input() -> None:
    result = {"run_id": "r", "updated_entities": 2}
    api = FakeApi([{"data": {"graphAnalyticsUpsertMetrics": result}}])
    payload = {"run_id": "r", "metrics": [], "complete": True}
    assert make_client(api).upsert_metrics(payload) == result
    assert api.calls[0][1] == {"input": payload}
    assert "graphAnalyticsUpsertMetrics(input: $input)" in api.calls[0][0]


def test_error_name() -> None:
    assert error_name(ValueError({"name": "AUTH_REQUIRED"})) == "AUTH_REQUIRED"
    assert error_name(ValueError("plain")) is None
