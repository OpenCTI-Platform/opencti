import threading
from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient
from pycti.api.opencti_api_work import ExpectationBatcher


@pytest.fixture
def api_client():
    """Create an API client instance without performing health check."""
    with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
        client = OpenCTIApiClient(
            url="http://localhost:4000",
            token="test-token",
            ssl_verify=False,
            perform_health_check=False,
        )
        client.app_logger = MagicMock()
        return client


def batcher_for(api_client, **kwargs):
    # A long interval: only explicit flushes and max_pending send
    return ExpectationBatcher(api_client, **{"interval": 3600, **kwargs})


def scripted(outcomes):
    # Each call takes the next outcome: an exception is raised, anything else returned
    def call(*_args, **_kwargs):
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return call


def sent(query_mock):
    return [
        (call.args[0].split("(")[0].split()[-1], call.args[1], call.kwargs["headers"])
        for call in query_mock.call_args_list
    ]


class TestExpectationBatcher:
    """Success reports are counted per work and sent together."""

    def test_sends_one_report_with_the_count(self, api_client):
        batcher = batcher_for(api_client)
        with patch.object(api_client, "query") as query:
            for _ in range(5):
                batcher.add("work-1")
            assert query.call_count == 0
            batcher.flush()
        assert [(name, variables) for name, variables, _ in sent(query)] == [
            ("reportExpectations", {"id": "work-1", "count": 5})
        ]

    def test_counts_each_work_and_draft_apart(self, api_client):
        batcher = batcher_for(api_client)
        with patch.object(api_client, "query") as query:
            batcher.add("work-1")
            api_client.set_draft_id("draft-1")
            batcher.add("work-1")
            batcher.add("work-1")
            api_client.set_draft_id(None)
            batcher.add("work-2")
            batcher.flush()
        reports = {
            (variables["id"], headers["opencti-draft-id"]): variables["count"]
            for _, variables, headers in sent(query)
        }
        assert reports == {
            ("work-1", None): 1,
            ("work-1", "draft-1"): 2,
            ("work-2", None): 1,
        }

    def test_sends_with_the_work_headers_not_the_last_message(self, api_client):
        batcher = batcher_for(api_client)
        api_client.set_applicant_id_header("user-1")
        api_client.set_event_id("event-1")
        api_client.set_work_id("work-other")
        with patch.object(api_client, "query") as query:
            batcher.add("work-1")
            batcher.flush()
        headers = sent(query)[0][2]
        assert headers["opencti-work-id"] == "work-1"
        assert "opencti-applicant-id" not in headers
        assert "opencti-event-id" not in headers
        assert headers["Authorization"] == api_client.request_headers["Authorization"]
        assert query.call_args.kwargs["session"] is batcher._session

    def test_sends_once_max_pending_is_reached(self, api_client):
        batcher = batcher_for(api_client, max_pending=3)
        sent_event = threading.Event()
        with patch.object(
            api_client, "query", side_effect=lambda *a, **k: sent_event.set()
        ) as query:
            batcher.add("work-1")
            batcher.add("work-1")
            assert not sent_event.wait(0.2)
            batcher.add("work-1")
            assert sent_event.wait(5)
        assert query.call_args.args[1] == {"id": "work-1", "count": 3}

    def test_falls_back_to_single_reports_on_an_older_platform(self, api_client):
        batcher = batcher_for(api_client)
        unknown = ValueError(
            {
                "name": "GRAPHQL_VALIDATION_FAILED",
                "error_message": 'Unknown argument "count" on field "WorkEditMutations.reportExpectation".',
            }
        )

        def platform(query, variables, *args, **kwargs):
            if "count" in variables:
                raise unknown

        with patch.object(api_client, "query", side_effect=platform) as query:
            batcher.add("work-1")
            batcher.add("work-1")
            batcher.flush()
            batcher.add("work-1")
            batcher.flush()
        names = [name for name, _, _ in sent(query)]
        assert names == [
            "reportExpectations",
            "reportExpectation",
            "reportExpectation",
            "reportExpectation",
        ]

    def test_retries_a_failed_send_then_drops_it(self, api_client):
        batcher = batcher_for(api_client, max_attempts=2)
        with patch.object(
            api_client, "query", side_effect=ConnectionError("down")
        ) as query:
            batcher.add("work-1")
            batcher.flush()
            batcher.flush()
            batcher.flush()
        assert query.call_count == 2
        api_client.app_logger.error.assert_called_once()

    def test_a_failed_send_is_counted_with_the_next_ones(self, api_client):
        batcher = batcher_for(api_client)
        outcomes = [ConnectionError("down"), None]
        with patch.object(api_client, "query", side_effect=scripted(outcomes)) as query:
            batcher.add("work-1")
            batcher.flush()
            batcher.add("work-1")
            batcher.flush()
        assert query.call_args.args[1] == {"id": "work-1", "count": 2}

    def test_single_reports_resume_where_they_failed(self, api_client):
        batcher = batcher_for(api_client)
        batcher._count_supported = False
        outcomes = [None, ConnectionError("down"), None, None]
        with patch.object(api_client, "query", side_effect=scripted(outcomes)) as query:
            for _ in range(3):
                batcher.add("work-1")
            batcher.flush()
            batcher.flush()
        # 3 reports: 1 sent, 1 failed, then the 2 left; never 4 counted
        assert query.call_count == 4
        assert outcomes == []


class TestReportExpectationSuccess:
    """The work API batches successes only when bundles go through the queue."""

    def test_batches_when_sending_to_queue(self, api_client):
        with patch.object(api_client, "query") as query:
            api_client.work.report_expectation_success("work-1")
            api_client.work.report_expectation_success("work-1")
            api_client.work.flush_expectations()
        assert query.call_count == 1
        assert query.call_args.args[1] == {"id": "work-1", "count": 2}

    def test_does_nothing_without_queue(self, api_client):
        api_client.bundle_send_to_queue = False
        with patch.object(api_client, "query") as query:
            api_client.work.report_expectation_success("work-1")
            api_client.work.flush_expectations()
        assert query.call_count == 0
