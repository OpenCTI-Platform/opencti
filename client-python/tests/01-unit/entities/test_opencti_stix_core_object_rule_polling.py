from types import SimpleNamespace

from pycti.entities import opencti_stix_core_object as stix_core_object_module
from pycti.entities.opencti_stix_core_object import StixCoreObject


class _PollingClient:
    def __init__(self, result_key):
        self.result_key = result_key
        self.responses = [False, False, True]
        self.calls = []
        self.app_logger = SimpleNamespace(
            info=lambda *_args, **_kwargs: None,
            error=lambda *_args, **_kwargs: None,
        )

    def query(self, query, variables):
        self.calls.append((query, variables))
        return {"data": {self.result_key: self.responses.pop(0)}}


def test_rule_apply_async_waits_between_incomplete_polls(monkeypatch):
    client = _PollingClient("ruleApplyAsync")
    sleep_calls = []
    monkeypatch.setattr(
        stix_core_object_module.time,
        "sleep",
        lambda seconds: sleep_calls.append(seconds),
    )

    StixCoreObject(client).rule_apply_async(
        element_id="indicator--1",
        rule_id="rule--1",
        execution_id="execution--1",
        poll_interval_seconds=0.25,
    )

    assert len(client.calls) == 3
    assert sleep_calls == [0.25, 0.25]


def test_rule_rescan_async_waits_between_incomplete_polls_and_sends_execution_id(
    monkeypatch,
):
    client = _PollingClient("rulesRescanAsync")
    sleep_calls = []
    monkeypatch.setattr(
        stix_core_object_module.time,
        "sleep",
        lambda seconds: sleep_calls.append(seconds),
    )

    StixCoreObject(client).rule_rescan_async(
        element_id="indicator--1",
        execution_id="execution--1",
        poll_interval_seconds=0.5,
    )

    assert len(client.calls) == 3
    assert sleep_calls == [0.5, 0.5]
    query, variables = client.calls[0]
    assert "$executionId: ID!" in query
    assert "executionId: $executionId" in query
    assert variables == {"elementId": "indicator--1", "executionId": "execution--1"}
