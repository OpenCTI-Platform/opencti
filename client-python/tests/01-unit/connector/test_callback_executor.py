from typing import Dict, List
from unittest.mock import MagicMock

import pytest

from pycti.connector.opencti_callback_executor import CallbackExecutor, ErrorCollector

API_ERROR = {
    "code": "API_UNREACHABLE",
    "message": "Source API returned 503",
    "criticity": 3,
}
BAD_VALUE_ERROR = {
    "code": "other.unknown",
    "message": "ValueError: bad value",
    "criticity": 50,
}


class InMemoryErrorCollector(ErrorCollector):
    def __init__(self):
        self.errors: List[Dict] = [{"code": "PREVIOUS", "message": "", "criticity": 1}]
        self.reset_count = 0

    def add_errors(self, errors: List[Dict]) -> None:
        self.errors.extend(errors)

    def reset(self) -> None:
        self.reset_count += 1
        self.errors = []


def _run(callback):
    collector = InMemoryErrorCollector()
    logger = MagicMock()
    metric = MagicMock()
    CallbackExecutor(collector, logger, metric).execute(callback)
    return collector, logger, metric


def test_collector_is_reset_before_the_callback_runs():
    collector = InMemoryErrorCollector()

    def process():
        assert collector.reset_count == 1
        return [API_ERROR]

    CallbackExecutor(collector, MagicMock(), MagicMock()).execute(process)
    assert collector.errors == [API_ERROR]


def test_collector_is_reset_on_each_run_by_default():
    collector = InMemoryErrorCollector()
    executor = CallbackExecutor(collector, MagicMock(), MagicMock())
    executor.execute(lambda: [API_ERROR])
    executor.execute(lambda: [API_ERROR])
    assert collector.reset_count == 2
    assert collector.errors == [API_ERROR]


def test_errors_accumulate_without_reset_on_each_run():
    collector = InMemoryErrorCollector()
    previous_errors = list(collector.errors)
    executor = CallbackExecutor(
        collector, MagicMock(), MagicMock(), reset_on_each_run=False
    )
    executor.execute(lambda: [API_ERROR])
    executor.execute(lambda: [API_ERROR])
    assert collector.reset_count == 0
    assert collector.errors == [*previous_errors, API_ERROR, API_ERROR]


def test_returned_errors_are_validated_before_being_collected():
    collector, logger, metric = _run(lambda: [API_ERROR, {"code": "NO_CRITICITY"}])
    assert collector.errors == [API_ERROR]
    logger.warning.assert_called_once()
    metric.inc.assert_not_called()


def test_raised_exception_is_collected_counted_and_logged():
    def process():
        raise ValueError("bad value")

    collector, logger, metric = _run(process)
    assert collector.errors == [BAD_VALUE_ERROR]
    metric.inc.assert_called_once_with("error_count")
    logger.error.assert_called_once_with(
        "Connector run raised an exception", {"reason": "ValueError: bad value"}
    )


def test_errors_yielded_before_an_exception_are_kept():
    def process():
        yield API_ERROR
        raise ValueError("bad value")

    collector, _, _ = _run(process)
    assert collector.errors == [API_ERROR, BAD_VALUE_ERROR]


def test_base_exceptions_propagate():
    def process():
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        _run(process)
