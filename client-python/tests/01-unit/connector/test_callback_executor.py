import sys
from typing import Dict, List
from unittest.mock import MagicMock

import pytest

from pycti.connector.opencti_callback_executor import (
    CallbackExecutor,
    ErrorCollector,
    _ConnectorRunError,
)

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

    def add_errors(self, errors: List[_ConnectorRunError]) -> None:
        self.errors.extend(error.model_dump() for error in errors)

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


def test_raised_exception_is_logged_while_it_is_handled():
    # AppLogger.error() logs with exc_info=1: the traceback is the exception being handled when it is called
    raised = ValueError("bad value")
    handled_when_logged = []
    logger = MagicMock()
    logger.error.side_effect = lambda *args: handled_when_logged.append(
        sys.exc_info()[1]
    )

    def process():
        raise raised

    CallbackExecutor(InMemoryErrorCollector(), logger, MagicMock()).execute(process)
    assert handled_when_logged == [raised]


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


def _execute(callback) -> bool:
    return CallbackExecutor(InMemoryErrorCollector(), MagicMock(), MagicMock()).execute(
        callback
    )


@pytest.mark.parametrize(
    "result",
    [None, [], True, "done", iter([])],
    ids=["none", "empty-list", "true", "status-string", "empty-generator"],
)
def test_run_without_errors_succeeds(result):
    assert _execute(lambda: result) is True


def test_run_returning_only_malformed_errors_succeeds():
    # Malformed errors are dropped with a warning: nothing is reported
    assert _execute(lambda: [{"code": "A"}, "not an error"]) is True


def test_run_returning_a_single_error_dict_succeeds():
    # Ignored with a warning, as it is not a list
    assert _execute(lambda: API_ERROR) is True


def _error(criticity: int) -> Dict:
    return {"code": f"CRITICITY_{criticity}", "message": "", "criticity": criticity}


@pytest.mark.parametrize(
    "criticities, succeeded",
    [
        ([0], True),
        ([39], True),
        ([40], False),
        ([0, 39, 3], True),
        ([0, 50, 3], False),
    ],
    ids=["zero", "below-threshold", "threshold", "all-below", "one-blocking"],
)
def test_run_returning_errors_fails_from_a_blocking_criticity(criticities, succeeded):
    assert _execute(lambda: [_error(c) for c in criticities]) is succeeded


def test_run_yielding_a_blocking_error_fails():
    def process():
        yield _error(40)

    assert _execute(process) is False


def test_run_raising_without_criticity_fails():
    def process():
        raise ValueError("bad value")

    assert _execute(process) is False


@pytest.mark.parametrize(
    "criticity, succeeded",
    [(39, True), (40, False)],
    ids=["below-threshold", "threshold"],
)
def test_run_raising_uses_the_criticity_of_the_exception(criticity, succeeded):
    exc = Exception("advisory")
    exc.criticity = criticity

    def process():
        raise exc

    assert _execute(process) is succeeded


def test_run_raising_a_blocking_exception_after_advisory_errors_fails():
    def process():
        yield _error(0)
        raise ValueError("bad value")

    assert _execute(process) is False
