import random
import time

import pytest

from pycti import OpenCTIApiClient, OpenCTIStix2
from pycti.utils import opencti_stix2 as stix2_module
from pycti.utils.opencti_stix2 import (
    ERROR_TYPE_MISSING_REFERENCE,
    PROCESSING_COUNT,
    _env_bool,
    _env_float,
    missing_ref_retry_delay,
)


@pytest.fixture
def opencti_stix2():
    api_client = OpenCTIApiClient(
        "http://fake:4000", "fake", ssl_verify=False, perform_health_check=False
    )
    return OpenCTIStix2(api_client)


@pytest.fixture
def uniform_bounds(monkeypatch):
    """Replace random.uniform by its midpoint and record the (low, high) bounds it was given."""
    bounds = []

    def fake_uniform(low, high):
        bounds.append((low, high))
        return (low + high) / 2

    monkeypatch.setattr(random, "uniform", fake_uniform)
    return bounds


class _MissingRefThenSuccess:
    """import_item stand-in: raises a missing-reference error `failures` times, then succeeds."""

    def __init__(self, failures: int):
        self.failures = failures
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        if self.calls <= self.failures:
            raise Exception(ERROR_TYPE_MISSING_REFERENCE)
        return None


def _run_import_with_retries(monkeypatch, opencti_stix2, failures):
    """Run import_item_with_retries against a failing import_item; capture sleeps and counters."""
    sleeps = []
    attempts = []
    error_adds = []
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))
    monkeypatch.setattr(
        stix2_module.bundles_missing_reference_error_counter,
        "add",
        lambda amount, attributes=None: error_adds.append((amount, attributes)),
    )
    monkeypatch.setattr(
        stix2_module.bundles_missing_reference_retry_attempt_counter,
        "add",
        lambda amount, attributes=None: attempts.append(attributes["attempt"]),
    )
    monkeypatch.setattr(opencti_stix2, "import_item", _MissingRefThenSuccess(failures))
    # No work_id: nothing is reported to the platform on the terminal path.
    result = opencti_stix2.import_item_with_retries({"id": "x", "type": "report"})
    return result, sleeps, attempts, error_adds


# --- schedule function -------------------------------------------------------------------------


def test_default_schedule_is_legacy_flat_wait(monkeypatch, uniform_bounds):
    # Flag off by default: the historical random.uniform(1, 3) on every attempt.
    assert stix2_module.MISSING_REF_RETRY_EXPONENTIAL is False
    delays = [missing_ref_retry_delay(i) for i in range(PROCESSING_COUNT)]
    assert uniform_bounds == [(1, 3)] * PROCESSING_COUNT
    assert delays == [2.0] * PROCESSING_COUNT


def test_exponential_schedule_is_fast_first(monkeypatch, uniform_bounds):
    monkeypatch.setattr(stix2_module, "MISSING_REF_RETRY_EXPONENTIAL", True)
    monkeypatch.setattr(stix2_module, "MISSING_REF_RETRY_INITIAL_DELAY", 0.5)
    monkeypatch.setattr(stix2_module, "MISSING_REF_RETRY_FACTOR", 2.0)
    delays = [missing_ref_retry_delay(i) for i in range(PROCESSING_COUNT)]
    # +-50% jitter around 0.5s, 1s, 2s, 4s: mean total budget 7.5s.
    assert uniform_bounds == [(0.25, 0.75), (0.5, 1.5), (1.0, 3.0), (2.0, 6.0)]
    assert delays == [0.5, 1.0, 2.0, 4.0]
    assert sum(delays) == 7.5


def test_exponential_schedule_honors_knobs(monkeypatch, uniform_bounds):
    monkeypatch.setattr(stix2_module, "MISSING_REF_RETRY_EXPONENTIAL", True)
    monkeypatch.setattr(stix2_module, "MISSING_REF_RETRY_INITIAL_DELAY", 1.0)
    monkeypatch.setattr(stix2_module, "MISSING_REF_RETRY_FACTOR", 1.0)
    delays = [missing_ref_retry_delay(i) for i in range(3)]
    # factor 1 = constant delay
    assert uniform_bounds == [(0.5, 1.5)] * 3
    assert delays == [1.0] * 3


# --- retry loop ---------------------------------------------------------------------------------


def test_missing_ref_retry_loop_legacy(
    opencti_stix2: OpenCTIStix2, monkeypatch, uniform_bounds
):
    result, sleeps, attempts, error_adds = _run_import_with_retries(
        monkeypatch, opencti_stix2, failures=PROCESSING_COUNT
    )
    # Healed on the 5th call, after the 4 retries allowed by PROCESSING_COUNT.
    assert result is None
    assert sleeps == [2.0] * PROCESSING_COUNT
    # The historical counter keeps its exact shape: one label-free add per retry.
    assert error_adds == [(1, None)] * PROCESSING_COUNT
    # attempt attribute is 1-based, on the dedicated counter, whatever the schedule.
    assert attempts == [1, 2, 3, 4]


def test_missing_ref_retry_loop_exponential(
    opencti_stix2: OpenCTIStix2, monkeypatch, uniform_bounds
):
    monkeypatch.setattr(stix2_module, "MISSING_REF_RETRY_EXPONENTIAL", True)
    result, sleeps, attempts, error_adds = _run_import_with_retries(
        monkeypatch, opencti_stix2, failures=PROCESSING_COUNT
    )
    assert result is None
    assert sleeps == [0.5, 1.0, 2.0, 4.0]
    assert error_adds == [(1, None)] * PROCESSING_COUNT
    assert attempts == [1, 2, 3, 4]


def test_missing_ref_retry_loop_stops_after_processing_count(
    opencti_stix2: OpenCTIStix2, monkeypatch, uniform_bounds
):
    # One failure too many: the missing-reference branch is no longer in retry, the item goes
    # to the terminal technical-error path (no more sleep) and is not re-attempted.
    result, sleeps, attempts, error_adds = _run_import_with_retries(
        monkeypatch, opencti_stix2, failures=PROCESSING_COUNT + 1
    )
    assert result is None
    assert len(sleeps) == PROCESSING_COUNT
    assert error_adds == [(1, None)] * PROCESSING_COUNT
    assert attempts == list(range(1, PROCESSING_COUNT + 1))
    assert opencti_stix2.import_item.calls == PROCESSING_COUNT + 1


# --- env parsing --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,default,expected",
    [
        (None, False, False),  # unset
        ("", False, False),  # empty -> default
        ("true", False, True),
        ("True", False, True),
        ("1", False, True),
        ("yes", False, True),
        ("on", False, True),
        ("false", True, False),
        ("0", True, False),
        ("off", True, False),
        ("maybe", False, False),  # unknown -> default
        ("maybe", True, True),
    ],
)
def test_env_bool_is_tolerant(monkeypatch, raw, default, expected):
    name = "OPENCTI_TEST_ENV_BOOL"
    if raw is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, raw)
    assert _env_bool(name, default=default) is expected


@pytest.mark.parametrize(
    "raw,default,minimum,expected",
    [
        (None, 0.5, 0.0, 0.5),  # unset
        ("", 0.5, 0.0, 0.5),  # empty
        ("abc", 0.5, 0.0, 0.5),  # malformed
        ("nan", 0.5, 0.0, 0.5),  # not finite
        ("inf", 0.5, 0.0, 0.5),  # not finite
        ("-1", 0.5, 0.0, 0.0),  # clamped to minimum
        ("0.25", 0.5, 0.0, 0.25),
        ("0.5", 2.0, 1.0, 1.0),  # factor clamped to >= 1
        ("3", 2.0, 1.0, 3.0),
    ],
)
def test_env_float_is_tolerant(monkeypatch, raw, default, minimum, expected):
    name = "OPENCTI_TEST_ENV_FLOAT"
    if raw is None:
        monkeypatch.delenv(name, raising=False)
    else:
        monkeypatch.setenv(name, raw)
    assert _env_float(name, default=default, minimum=minimum) == expected
