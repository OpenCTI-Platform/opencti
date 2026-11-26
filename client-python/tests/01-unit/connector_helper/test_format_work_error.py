"""Tests for _format_work_error: how a failed message processing is reported
as a work error that the OpenCTI front end classifies (Critical or Warning).

The standard errors are defined locally, with the shape of the connectors SDK
errors (class-level ``code`` and ``criticity``), so that pycti never depends on
connectors_sdk.
"""

import json
from enum import IntEnum

import pytest

from pycti.connector.opencti_connector_helper import _format_work_error


class Criticity(IntEnum):
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class StandardError(Exception):
    code = "other.unknown"
    criticity = Criticity.CRITICAL


class ApiTimeoutError(StandardError):
    code = "api.timeout"
    criticity = Criticity.ERROR


class UnknownError(StandardError):
    code = "other.unknown"
    criticity = Criticity.CRITICAL


class RejectedError(StandardError):
    code = "target.rejected"
    criticity = Criticity.WARNING


class ConversionError(StandardError):
    code = "data.conversion"
    criticity = Criticity.WARNING


def _parse(message: str) -> dict:
    return json.loads(message)


# --- Standard errors at or above ERROR --------------------------------------


def test_error_criticity_is_reported_as_critical():
    message = _format_work_error(ApiTimeoutError("Read timed out"))
    assert _parse(message) == {
        "name": "INTERNAL_SERVER_ERROR",
        "error_message": "[api.timeout] Read timed out",
    }


def test_critical_criticity_is_reported_as_critical():
    message = _format_work_error(UnknownError("boom"))
    assert _parse(message)["name"] == "INTERNAL_SERVER_ERROR"


def test_plain_int_criticity_is_accepted():
    class PlainIntError(Exception):
        code = "api.server"
        criticity = 40

    assert _parse(_format_work_error(PlainIntError("x")))["name"] == (
        "INTERNAL_SERVER_ERROR"
    )


# --- Standard errors below ERROR --------------------------------------------


def test_warning_criticity_is_reported_as_warning():
    message = _format_work_error(RejectedError("Item refused"))
    assert _parse(message) == {
        "name": "VALIDATION_ERROR",
        "error_message": "[target.rejected] Item refused",
    }


def test_criticity_just_below_error_is_reported_as_warning():
    class AlmostError(Exception):
        code = "data.missing_data"
        criticity = 39

    assert _parse(_format_work_error(AlmostError("x")))["name"] == "VALIDATION_ERROR"


# --- The connector's own error code stays visible ---------------------------


def test_code_is_prefixed_to_the_message():
    message = _format_work_error(ConversionError("Unsupported pattern"))
    assert _parse(message)["error_message"] == "[data.conversion] Unsupported pattern"


def test_no_doc_code_is_sent():
    # The front end reads doc_code before name: a connector code there would
    # leave the error unclassified
    assert "doc_code" not in _parse(_format_work_error(ApiTimeoutError("x")))


def test_quotes_and_newlines_round_trip():
    text = 'He said "no"\nthen left \\ again'
    message = _format_work_error(RejectedError(text))
    assert _parse(message)["error_message"] == f"[target.rejected] {text}"


# --- Other exceptions are reported unchanged --------------------------------


def test_plain_exception_is_reported_as_its_text():
    assert _format_work_error(ValueError("Connection refused")) == "Connection refused"


def test_missing_code_is_reported_as_its_text():
    class NoCodeError(Exception):
        criticity = 40

    assert _format_work_error(NoCodeError("no code")) == "no code"


@pytest.mark.parametrize("code", ["", "   ", None, 42])
def test_invalid_code_is_reported_as_its_text(code):
    class BadCodeError(Exception):
        criticity = 40

    BadCodeError.code = code
    assert _format_work_error(BadCodeError("bad code")) == "bad code"


@pytest.mark.parametrize("criticity", ["high", True, False, 40.0, None, 2**31])
def test_invalid_criticity_is_reported_as_its_text(criticity):
    class BadCriticityError(Exception):
        code = "api.timeout"

    BadCriticityError.criticity = criticity
    assert _format_work_error(BadCriticityError("bad criticity")) == "bad criticity"


def test_missing_criticity_is_reported_as_its_text():
    class NoCriticityError(Exception):
        code = "api.timeout"

    assert _format_work_error(NoCriticityError("no criticity")) == "no criticity"


# --- Classifying an error never prevents reporting it -----------------------


def test_standard_error_whose_text_cannot_be_rendered_still_returns_a_message():
    class UnprintableError(RejectedError):
        def __str__(self):
            raise RuntimeError("cannot render")

    message = _format_work_error(UnprintableError("x"))
    assert isinstance(message, str)
    assert message == "UnprintableError"


def test_plain_exception_whose_text_cannot_be_rendered_still_returns_a_message():
    class UnprintablePlainError(Exception):
        def __str__(self):
            raise RuntimeError("cannot render")

    assert _format_work_error(UnprintablePlainError()) == "UnprintablePlainError"


def test_attribute_access_that_raises_still_returns_a_message():
    class ExplodingError(Exception):
        @property
        def code(self):
            raise RuntimeError("no access")

    assert _format_work_error(ExplodingError("exploding")) == "exploding"
