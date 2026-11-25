import sys
from enum import Enum, IntEnum

import pytest

from pycti.connector.opencti_callback_executor import (
    CONNECTOR_UNKNOWN_ERROR_CODE,
    CONNECTOR_UNKNOWN_ERROR_CRITICITY,
    _ConnectorRunError,
    _ExceptionConverter,
)

requires_exception_group = pytest.mark.skipif(
    sys.version_info < (3, 11), reason="ExceptionGroup is 3.11+"
)


class _DataConversionError(Exception):
    code = "data.conversion"
    criticity = 30


class _Criticity(IntEnum):
    CRITICAL = 70


class _StrCode(str, Enum):
    AUTH = "api.authentication"


def _with(code=None, criticity=None, message="boom") -> Exception:
    exc = Exception(message)
    exc.code = code
    exc.criticity = criticity
    return exc


def _single_error(exc: BaseException) -> _ConnectorRunError:
    [error] = _ExceptionConverter(exc).to_error_list()
    return error


def test_returns_connector_run_error_models():
    errors = _ExceptionConverter(_DataConversionError("bad IOC")).to_error_list()
    assert errors == [
        _ConnectorRunError(
            code="data.conversion",
            message="_DataConversionError: bad IOC",
            criticity=30,
        )
    ]


def test_exception_without_code_nor_criticity_is_an_unknown_error():
    error = _single_error(ValueError("bad value"))
    assert error.code == CONNECTOR_UNKNOWN_ERROR_CODE
    assert error.criticity == CONNECTOR_UNKNOWN_ERROR_CRITICITY


def test_code_is_stripped():
    assert _single_error(_with(code="  api.timeout  ", criticity=10)).code == (
        "api.timeout"
    )


def test_enum_code_and_criticity_become_plain_values():
    error = _single_error(_with(code=_StrCode.AUTH, criticity=_Criticity.CRITICAL))
    assert error.code == "api.authentication"
    assert type(error.code) is str
    assert error.criticity == 70
    assert type(error.criticity) is int


@pytest.mark.parametrize(
    "criticity", [-(2**31), 0, 2**31 - 1], ids=["int-min", "zero", "int-max"]
)
def test_criticity_within_the_graphql_int_range_is_kept(criticity):
    assert _single_error(_with(code="A", criticity=criticity)).criticity == criticity


@pytest.mark.parametrize(
    "code",
    [404, "", "   ", None],
    ids=["int", "empty", "blank", "none"],
)
def test_invalid_code_falls_back_and_keeps_the_criticity(code):
    error = _single_error(_with(code=code, criticity=10))
    assert (error.code, error.criticity) == (CONNECTOR_UNKNOWN_ERROR_CODE, 10)


@pytest.mark.parametrize(
    "criticity",
    ["HIGH", "10", True, 10.0, -(2**31) - 1, 2**31, None],
    ids=[
        "str",
        "numeric-str",
        "bool",
        "float",
        "below-int-min",
        "above-int-max",
        "none",
    ],
)
def test_invalid_criticity_falls_back_and_keeps_the_code(criticity):
    error = _single_error(_with(code="api.timeout", criticity=criticity))
    assert (error.code, error.criticity) == (
        "api.timeout",
        CONNECTOR_UNKNOWN_ERROR_CRITICITY,
    )


def test_message_is_prefixed_with_the_exception_type():
    assert _single_error(ValueError("bad value")).message == "ValueError: bad value"


def test_message_without_text_is_the_exception_type():
    assert _single_error(KeyError()).message == "KeyError"


def test_failing_attribute_is_read_as_missing_without_affecting_the_others():
    class _BrokenCode(Exception):
        criticity = 20

        @property
        def code(self):
            raise RuntimeError("broken attribute")

    error = _single_error(_BrokenCode("still reported"))
    assert error == _ConnectorRunError(
        code=CONNECTOR_UNKNOWN_ERROR_CODE,
        message="_BrokenCode: still reported",
        criticity=20,
    )


def test_exception_failing_everywhere_is_still_converted():
    class _Unprintable(Exception):
        @property
        def code(self):
            raise RuntimeError("broken attribute")

        @property
        def criticity(self):
            raise RuntimeError("broken attribute")

        def __str__(self):
            raise RuntimeError("broken __str__")

    converter = _ExceptionConverter(_Unprintable())
    assert converter.to_error_list() == [
        _ConnectorRunError(
            code=CONNECTOR_UNKNOWN_ERROR_CODE,
            message="_Unprintable",
            criticity=CONNECTOR_UNKNOWN_ERROR_CRITICITY,
        )
    ]
    assert converter.message() == "_Unprintable"


def test_message_describes_the_exception_itself():
    converter = _ExceptionConverter(_DataConversionError("bad IOC"))
    assert converter.message() == "_DataConversionError: bad IOC"


@requires_exception_group
def test_exception_group_is_flattened_in_order():
    group = ExceptionGroup(  # noqa: F821
        "run failed",
        [
            _DataConversionError("first"),
            ExceptionGroup(  # noqa: F821
                "nested",
                [
                    ValueError("second"),
                    _with(code="third", criticity=1, message="third"),
                ],
            ),
            KeyError("fourth"),
        ],
    )
    errors = _ExceptionConverter(group).to_error_list()
    assert [(error.code, error.message) for error in errors] == [
        ("data.conversion", "_DataConversionError: first"),
        (CONNECTOR_UNKNOWN_ERROR_CODE, "ValueError: second"),
        ("third", "Exception: third"),
        (CONNECTOR_UNKNOWN_ERROR_CODE, "KeyError: 'fourth'"),
    ]


@requires_exception_group
def test_exception_group_message_describes_the_group():
    group = ExceptionGroup("run failed", [ValueError("bad value")])  # noqa: F821
    assert _ExceptionConverter(group).message() == (
        "ExceptionGroup: run failed (1 sub-exception)"
    )
