"""OpenCTI Callback Executor module.

This module runs a connector callback and collects the errors of the run: the
errors the callback returns and the exceptions it raises.
"""

import builtins
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, ValidationError

# The platform only accepts a GraphQL Int (32 bits)
_GRAPHQL_INT_MIN = -(2**31)
_GRAPHQL_INT_MAX = 2**31 - 1


# Private for now: returned dicts and add_error are the documented contract, exporting it later stays compatible
class _ConnectorRunError(BaseModel):
    """Error returned by a connector run"""

    model_config = ConfigDict(strict=True, extra="forbid")

    code: str
    message: str
    criticity: int = Field(ge=_GRAPHQL_INT_MIN, le=_GRAPHQL_INT_MAX)


def _parse_criticity(value) -> int:
    # bool is an int subclass
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"criticity must be an integer, got {type(value).__name__}")
    if not _GRAPHQL_INT_MIN <= value <= _GRAPHQL_INT_MAX:
        raise ValueError(f"criticity {value} is out of the GraphQL Int range")
    return value


# Reported for an exception that carries no valid code or criticity, as UnknownError in the connectors SDK
CONNECTOR_UNKNOWN_ERROR_CODE = "other.unknown"
CONNECTOR_UNKNOWN_ERROR_CRITICITY = 50

# Built in since Python 3.11 only
_BASE_EXCEPTION_GROUP = getattr(builtins, "BaseExceptionGroup", None)


class _ExceptionConverter:
    """Converts an exception raised by a connector run into connector errors.

    It never raises: the exception may come from any library, and a failure
    here would stop the scheduler again.
    """

    def __init__(self, exc: BaseException):
        self.exc = exc

    def to_error_list(self) -> List[Dict]:
        """One error per exception, each exception of an ExceptionGroup included."""
        return [self._to_error(exc) for exc in self._flatten(self.exc)]

    def message(self) -> str:
        return self._message(self.exc)

    @classmethod
    def _flatten(cls, exc: BaseException) -> List[BaseException]:
        if _BASE_EXCEPTION_GROUP is not None and isinstance(exc, _BASE_EXCEPTION_GROUP):
            return [leaf for inner in exc.exceptions for leaf in cls._flatten(inner)]
        return [exc]

    @classmethod
    def _to_error(cls, exc: BaseException) -> Dict:
        return {
            "code": cls._code(exc),
            "message": cls._message(exc),
            "criticity": cls._criticity(exc),
        }

    @classmethod
    def _code(cls, exc: BaseException) -> str:
        code = cls._read(lambda: exc.code)
        # A third-party code (urllib HTTPError.code is an int...) is ignored
        if not isinstance(code, str) or not code.strip():
            return CONNECTOR_UNKNOWN_ERROR_CODE
        # strip() also turns a str subclass (a str enum) into a plain str
        return code.strip()

    @classmethod
    def _criticity(cls, exc: BaseException) -> int:
        try:
            # An IntEnum (Criticity of the connectors SDK) is sent as a plain int
            return int(_parse_criticity(cls._read(lambda: exc.criticity)))
        except (TypeError, ValueError):
            return CONNECTOR_UNKNOWN_ERROR_CRITICITY

    @classmethod
    def _message(cls, exc: BaseException) -> str:
        name = type(exc).__name__
        text = cls._read(lambda: str(exc))
        return f"{name}: {text}" if text else name

    @staticmethod
    def _read(reader: Callable[[], Any]) -> Any:
        # A property or __str__ may raise anything, not only AttributeError: read as missing
        try:
            return reader()
        except Exception:  # pylint: disable=broad-except
            return None


class ErrorCollector(ABC):
    """Where the errors of a connector run go."""

    @abstractmethod
    def add_errors(self, errors: List[Dict]) -> None:
        """Add valid errors, dicts with ``code``, ``message`` and ``criticity``."""

    @abstractmethod
    def reset(self) -> None:
        """Remove the errors of the previous run."""


class CallbackExecutor:
    """Runs a connector callback and reports its errors to an ErrorCollector.

    The callback may return a list of errors, or yield them, and may raise:
    each raised exception (each exception of an ``ExceptionGroup``) is reported
    as an error. A ``BaseException`` always propagates.

    With ``swallow_errors`` (the default), an ``Exception`` never propagates:
    it is counted, logged and ``execute`` returns ``None``. Without it, the
    exception is added to the error collector and re-raised, untouched: the
    caller handles it as if the callback had raised it, logging and counting
    included.

    With ``reset_on_each_run`` (the default), the error collector is reset
    before each run, so only the errors of the last run are kept. Without it,
    the errors of successive runs accumulate.

    Without ``returns_errors``, the callback's return value is not a list of
    errors (the status message of a ``listen()`` callback): it is neither
    consumed nor validated, only returned by ``execute``, and only the raised
    exceptions are reported.
    """

    def __init__(
        self,
        error_collector: ErrorCollector,
        logger,
        metric,
        reset_on_each_run: bool = True,
        returns_errors: bool = True,
        swallow_errors: bool = True,
    ):
        self._error_collector = error_collector
        self._logger = logger
        self._metric = metric
        self._reset_on_each_run = reset_on_each_run
        self._returns_errors = returns_errors
        self._swallow_errors = swallow_errors

    def execute(self, callback: Callable[[], Any]) -> Any:
        """Run the callback and return its result, ``None`` when it raised."""
        # Errors belong to a run: reset before it so those added with add_error during it are kept
        if self._reset_on_each_run:
            self._error_collector.reset()
        if self._returns_errors:
            result, exception = self._invoke(callback)
            self._error_collector.add_errors(self._validate(result))
        else:
            result, exception = self._invoke_for_result(callback)
        if exception is None:
            return result
        converter = _ExceptionConverter(exception)
        self._error_collector.add_errors(converter.to_error_list())
        if not self._swallow_errors:
            # The caller counts and logs it, as when the callback raised it directly
            raise exception
        self._metric.inc("error_count")
        self._logger.error(
            "Connector run raised an exception", {"reason": converter.message()}
        )
        return None

    @staticmethod
    def _invoke_for_result(
        callback: Callable[[], Any],
    ) -> Tuple[Any, Optional[Exception]]:
        try:
            return callback(), None
        except Exception as err:  # pylint: disable=broad-except
            return None, err

    @staticmethod
    def _is_iterable_collection(value: Any) -> bool:
        # Strings, bytes and mappings are iterable but are not a list of errors
        return isinstance(value, Iterable) and not isinstance(
            value, (str, bytes, Mapping)
        )

    @classmethod
    def _invoke(cls, callback: Callable[[], Any]) -> Tuple[Any, Optional[Exception]]:
        consumed_errors: List = []
        try:
            result = callback()
            if not cls._is_iterable_collection(result):
                return result, None
            # A generator callback runs while it is consumed: consume it here so its exceptions are caught
            consumed_errors.extend(result)
            return consumed_errors, None
        # A raised exception is reported like a returned error, and the next run is still scheduled
        except Exception as err:  # pylint: disable=broad-except
            # Errors a generator yielded before raising are kept
            return consumed_errors, err

    def _validate(self, result: Any) -> List[Dict]:
        if isinstance(result, Mapping):
            self._logger.warning(
                "Connector run returned a single error instead of a list, ignored",
                {"received": repr(result)},
            )
            return []
        # Other non-list returns (True, a status string...) predate errors reporting and stay silent
        if not self._is_iterable_collection(result):
            return []
        valid_errors: List[Dict] = []
        for error in result:
            try:
                valid_errors.append(
                    _ConnectorRunError.model_validate(error).model_dump()
                )
            except ValidationError as e:
                self._logger.warning(
                    "Malformed error response from the connector",
                    {"received": repr(error), "reason": str(e)},
                )
        return valid_errors
