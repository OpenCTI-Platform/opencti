"""OpenCTI Callback Executor module.

This module runs a scheduled connector callback and collects the errors of the
run: the errors the callback returns and the exceptions it raises.
"""

import builtins
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

# typing.Annotated is Python 3.9+; typing_extensions always comes with pydantic
from typing_extensions import Annotated

# The platform only accepts a GraphQL Int (32 bits)
_GRAPHQL_INT_MIN = -(2**31)
_GRAPHQL_INT_MAX = 2**31 - 1

# Strict: a bool, a float or a numeric string is rejected; an IntEnum is accepted and dumped as a plain int
_Criticity = Annotated[
    int, Field(strict=True, ge=_GRAPHQL_INT_MIN, le=_GRAPHQL_INT_MAX)
]
_CRITICITY_ADAPTER = TypeAdapter(_Criticity)

# Same limits as the platform, which truncates too: truncating here keeps each ping small
CONNECTOR_ERROR_CODE_MAX_LENGTH = 256
CONNECTOR_ERROR_MESSAGE_MAX_LENGTH = 1024


# Private for now: returned dicts and add_error are the documented contract, exporting it later stays compatible
class _ConnectorRunError(BaseModel):
    """Error returned by a connector run"""

    model_config = ConfigDict(strict=True, extra="forbid", str_strip_whitespace=True)

    code: str = Field(min_length=1)
    message: str
    criticity: _Criticity

    def to_graphql_dict(self) -> Dict:
        """The error as sent in the ping mutation, code and message truncated."""
        return {
            "code": self.code[:CONNECTOR_ERROR_CODE_MAX_LENGTH],
            "message": self.message[:CONNECTOR_ERROR_MESSAGE_MAX_LENGTH],
            "criticity": self.criticity,
        }


# Reported for an exception that carries no valid code or criticity, as UnknownError in the connectors SDK
CONNECTOR_UNKNOWN_ERROR_CODE = "other.unknown"
CONNECTOR_UNKNOWN_ERROR_CRITICITY = 50

# Same threshold as the platform: from this criticity an error is blocking, and the run failed
CONNECTOR_ERROR_BLOCKING_CRITICITY = 40

# Built in since Python 3.11 only
_BASE_EXCEPTION_GROUP = getattr(builtins, "BaseExceptionGroup", None)


class _ExceptionConverter:
    """Converts an exception raised by a connector run into connector errors.

    It never raises: the exception may come from any library, and a failure
    here would stop the scheduler again.
    """

    def __init__(self, exc: BaseException):
        self.exc = exc

    def to_error_list(self) -> List[_ConnectorRunError]:
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
    def _to_error(cls, exc: BaseException) -> _ConnectorRunError:
        # Each field is already valid or replaced by its default: this validation cannot fail
        return _ConnectorRunError(
            code=cls._code(exc),
            message=cls._message(exc),
            criticity=cls._criticity(exc),
        )

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
            return int(
                _CRITICITY_ADAPTER.validate_python(cls._read(lambda: exc.criticity))
            )
        except ValidationError:
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
    def add_errors(self, errors: List[_ConnectorRunError]) -> None:
        """Add the errors of a run, already validated."""

    @abstractmethod
    def reset(self) -> None:
        """Remove the errors of the previous run."""


class CallbackExecutor:
    """Runs a connector callback and reports its errors to an ErrorCollector.

    The callback may return a list of errors, or yield them, and may raise:
    each raised exception (each exception of an ``ExceptionGroup``) is reported
    as an error. An ``Exception`` never propagates, a ``BaseException`` does.

    With ``reset_on_each_run`` (the default), the error collector is reset
    before each run, so only the errors of the last run are kept. Without it,
    the errors of successive runs accumulate.
    """

    def __init__(
        self,
        error_collector: ErrorCollector,
        logger,
        metric,
        reset_on_each_run: bool = True,
    ):
        """Create the executor.

        :param error_collector: Where the errors of each run go
        :type error_collector: ErrorCollector
        :param logger: Logger of the connector
        :type logger: AppLogger
        :param metric: Metric handler of the connector, ``error_count`` is incremented on an exception
        :type metric: OpenCTIMetricHandler
        :param reset_on_each_run: Whether to reset the error collector before each run
        :type reset_on_each_run: bool
        """
        self._error_collector = error_collector
        self._logger = logger
        self._metric = metric
        self._reset_on_each_run = reset_on_each_run

    def execute(self, callback: Callable[[], Any]) -> bool:
        """Run the callback and report its errors to the error collector.

        :param callback: The connector run
        :type callback: Callable
        :return: True when the run succeeded: every error it returned or raised
            is below ``CONNECTOR_ERROR_BLOCKING_CRITICITY``
        :rtype: bool
        """
        # Errors belong to a run: reset before it so those added with add_error during it are kept
        if self._reset_on_each_run:
            self._error_collector.reset()
        result, exception = self._invoke(callback)
        errors = self._validate(result)
        self._error_collector.add_errors(errors)
        if exception is not None:
            errors = errors + self._report_exception(exception)
        return all(
            error.criticity < CONNECTOR_ERROR_BLOCKING_CRITICITY for error in errors
        )

    @staticmethod
    def _is_iterable_collection(value: Any) -> bool:
        # Strings, bytes and mappings are iterable but are not a list of errors
        return isinstance(value, Iterable) and not isinstance(
            value, (str, bytes, Mapping)
        )

    def _invoke(self, callback: Callable[[], Any]) -> Tuple[Any, Optional[Exception]]:
        consumed_errors: List = []
        try:
            result = callback()
            if not self._is_iterable_collection(result):
                return result, None
            # A generator callback runs while it is consumed: consume it here so its exceptions are caught
            consumed_errors.extend(result)
            return consumed_errors, None
        # A raised exception is reported like a returned error, and the next run is still scheduled
        except Exception as err:  # pylint: disable=broad-except
            # Logged here: AppLogger.error() attaches the traceback of the exception being handled
            self._logger.error(
                "Connector run raised an exception",
                {"reason": _ExceptionConverter(err).message()},
            )
            # Errors a generator yielded before raising are kept
            return consumed_errors, err

    def _validate(self, result: Any) -> List[_ConnectorRunError]:
        if isinstance(result, Mapping):
            self._logger.warning(
                "Connector run returned a single error instead of a list, ignored",
                {"received": repr(result)},
            )
            return []
        # Other non-list returns (True, a status string...) predate errors reporting and stay silent
        if not self._is_iterable_collection(result):
            return []
        valid_errors: List[_ConnectorRunError] = []
        for error in result:
            try:
                valid_errors.append(_ConnectorRunError.model_validate(error))
            except ValidationError as e:
                self._logger.warning(
                    "Malformed error response from the connector",
                    {"received": repr(error), "reason": str(e)},
                )
        return valid_errors

    def _report_exception(self, exception: Exception) -> List[_ConnectorRunError]:
        errors = _ExceptionConverter(exception).to_error_list()
        self._error_collector.add_errors(errors)
        self._metric.inc("error_count")
        return errors
