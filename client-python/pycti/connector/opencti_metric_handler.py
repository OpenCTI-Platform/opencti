"""OpenCTI Metric Handler module.

This module provides Prometheus metrics support for OpenCTI connectors,
allowing monitoring of connector performance and health.
"""

from typing import Type, Union

from prometheus_client import Counter, Enum, start_http_server


class OpenCTIMetricHandler:
    """Handler for Prometheus metrics in OpenCTI connectors.

    This class manages Prometheus metrics for monitoring connector behavior,
    including bundle sends, records processed, run counts, API pings, and errors.

    When activated, it starts an HTTP server to expose metrics for scraping
    by Prometheus or compatible monitoring systems.

    :param connector_logger: Logger instance for the connector
    :type connector_logger: logging.Logger
    :param activated: Whether to enable metrics collection and exposure
    :type activated: bool
    :param namespace: Prometheus metrics namespace prefix
    :type namespace: str
    :param subsystem: Prometheus metrics subsystem prefix
    :type subsystem: str
    :param port: Port number for the Prometheus HTTP server
    :type port: int

    Example:
        >>> handler = OpenCTIMetricHandler(
        ...     connector_logger=logger,
        ...     activated=True,
        ...     namespace="opencti",
        ...     subsystem="connector",
        ...     port=9095
        ... )
        >>> handler.inc("bundle_send")
        >>> handler.state("running")
    """

    def __init__(
        self,
        connector_logger,
        activated: bool = False,
        namespace: str = "",
        subsystem: str = "",
        port: int = 9095,
    ):
        """Initialize the OpenCTIMetricHandler instance.

        :param connector_logger: Logger instance for the connector
        :type connector_logger: logging.Logger
        :param activated: Whether to enable metrics (default: False)
        :type activated: bool
        :param namespace: Prometheus metrics namespace prefix (default: "")
        :type namespace: str
        :param subsystem: Prometheus metrics subsystem prefix (default: "")
        :type subsystem: str
        :param port: Port for Prometheus HTTP server (default: 9095)
        :type port: int
        """
        self.activated = activated
        self.connector_logger = connector_logger
        if self.activated:
            self.connector_logger.info("Exposing metrics on port", {"port": port})
            start_http_server(port)
            self._metrics = {
                "bundle_send": Counter(
                    "bundles_sent_total",
                    "Number of bundles sent",
                    namespace=namespace,
                    subsystem=subsystem,
                ),
                "record_send": Counter(
                    "records_sent_total",
                    "Number of records (objects per bundle) sent",
                    namespace=namespace,
                    subsystem=subsystem,
                ),
                "run_count": Counter(
                    "runs_total",
                    "Number of run",
                    namespace=namespace,
                    subsystem=subsystem,
                ),
                "ping_api_count": Counter(
                    "ping_api_total",
                    "Number of pings to the API",
                    namespace=namespace,
                    subsystem=subsystem,
                ),
                "ping_api_error": Counter(
                    "ping_api_errors_total",
                    "Number of errors when pinging the API",
                    namespace=namespace,
                    subsystem=subsystem,
                ),
                "error_count": Counter(
                    "errors_total",
                    "Number of errors",
                    namespace=namespace,
                    subsystem=subsystem,
                ),
                "client_error_count": Counter(
                    "client_errors_total",
                    "Number of client errors",
                    namespace=namespace,
                    subsystem=subsystem,
                ),
                "state": Enum(
                    "state",
                    "State of connector",
                    states=["idle", "running", "stopped"],
                    namespace=namespace,
                    subsystem=subsystem,
                ),
            }

    def _metric_exists(
        self, name: str, expected_type: Union[Type[Counter], Type[Enum]]
    ) -> bool:
        """Check if a metric exists and has the expected type.

        Validates that the named metric is registered and matches the expected
        Prometheus metric type. Logs an error if validation fails.

        :param name: Name of the metric to validate
        :type name: str
        :param expected_type: Expected Prometheus metric type (Counter or Enum)
        :type expected_type: Union[Type[Counter], Type[Enum]]

        :return: True if metric exists and has correct type, False otherwise
        :rtype: bool
        """
        if name not in self._metrics:
            self.connector_logger.error("Metric does not exist.", {"name": name})
            return False
        if not isinstance(self._metrics[name], expected_type):
            self.connector_logger.error(
                "Metric not of expected type",
                {"name": name, "expected_type": expected_type},
            )
            return False
        return True

    def inc(self, name: str, n: int = 1) -> None:
        """Increment a counter metric by a specified amount.

        Increments the named counter metric. If metrics are not activated
        or the metric does not exist, this method does nothing.

        Available counter metrics:
            - bundle_send: Number of bundles sent
            - record_send: Number of records sent
            - run_count: Number of connector runs
            - ping_api_count: Number of API pings
            - ping_api_error: Number of API ping errors
            - error_count: Total number of errors
            - client_error_count: Number of client errors

        :param name: Name of the counter metric to increment
        :type name: str
        :param n: Amount to increment the counter by (default: 1)
        :type n: int

        Example:
            >>> handler.inc("bundle_send")
            >>> handler.inc("record_send", 10)
        """
        if self.activated:
            if self._metric_exists(name, Counter):
                self._metrics[name].inc(n)

    def state(self, state: str, name: str = "state") -> None:
        """Set the state of an Enum metric.

        Updates the named Enum metric to the specified state value.
        If metrics are not activated or the metric does not exist,
        this method does nothing.

        Available states for the default "state" metric:
            - idle: Connector is idle
            - running: Connector is running
            - stopped: Connector is stopped

        :param state: State value to set (must be a valid state for the metric)
        :type state: str
        :param name: Name of the Enum metric to update (default: "state")
        :type name: str

        Example:
            >>> handler.state("running")
            >>> handler.state("idle", "state")
        """
        if self.activated:
            if self._metric_exists(name, Enum):
                self._metrics[name].state(state)
