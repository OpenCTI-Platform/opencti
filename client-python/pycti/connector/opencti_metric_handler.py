from typing import Type, Union

from prometheus_client import Counter, Enum, start_http_server


class OpenCTIMetricHandler:
    def __init__(
        self,
        connector_logger,
        activated: bool = False,
        namespace: str = "",
        subsystem: str = "",
        port: int = 9095,
    ):
        """Initialize OpenCTIMetricHandler class.

        :param connector_logger: Logger instance for the connector
        :param activated: If True, use metrics in client and connectors
        :type activated: bool
        :param namespace: Namespace for the prometheus metrics
        :type namespace: str
        :param subsystem: Subsystem for the prometheus metrics
        :type subsystem: str
        :param port: Port for prometheus server
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
        """Check if a metric exists and has the correct type.

        If it does not, log an error and return False.

        :param name: Name of the metric to check
        :type name: str
        :param expected_type: Expected type of the metric (Counter or Enum)
        :type expected_type: Counter or Enum
        :return: True if the metric exists and is of the correct type, else False
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

    def inc(self, name: str, n: int = 1):
        """Increment the metric (counter) `name` by `n`.

        :param name: Name of the metric to increment
        :type name: str
        :param n: Increment the counter by `n`
        :type n: int
        """
        if self.activated:
            if self._metric_exists(name, Counter):
                self._metrics[name].inc(n)

    def state(self, state: str, name: str = "state"):
        """Set the state `state` for metric `name`.

        :param state: State to set
        :type state: str
        :param name: Name of the metric to set
        :type name: str
        """
        if self.activated:
            if self._metric_exists(name, Enum):
                self._metrics[name].state(state)
