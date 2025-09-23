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
        """
        Init of OpenCTIMetricHandler class.

        Parameters
        ----------
        activated : bool, default False
            If True use metrics in client and connectors.
        namespace: str, default empty
            Namespace for the prometheus metrics.
        subsystem: str, default empty
            Subsystem for the prometheus metrics.
        port : int, default 9095
            Port for prometheus server.
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
        """
        Check if a metric exists and has the correct type.

        If it does not, log an error and return False.

        Parameters
        ----------
        name : str
            Name of the metric to check.
        expected_type : Counter or Enum
            Expected type of the metric.

        Returns
        -------
        bool
            True if the metric exists and is of the correct type else False.
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
        """
        Increment the metric (counter) `name` by `n`.

        Parameters
        ----------
        name : str
            Name of the metric to increment.
        n : int, default 1
            Increment the counter by `n`.
        """
        if self.activated:
            if self._metric_exists(name, Counter):
                self._metrics[name].inc(n)

    def state(self, state: str, name: str = "state"):
        """
        Set the state `state` for metric `name`.

        Parameters
        ----------
        state : str
            State to set.
        name : str, default = "state"
            Name of the metric to set.
        """
        if self.activated:
            if self._metric_exists(name, Enum):
                self._metrics[name].state(state)
