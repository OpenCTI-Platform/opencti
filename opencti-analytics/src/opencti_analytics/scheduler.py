"""Run loop: one run every `run_interval_hours`, interrupted by shutdown requests."""

import threading
from typing import Callable

from opencti_analytics.client import Logger
from opencti_analytics.runner import STATUS_CANCELLED, STATUS_FAILED, RunReport

# A failed run is retried sooner than the next regular run: 15 minutes, doubled
# on every consecutive failure, never more than the run interval.
FAILURE_RETRY_SECONDS = 900.0
MAX_BACKOFF_EXPONENT = 30


class Scheduler:
    def __init__(
        self,
        run: Callable[[], RunReport],
        interval_seconds: float,
        run_on_start: bool,
        logger: Logger,
        stop_event: threading.Event,
        failure_retry_seconds: float = FAILURE_RETRY_SECONDS,
    ) -> None:
        self.run = run
        self.interval_seconds = interval_seconds
        self.run_on_start = run_on_start
        self.logger = logger
        self.stop_event = stop_event
        self.failure_retry_seconds = failure_retry_seconds

    def stop(self) -> None:
        self.stop_event.set()

    def _safe_run(self) -> RunReport:
        try:
            return self.run()
        except Exception as e:  # pylint: disable=broad-except
            self.logger.error(
                "Graph analytics run crashed",
                {"error": type(e).__name__, "reason": str(e)},
            )
            return RunReport(run_id="", status=STATUS_FAILED, reason=str(e))

    def run_once(self) -> RunReport:
        return self._safe_run()

    def next_delay(self, report: RunReport, consecutive_failures: int) -> float:
        if report.status != STATUS_FAILED:
            return self.interval_seconds
        # 2**30 retries exceed any interval: a bounded exponent never overflows float()
        exponent = min(max(consecutive_failures - 1, 0), MAX_BACKOFF_EXPONENT)
        retry = self.failure_retry_seconds * float(2**exponent)
        return min(self.interval_seconds, retry)

    def run_forever(self) -> None:
        delay = 0.0 if self.run_on_start else self.interval_seconds
        failures = 0
        while not self.stop_event.is_set():
            if delay > 0:
                self.logger.info(
                    "Next graph analytics run scheduled", {"in_seconds": round(delay)}
                )
                if self.stop_event.wait(delay):
                    break
            report = self._safe_run()
            if report.status == STATUS_CANCELLED:
                break
            failures = failures + 1 if report.status == STATUS_FAILED else 0
            delay = self.next_delay(report, failures)
        self.logger.info("Graph analytics scheduler stopped")
