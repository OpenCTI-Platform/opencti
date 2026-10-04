"""Process wiring: configuration, API client, telemetry, signals, scheduling."""

import argparse
import dataclasses
import os
import signal
import sys
import threading
from types import FrameType
from typing import List, Optional

from pycti import OpenCTIApiClient

from opencti_analytics import PROCESS_NAME, __version__
from opencti_analytics.client import AnalyticsClient
from opencti_analytics.config import Settings, load_config_file, load_settings
from opencti_analytics.engines import select_engine
from opencti_analytics.runner import (
    STATUS_DISABLED,
    STATUS_SKIPPED,
    STATUS_SUCCESS,
    AnalyticsRunner,
)
from opencti_analytics.scheduler import Scheduler
from opencti_analytics.telemetry import Telemetry

DEFAULT_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.yml"
)

EXIT_OK = 0
EXIT_RUN_FAILED = 1
EXIT_CONFIG_ERROR = 2


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="analytics.py",
        description="OpenCTI graph analytics process (communities, clusters, "
        "approximate betweenness).",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="run a single analysis and exit (cron, Kubernetes jobs)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="run even when the platform has fewer edges than analytics.min_edges",
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="path of the YAML configuration file (default: config.yml)",
    )
    return parser.parse_args(argv)


def build_api_client(settings: Settings) -> OpenCTIApiClient:
    return OpenCTIApiClient(
        url=settings.opencti_url,
        token=settings.opencti_token,
        log_level=settings.log_level,
        json_logging=settings.opencti_json_logging,
        ssl_verify=settings.opencti_ssl_verify,
        # the platform may still be starting, runs retry on their own
        perform_health_check=False,
        custom_headers=settings.opencti_custom_headers,
        requests_timeout=settings.opencti_requests_timeout,
        provider=f"{PROCESS_NAME}/{__version__}",
    )


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        settings = load_settings(load_config_file(args.config))
        if args.force:
            settings = dataclasses.replace(settings, force=True)
        engine = select_engine(settings.engine)
        api = build_api_client(settings)
    except (ValueError, ImportError) as e:
        print(f"opencti-analytics configuration error: {e}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    logger = api.logger_class(PROCESS_NAME)
    stop_event = threading.Event()
    telemetry = Telemetry()
    if settings.telemetry_enabled:
        telemetry.start(
            settings.telemetry_prometheus_port, settings.telemetry_prometheus_host
        )
    client = AnalyticsClient(api, logger, stop_event=stop_event)
    runner = AnalyticsRunner(
        settings, client, logger, engine, telemetry=telemetry, stop_event=stop_event
    )
    scheduler = Scheduler(
        runner.run_once,
        settings.run_interval_seconds,
        settings.run_on_start,
        logger,
        stop_event,
    )

    def exit_handler(signum: int, _frame: Optional[FrameType]) -> None:
        logger.info("Graph analytics shutdown requested", {"signal": signum})
        stop_event.set()

    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)

    logger.info(
        "Graph analytics process started",
        {
            "version": __version__,
            "engine": engine.name,
            "once": args.once,
            "enabled": settings.enabled,
            "run_interval_hours": settings.run_interval_hours,
            "min_edges": settings.min_edges,
            "force": settings.force,
            "relationship_types": list(settings.relationship_types),
        },
    )
    try:
        if args.once:
            report = scheduler.run_once()
            succeeded = (STATUS_SUCCESS, STATUS_SKIPPED, STATUS_DISABLED)
            return EXIT_OK if report.status in succeeded else EXIT_RUN_FAILED
        scheduler.run_forever()
        return EXIT_OK
    finally:
        telemetry.stop()
