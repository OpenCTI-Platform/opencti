"""Benchmark HTTP listener callback overlap on the asyncio event loop.

The benchmark runs two concurrent API-listener requests against one
ListenQueue instance. A blocking callback should not serialize the event loop:
both requests can wait for their own callback completion while unrelated
requests continue to make progress.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import threading
import time

from pycti.connector.opencti_connector_helper import ListenQueue


class _NoopLogger:
    def error(self, *_args, **_kwargs):
        pass


class _Helper:
    def __init__(self):
        self.connector_logger = _NoopLogger()


class _Request:
    headers = {"Authorization": "Bearer benchmark"}

    async def json(self):
        return {"event": {}, "internal": {}}


def _listener(callback):
    listener = object.__new__(ListenQueue)
    listener.helper = _Helper()
    listener.is_token_valid = lambda _token: True
    listener._data_handler = callback
    return listener


async def _run_pair(listener):
    await asyncio.gather(
        listener._http_process_callback(_Request()),
        listener._http_process_callback(_Request()),
    )


def _run_once(iterations: int, callback_sleep_seconds: float) -> tuple[float, int]:
    lock = threading.Lock()
    active_callbacks = 0
    max_in_flight = 0

    def callback(_data):
        nonlocal active_callbacks, max_in_flight
        with lock:
            active_callbacks += 1
            max_in_flight = max(max_in_flight, active_callbacks)
        try:
            time.sleep(callback_sleep_seconds)
        finally:
            with lock:
                active_callbacks -= 1

    listener = _listener(callback)

    async def run_iterations():
        for _ in range(iterations):
            await _run_pair(listener)

    started_at = time.perf_counter()
    asyncio.run(run_iterations())
    return time.perf_counter() - started_at, max_in_flight


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--callback-sleep-ms", type=float, default=5.0)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    callback_sleep_seconds = args.callback_sleep_ms / 1000
    _run_once(min(args.iterations, 2), callback_sleep_seconds)
    samples = [
        _run_once(args.iterations, callback_sleep_seconds) for _ in range(args.repeat)
    ]
    runtime_samples = [sample[0] for sample in samples]
    max_in_flight_samples = [sample[1] for sample in samples]
    result = {
        "iterations": args.iterations,
        "callback_sleep_ms": args.callback_sleep_ms,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(runtime_samples) * 1000, 3),
        "min_runtime_ms": round(min(runtime_samples) * 1000, 3),
        "max_runtime_ms": round(max(runtime_samples) * 1000, 3),
        "median_max_in_flight": int(statistics.median(max_in_flight_samples)),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
