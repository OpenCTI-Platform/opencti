"""Benchmark AMQP listener in-flight callback overlap.

The benchmark drives two AMQP deliveries through one ListenQueue instance with
a blocking callback. The pre-fix listener creates a thread per delivery but
waits for it before returning to the consumer loop, so the callbacks remain
serialized. A concurrent listener should allow both deliveries to remain in
flight until their callback work completes.
"""

from __future__ import annotations

import argparse
import json
import queue
import statistics
import threading
import time
from types import SimpleNamespace

from pycti.connector.opencti_connector_helper import ListenQueue


class _NoopLogger:
    def info(self, *_args, **_kwargs):
        pass

    def error(self, *_args, **_kwargs):
        pass


class _Helper:
    def __init__(self):
        self.connector_logger = _NoopLogger()


class _FakeChannel:
    def __init__(self):
        self.acked_delivery_tags = []
        self.nacked_delivery_tags = []
        self.is_closed = False

    def basic_ack(self, delivery_tag):
        self.acked_delivery_tags.append(delivery_tag)

    def basic_nack(self, delivery_tag, requeue=True):
        self.nacked_delivery_tags.append((delivery_tag, requeue))


class _FakeConnection:
    def __init__(self):
        self._callbacks = queue.Queue()
        self.is_closed = False

    def add_callback_threadsafe(self, callback):
        self._callbacks.put(callback)

    def sleep(self, seconds):
        time.sleep(seconds)
        self.drain_callbacks()

    def drain_callbacks(self):
        while True:
            try:
                callback = self._callbacks.get_nowait()
            except queue.Empty:
                return
            callback()


def _listener(callback, worker_count):
    listener = object.__new__(ListenQueue)
    listener.helper = _Helper()
    listener._data_handler = callback
    listener.pika_connection = _FakeConnection()
    listener.channel = _FakeChannel()
    listener.thread = None
    listener.exit_event = threading.Event()
    listener.listen_worker_count = worker_count
    listener.listen_prefetch_count = worker_count
    listener._worker_pool = None
    listener._in_flight_messages = {}
    listener._in_flight_lock = threading.Lock()
    return listener


def _message(delivery_tag):
    return (
        SimpleNamespace(delivery_tag=delivery_tag),
        json.dumps({"internal": {"work_id": f"work-{delivery_tag}"}}).encode("utf-8"),
    )


def _shutdown_listener(listener):
    shutdown = getattr(listener, "_shutdown_worker_pool", None)
    if shutdown is not None:
        shutdown()
        return
    worker_pool = getattr(listener, "_worker_pool", None)
    if worker_pool is not None:
        worker_pool.shutdown(wait=True)


def _run_once(iterations: int, callback_sleep_seconds: float, worker_count: int):
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
            return True
        finally:
            with lock:
                active_callbacks -= 1

    listener = _listener(callback, worker_count)
    expected_acks = 0
    started_at = time.perf_counter()
    try:
        for iteration in range(iterations):
            for offset in range(2):
                delivery_tag = iteration * 2 + offset + 1
                method, body = _message(delivery_tag)
                listener._process_message(listener.channel, method, None, body)
                expected_acks += 1
            while len(listener.channel.acked_delivery_tags) < expected_acks:
                listener.pika_connection.sleep(0.001)
    finally:
        _shutdown_listener(listener)
    return time.perf_counter() - started_at, max_in_flight


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--callback-sleep-ms", type=float, default=5.0)
    parser.add_argument("--worker-count", type=int, default=2)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args()

    callback_sleep_seconds = args.callback_sleep_ms / 1000
    _run_once(min(args.iterations, 2), callback_sleep_seconds, args.worker_count)
    samples = [
        _run_once(args.iterations, callback_sleep_seconds, args.worker_count)
        for _ in range(args.repeat)
    ]
    runtime_samples = [sample[0] for sample in samples]
    max_in_flight_samples = [sample[1] for sample in samples]
    result = {
        "iterations": args.iterations,
        "callback_sleep_ms": args.callback_sleep_ms,
        "worker_count": args.worker_count,
        "repeat": args.repeat,
        "median_runtime_ms": round(statistics.median(runtime_samples) * 1000, 3),
        "min_runtime_ms": round(min(runtime_samples) * 1000, 3),
        "max_runtime_ms": round(max(runtime_samples) * 1000, 3),
        "median_max_in_flight": int(statistics.median(max_in_flight_samples)),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
