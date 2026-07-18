import json
import queue
import threading
import time
from types import SimpleNamespace

from pycti.connector.opencti_connector_helper import (
    IN_FLIGHT_WORK_PING_INTERVAL_SECONDS,
    ListenQueue,
)


class _NoopLogger:
    def info(self, *_args, **_kwargs):
        pass

    def error(self, *_args, **_kwargs):
        pass


class _Helper:
    def __init__(self):
        self.connector_logger = _NoopLogger()
        self.api = SimpleNamespace(work=SimpleNamespace(ping=self._ping))
        self.pinged_work_ids = []

    def _ping(self, work_id):
        self.pinged_work_ids.append(work_id)


class _FakeChannel:
    def __init__(self):
        self.acked_delivery_tags = []
        self.nacked_delivery_tags = []
        self.ack_thread_ids = []
        self.is_closed = False

    def basic_ack(self, delivery_tag):
        self.acked_delivery_tags.append(delivery_tag)
        self.ack_thread_ids.append(threading.get_ident())

    def basic_nack(self, delivery_tag, requeue=True):
        self.nacked_delivery_tags.append((delivery_tag, requeue))


class _FakeConnection:
    def __init__(self):
        self._callbacks = queue.Queue()
        self.scheduled_callbacks = []
        self.is_closed = False

    def add_callback_threadsafe(self, callback):
        self._callbacks.put(callback)

    def call_later(self, delay, callback):
        self.scheduled_callbacks.append((delay, callback))
        return len(self.scheduled_callbacks)

    def drain_callbacks(self):
        while True:
            try:
                callback = self._callbacks.get_nowait()
            except queue.Empty:
                return
            callback()


def _listener(callback, worker_count=1):
    listener = object.__new__(ListenQueue)
    listener.helper = _Helper()
    listener._data_handler = callback
    listener.pika_connection = _FakeConnection()
    listener.channel = _FakeChannel()
    listener.exit_event = threading.Event()
    listener.listen_worker_count = worker_count
    listener.listen_prefetch_count = worker_count
    listener._worker_pool = None
    listener._in_flight_messages = {}
    listener._in_flight_lock = threading.Lock()
    return listener


def _deliver(listener, delivery_tag, marker=None):
    body = json.dumps(
        {
            "event": {"marker": marker},
            "internal": {"work_id": f"work-{delivery_tag}"},
        }
    ).encode("utf-8")
    listener._process_message(
        listener.channel,
        SimpleNamespace(delivery_tag=delivery_tag),
        None,
        body,
    )


def _drain_until(listener, predicate, timeout=1.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        listener.pika_connection.drain_callbacks()
        if predicate():
            return
        time.sleep(0.001)
    listener.pika_connection.drain_callbacks()
    assert predicate()


def test_amqp_listener_acks_only_after_callback_completion_on_connection_thread():
    callback_started = threading.Event()
    release_callback = threading.Event()

    def callback(_data):
        callback_started.set()
        release_callback.wait(timeout=1.0)
        return True

    listener = _listener(callback)
    owner_thread_id = threading.get_ident()
    try:
        _deliver(listener, 1)
        assert callback_started.wait(timeout=1.0)
        assert listener.channel.acked_delivery_tags == []
        assert listener.channel.nacked_delivery_tags == []

        release_callback.set()
        _drain_until(listener, lambda: listener.channel.acked_delivery_tags == [1])

        assert listener.channel.ack_thread_ids == [owner_thread_id]
        assert listener.channel.nacked_delivery_tags == []
        assert listener._in_flight_messages == {}
    finally:
        listener._shutdown_worker_pool()


def test_amqp_listener_runs_multiple_callbacks_in_flight_with_worker_pool():
    first_started = threading.Event()
    second_started = threading.Event()
    release_callbacks = threading.Event()

    def callback(data):
        if data["event"]["marker"] == "a":
            first_started.set()
        else:
            second_started.set()
        release_callbacks.wait(timeout=1.0)
        return True

    listener = _listener(callback, worker_count=2)
    try:
        _deliver(listener, 1, "a")
        _deliver(listener, 2, "b")

        assert first_started.wait(timeout=1.0)
        assert second_started.wait(timeout=1.0)
        assert listener.channel.acked_delivery_tags == []

        release_callbacks.set()
        _drain_until(
            listener,
            lambda: sorted(listener.channel.acked_delivery_tags) == [1, 2],
        )
        assert listener._in_flight_messages == {}
    finally:
        listener._shutdown_worker_pool()


def test_amqp_listener_nacks_when_processing_has_no_durable_outcome():
    listener = _listener(lambda _data: False)
    try:
        _deliver(listener, 1)
        _drain_until(
            listener, lambda: listener.channel.nacked_delivery_tags == [(1, True)]
        )

        assert listener.channel.acked_delivery_tags == []
        assert listener._in_flight_messages == {}
    finally:
        listener._shutdown_worker_pool()


def test_amqp_listener_preserves_long_running_work_keepalive_pings():
    listener = _listener(lambda _data: True)
    listener._in_flight_messages[(1, 1)] = {
        "work_id": "work-1",
        "last_ping": time.monotonic() - IN_FLIGHT_WORK_PING_INTERVAL_SECONDS - 1,
    }

    listener._ping_in_flight_work()

    assert listener.helper.pinged_work_ids == ["work-1"]
    assert len(listener.pika_connection.scheduled_callbacks) == 1
