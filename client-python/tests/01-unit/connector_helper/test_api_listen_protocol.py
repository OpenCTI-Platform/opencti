import asyncio
import json
import threading
import time
from unittest import IsolatedAsyncioTestCase

from pycti.connector.opencti_connector_helper import ListenQueue, _health, app


class DummyLogger:
    def info(self, message, data=None):
        pass

    def debug(self, message, data=None):
        pass

    def warning(self, message, data=None):
        pass

    def error(self, message, data=None):
        pass


class DummyHelper:
    def __init__(self):
        self.connector_logger = DummyLogger()


class FakeRequest:
    """Minimal stand-in for a FastAPI Request for the API listen callback."""

    def __init__(self, payload, token="valid-token"):
        self.headers = {"Authorization": f"Bearer {token}"}
        self._payload = payload

    async def json(self):
        return self._payload


def _make_listen_queue(data_handler):
    """Build a minimal ListenQueue without running the heavy __init__.

    Only the attributes used by _http_process_callback are set.
    """
    lq = ListenQueue.__new__(ListenQueue)
    lq.helper = DummyHelper()
    lq._callback_lock = None
    lq.is_token_valid = lambda token: True
    lq._data_handler = data_handler
    return lq


class TestApiListenProtocol(IsolatedAsyncioTestCase):
    async def test_health_endpoint_returns_200(self):
        response = await _health()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.body), {"status": "ok"})

    async def test_health_route_registered_once(self):
        # Registered at module import; must appear exactly once even though
        # ListenQueue.run() may be entered multiple times in a process.
        health_routes = [
            r for r in app.routes if getattr(r, "path", None) == "/health"
        ]
        self.assertEqual(len(health_routes), 1)

    async def test_callbacks_are_serialized(self):
        """Concurrent POST callbacks must not run _data_handler concurrently.

        _data_handler mutates shared connector state, so the async lock must
        serialize it even though it now runs in a worker thread.
        """
        state = {"current": 0, "max": 0}
        counter_lock = threading.Lock()

        def data_handler(_data):
            with counter_lock:
                state["current"] += 1
                state["max"] = max(state["max"], state["current"])
            time.sleep(0.05)
            with counter_lock:
                state["current"] -= 1

        lq = _make_listen_queue(data_handler)
        responses = await asyncio.gather(
            lq._http_process_callback(FakeRequest({"a": 1})),
            lq._http_process_callback(FakeRequest({"b": 2})),
            lq._http_process_callback(FakeRequest({"c": 3})),
        )
        self.assertEqual(state["max"], 1)
        self.assertTrue(all(r.status_code == 202 for r in responses))

    async def test_event_loop_not_blocked_during_processing(self):
        """A long _data_handler must not block the event loop.

        A concurrent lightweight coroutine (standing in for /health) should
        complete while _data_handler is still processing in a worker thread.
        """
        order = []

        def slow_handler(_data):
            time.sleep(0.2)
            order.append("handler_done")

        lq = _make_listen_queue(slow_handler)

        async def quick_task():
            await asyncio.sleep(0.05)
            order.append("quick_done")

        await asyncio.gather(
            lq._http_process_callback(FakeRequest({"x": 1})),
            quick_task(),
        )
        self.assertEqual(order[0], "quick_done")

    async def test_invalid_token_returns_401_without_running_handler(self):
        def data_handler(_data):
            raise AssertionError("handler must not run for an invalid token")

        lq = _make_listen_queue(data_handler)
        lq.is_token_valid = lambda token: False
        response = await lq._http_process_callback(FakeRequest({"a": 1}))
        self.assertEqual(response.status_code, 401)
