"""Tests for the API listen protocol in ListenQueue: request lifecycle and
concurrency model.

Covers the full _http_process_callback contract (auth, payload validation,
processing errors, happy path) plus the concurrency guarantees introduced to
keep the Uvicorn event loop responsive: /health stays live while a callback
is processing, and concurrent callback requests are serialized (single-flight)
through the dedicated executor documented on ListenQueue.__init__.
"""

import asyncio
import concurrent.futures
import threading
import time
from unittest import TestCase
from unittest.mock import MagicMock, patch

from pycti.connector.opencti_connector_helper import ListenQueue


class DummyLogger:
    def info(self, message, data=None):
        pass

    def error(self, message, data=None):
        pass


class DummyRequest:
    def __init__(self, payload):
        self.headers = {"Authorization": "Bearer test-token"}
        self._payload = payload

    async def json(self):
        return self._payload


def _build_listen_queue():
    listen_queue = ListenQueue.__new__(ListenQueue)
    listen_queue.helper = MagicMock()
    listen_queue.helper.connector_logger = DummyLogger()
    listen_queue.callback = MagicMock(return_value="success")
    listen_queue.connector_applicant_id = "test-applicant"
    listen_queue.pika_connection = None
    listen_queue.thread = None
    listen_queue._callback_executor = concurrent.futures.ThreadPoolExecutor(
        max_workers=1, thread_name_prefix="test-callback"
    )
    return listen_queue


class TestApiListenConcurrency(TestCase):
    # --- Happy path ---------------------------------------------------

    def test_single_valid_request_is_processed_and_returns_202(self):
        listen_queue = _build_listen_queue()
        listen_queue._data_handler = MagicMock()

        async def scenario():
            with patch.object(listen_queue, "is_token_valid", return_value=True):
                response = await listen_queue._http_process_callback(
                    DummyRequest({"event": {}})
                )
                self.assertEqual(response.status_code, 202)

        asyncio.run(scenario())
        listen_queue._callback_executor.shutdown(wait=True)
        listen_queue._data_handler.assert_called_once_with({"event": {}})

    def test_health_check_returns_200_at_rest(self):
        listen_queue = _build_listen_queue()

        async def scenario():
            response = await listen_queue._http_health_callback(DummyRequest(None))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.body, b'{"status":"ok"}')

        asyncio.run(scenario())
        listen_queue._callback_executor.shutdown(wait=True)

    # --- Bad path -------------------------------------------------------

    def test_missing_authorization_header_returns_401(self):
        listen_queue = _build_listen_queue()
        request = DummyRequest({"event": {}})
        request.headers = {}

        async def scenario():
            response = await listen_queue._http_process_callback(request)
            self.assertEqual(response.status_code, 401)

        asyncio.run(scenario())
        listen_queue._callback_executor.shutdown(wait=True)

    def test_invalid_token_returns_401(self):
        listen_queue = _build_listen_queue()

        async def scenario():
            with patch.object(listen_queue, "is_token_valid", return_value=False):
                response = await listen_queue._http_process_callback(
                    DummyRequest({"event": {}})
                )
                self.assertEqual(response.status_code, 401)

        asyncio.run(scenario())
        listen_queue._callback_executor.shutdown(wait=True)

    def test_invalid_json_payload_returns_400(self):
        listen_queue = _build_listen_queue()
        request = DummyRequest(None)

        async def raise_json_decode_error():
            raise __import__("json").JSONDecodeError("bad json", "", 0)

        request.json = raise_json_decode_error

        async def scenario():
            with patch.object(listen_queue, "is_token_valid", return_value=True):
                response = await listen_queue._http_process_callback(request)
                self.assertEqual(response.status_code, 400)

        asyncio.run(scenario())
        listen_queue._callback_executor.shutdown(wait=True)

    def test_data_handler_exception_returns_500(self):
        listen_queue = _build_listen_queue()
        listen_queue._data_handler = MagicMock(side_effect=ValueError("boom"))

        async def scenario():
            with patch.object(listen_queue, "is_token_valid", return_value=True):
                response = await listen_queue._http_process_callback(
                    DummyRequest({"event": {}})
                )
                self.assertEqual(response.status_code, 500)

        asyncio.run(scenario())
        listen_queue._callback_executor.shutdown(wait=True)

    # --- Concurrency model ----------------------------------------------

    def test_health_check_responds_while_callback_is_processing(self):
        listen_queue = _build_listen_queue()
        processing_started = threading.Event()
        release_processing = threading.Event()

        def blocking_data_handler(_json_data):
            processing_started.set()
            release_processing.wait(timeout=5)

        listen_queue._data_handler = blocking_data_handler

        async def scenario():
            with patch.object(listen_queue, "is_token_valid", return_value=True):
                callback_task = asyncio.ensure_future(
                    listen_queue._http_process_callback(DummyRequest({"event": {}}))
                )
                await asyncio.get_event_loop().run_in_executor(
                    None, processing_started.wait, 5
                )
                # The event loop must still service /health immediately.
                health_response = await listen_queue._http_health_callback(
                    DummyRequest(None)
                )
                self.assertEqual(health_response.status_code, 200)
                release_processing.set()
                callback_response = await callback_task
                self.assertEqual(callback_response.status_code, 202)

        asyncio.run(scenario())
        listen_queue._callback_executor.shutdown(wait=True)

    def test_concurrent_callbacks_are_serialized(self):
        listen_queue = _build_listen_queue()
        active_count = 0
        max_concurrent = 0
        lock = threading.Lock()

        def tracking_data_handler(_json_data):
            nonlocal active_count, max_concurrent
            with lock:
                active_count += 1
                max_concurrent = max(max_concurrent, active_count)
            time.sleep(0.05)
            with lock:
                active_count -= 1

        listen_queue._data_handler = tracking_data_handler

        async def scenario():
            with patch.object(listen_queue, "is_token_valid", return_value=True):
                responses = await asyncio.gather(
                    listen_queue._http_process_callback(DummyRequest({"event": {}})),
                    listen_queue._http_process_callback(DummyRequest({"event": {}})),
                    listen_queue._http_process_callback(DummyRequest({"event": {}})),
                )
                for response in responses:
                    self.assertEqual(response.status_code, 202)

        asyncio.run(scenario())
        listen_queue._callback_executor.shutdown(wait=True)

        self.assertEqual(max_concurrent, 1)

    # --- Edge cases -------------------------------------------------------

    def test_stop_shuts_down_executor_without_pika_connection(self):
        listen_queue = _build_listen_queue()
        listen_queue.exit_event = threading.Event()

        listen_queue.stop()

        self.assertTrue(listen_queue._callback_executor._shutdown)

    def test_stop_is_idempotent(self):
        """Calling stop() twice (e.g. duplicate signal handlers) must not
        raise, even though ThreadPoolExecutor.shutdown() is called again."""
        listen_queue = _build_listen_queue()
        listen_queue.exit_event = threading.Event()

        listen_queue.stop()
        listen_queue.stop()  # should not raise

        self.assertTrue(listen_queue._callback_executor._shutdown)
