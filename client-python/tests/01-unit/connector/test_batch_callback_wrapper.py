import queue
import threading
import time
from unittest import TestCase

from pycti.connector.opencti_connector_helper import BatchCallbackWrapper


class DummyLogger:
    def __init__(self):
        self.messages = []

    def info(self, message, data=None):
        self.messages.append(("info", message, data))

    def debug(self, message, data=None):
        self.messages.append(("debug", message, data))

    def warning(self, message, data=None):
        self.messages.append(("warning", message, data))

    def error(self, message, data=None):
        self.messages.append(("error", message, data))


class DummyHelper:
    def __init__(self):
        self.connector_logger = DummyLogger()
        self._state = None
        self.set_state_calls = []

    def get_state(self):
        return self._state

    def set_state(self, state):
        self._state = state
        self.set_state_calls.append(state)


class DummyMessage:
    def __init__(self, message_id):
        self.id = message_id


class TestBatchCallbackWrapper(TestCase):
    def setUp(self):
        self._original_interval = BatchCallbackWrapper._TIMER_CHECK_INTERVAL
        BatchCallbackWrapper._TIMER_CHECK_INTERVAL = 0.01

    def tearDown(self):
        BatchCallbackWrapper._TIMER_CHECK_INTERVAL = self._original_interval

    def test_batch_size_trigger_updates_state(self):
        helper = DummyHelper()
        helper.set_state({"recover_until": "now"})
        batches = []
        done = threading.Event()

        def callback(batch_data):
            batches.append(batch_data)
            done.set()

        wrapper = BatchCallbackWrapper(
            helper, callback, batch_size=2, batch_timeout=10.0
        )
        try:
            wrapper(DummyMessage("1-0"))
            wrapper(DummyMessage("2-0"))
            self.assertTrue(done.wait(timeout=5))
            self.assertEqual(len(batches), 1)
            batch_data = batches[0]
            self.assertEqual(
                batch_data["batch_metadata"]["trigger_reason"], "size_limit"
            )
            self.assertEqual(batch_data["batch_metadata"]["batch_size"], 2)
            self.assertEqual([m.id for m in batch_data["events"]], ["1-0", "2-0"])
            self.assertIsNotNone(helper.get_state())
            self.assertEqual(helper.get_state()["start_from"], "2-0")
            self.assertEqual(helper.get_state()["recover_until"], "now")
        finally:
            wrapper.stop()

    def test_batch_timeout_trigger(self):
        helper = DummyHelper()
        batches = []
        done = threading.Event()

        def callback(batch_data):
            batches.append(batch_data)
            done.set()

        wrapper = BatchCallbackWrapper(
            helper, callback, batch_size=10, batch_timeout=0.05
        )
        try:
            wrapper(DummyMessage("1-0"))
            self.assertTrue(done.wait(timeout=5))
            self.assertEqual(len(batches), 1)
            self.assertEqual(batches[0]["batch_metadata"]["trigger_reason"], "timeout")
            self.assertEqual(batches[0]["batch_metadata"]["batch_size"], 1)
        finally:
            wrapper.stop()

    def test_shutdown_processes_remaining_messages(self):
        helper = DummyHelper()
        batches = []

        def callback(batch_data):
            batches.append(batch_data)

        wrapper = BatchCallbackWrapper(
            helper, callback, batch_size=10, batch_timeout=10.0
        )
        wrapper(DummyMessage("9-0"))
        wrapper.stop()

        self.assertEqual(len(batches), 1)
        self.assertEqual(batches[0]["batch_metadata"]["trigger_reason"], "shutdown")
        self.assertEqual(batches[0]["batch_metadata"]["batch_size"], 1)

    def test_batch_callback_error_does_not_update_state(self):
        helper = DummyHelper()

        def failing_callback(_batch_data):
            raise ValueError("boom")

        wrapper = BatchCallbackWrapper(
            helper, failing_callback, batch_size=1, batch_timeout=10.0
        )
        batch_data = {
            "events": [DummyMessage("1-0")],
            "batch_metadata": {
                "batch_size": 1,
                "trigger_reason": "size_limit",
                "elapsed_time": 0.0,
                "timestamp": time.time(),
            },
        }
        try:
            with self.assertRaises(ValueError):
                wrapper._execute_batch_callback(batch_data)
        finally:
            wrapper.stop()

        self.assertEqual(helper.set_state_calls, [])
        self.assertIsNone(helper.get_state())

    def test_heartbeat_queue_puts_message(self):
        helper = DummyHelper()
        batches = []

        def callback(batch_data):
            batches.append(batch_data)

        wrapper = BatchCallbackWrapper(
            helper, callback, batch_size=1, batch_timeout=10.0
        )
        heartbeat_queue = queue.Queue(maxsize=1)
        wrapper.set_heartbeat_queue(heartbeat_queue)
        try:
            batch_data = {
                "events": [DummyMessage("5-0")],
                "batch_metadata": {
                    "batch_size": 1,
                    "trigger_reason": "size_limit",
                    "elapsed_time": 0.0,
                    "timestamp": time.time(),
                },
            }
            wrapper._execute_batch_callback(batch_data)
            self.assertEqual(heartbeat_queue.get_nowait(), "batch_processing")

            heartbeat_queue.put_nowait("already_full")
            wrapper._execute_batch_callback(batch_data)
            self.assertEqual(len(batches), 2)
            self.assertEqual(heartbeat_queue.qsize(), 1)
        finally:
            wrapper.stop()
