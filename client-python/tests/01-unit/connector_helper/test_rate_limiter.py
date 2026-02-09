import threading
from collections import deque
from unittest import TestCase
from unittest.mock import patch

from pycti.connector.opencti_connector_helper import RateLimiter


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


class TestRateLimiter(TestCase):
    def test_cleanup_old_timestamps(self):
        helper = DummyHelper()
        limiter = RateLimiter(helper, max_per_minute=2)
        now = 1000.0
        limiter.timestamps = deque([now - 61.0, now - 30.0])

        with patch("pycti.connector.opencti_connector_helper.time") as time_mock:
            time_mock.time.return_value = now
            time_mock.sleep.return_value = None
            wait_time = limiter.wait_if_needed()

        self.assertEqual(wait_time, 0.0)
        self.assertEqual(len(limiter.timestamps), 2)
        self.assertTrue(all(ts >= now - 60.0 for ts in limiter.timestamps))

    def test_concurrent_access_is_thread_safe(self):
        helper = DummyHelper()
        limiter = RateLimiter(helper, max_per_minute=100)

        counter_lock = threading.Lock()
        counter = {"value": 0}

        def fake_time():
            with counter_lock:
                counter["value"] += 1
                return 3000.0 + counter["value"] * 0.001

        def worker():
            limiter.wait_if_needed()

        with patch("pycti.connector.opencti_connector_helper.time") as time_mock:
            time_mock.time.side_effect = fake_time
            time_mock.sleep.return_value = None
            threads = [threading.Thread(target=worker) for _ in range(10)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)

        self.assertEqual(len(limiter.timestamps), 10)

    def test_no_wait_when_under_limit(self):
        helper = DummyHelper()
        limiter = RateLimiter(helper, max_per_minute=2)
        now = 5000.0

        with patch("pycti.connector.opencti_connector_helper.time") as time_mock:
            time_mock.time.return_value = now
            time_mock.sleep.return_value = None
            wait_time = limiter.wait_if_needed()

        self.assertEqual(wait_time, 0.0)
        self.assertEqual(len(limiter.timestamps), 1)
        self.assertAlmostEqual(limiter.timestamps[0], now, places=6)
