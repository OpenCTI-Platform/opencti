from unittest import TestCase

from prometheus_client import Counter, Enum

from pycti import OpenCTIMetricHandler


class TestOpenCTIMetricHandler(TestCase):
    def test_metric_exists(self):
        metric = OpenCTIMetricHandler(activated=True)
        self.assertTrue(metric._metric_exists("error_count", Counter))
        self.assertFalse(metric._metric_exists("error_count", Enum))
        self.assertFalse(metric._metric_exists("best_metric_count", Counter))
