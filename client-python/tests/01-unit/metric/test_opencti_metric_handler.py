from unittest import TestCase

from prometheus_client import Counter, Enum

from pycti import OpenCTIMetricHandler
from pycti.utils.opencti_logger import logger


class TestOpenCTIMetricHandler(TestCase):
    def test_metric_exists(self):
        test_logger = logger("INFO")("test")
        metric = OpenCTIMetricHandler(test_logger, activated=True)
        self.assertTrue(metric._metric_exists("error_count", Counter))
        self.assertFalse(metric._metric_exists("error_count", Enum))
        self.assertFalse(metric._metric_exists("best_metric_count", Counter))
