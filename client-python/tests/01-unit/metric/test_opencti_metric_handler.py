from unittest import TestCase

from prometheus_client import REGISTRY, Counter, Enum, Info

from pycti import OpenCTIMetricHandler
from pycti.utils.opencti_logger import logger


class TestOpenCTIMetricHandler(TestCase):
    @classmethod
    def setUpClass(cls):
        # Metrics are registered in the global Prometheus registry,
        # so the handler can only be instantiated once per process.
        test_logger = logger("INFO")("test")
        cls.metric = OpenCTIMetricHandler(
            test_logger,
            activated=True,
            namespace="opencti",
            subsystem="connector",
            port=0,
        )

    def test_metric_exists(self):
        self.assertTrue(self.metric._metric_exists("error_count", Counter))
        self.assertFalse(self.metric._metric_exists("error_count", Enum))
        self.assertFalse(self.metric._metric_exists("best_metric_count", Counter))
        self.assertTrue(self.metric._metric_exists("identity", Info))

    def test_set_info(self):
        self.metric.set_info(
            connector_id="0b6f3c9e-1234-4abc-9def-0123456789ab",
            connector_name="My connector",
            connector_type="EXTERNAL_IMPORT",
            connector_scope="report",
        )
        # Prometheus recording rules join on these exact metric and label names
        self.assertEqual(
            REGISTRY.get_sample_value(
                "opencti_connector_identity_info",
                {
                    "id": "0b6f3c9e-1234-4abc-9def-0123456789ab",
                    "name": "My connector",
                    "type": "EXTERNAL_IMPORT",
                    "scope": "report",
                },
            ),
            1.0,
        )
