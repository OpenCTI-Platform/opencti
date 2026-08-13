"""Unit tests ensuring PushHandler.handle_message's telemetry recording in the
finally block can never override the ack/nack decision made by the try/except
above it, and can never itself escape as an unhandled exception.

These tests build a PushHandler without running __post_init__ (which opens a
real OpenCTIApiClient/network session), constructing only the attributes that
handle_message actually touches.
"""

import base64
import json
from unittest.mock import MagicMock

from push_handler import PushHandler


def make_push_handler(
    bundles_processing_time_gauge=None, bundles_global_counter=None
) -> PushHandler:
    handler = PushHandler.__new__(PushHandler)
    handler.logger = MagicMock()
    handler.api = MagicMock()
    handler.bundles_global_counter = bundles_global_counter or MagicMock()
    handler.bundles_processing_time_gauge = (
        bundles_processing_time_gauge or MagicMock()
    )
    handler.objects_max_refs = 0
    return handler


def encode_message(bundle: dict, **extra) -> str:
    content_json = json.dumps(bundle)
    content_b64 = base64.b64encode(content_json.encode("utf-8")).decode("utf-8")
    data = {"type": "bundle", "content": content_b64, **extra}
    return json.dumps(data)


class TestFinallyBlockNeverOverridesResult:
    def test_telemetry_failure_does_not_mask_ack_result(self):
        gauge = MagicMock()
        gauge.record.side_effect = RuntimeError("telemetry backend unavailable")
        handler = make_push_handler(bundles_processing_time_gauge=gauge)
        bundle = {"type": "bundle", "objects": [{"type": "malware", "id": "malware--1"}]}
        handler.api.stix2.import_bundle_from_json.return_value = ([], [])

        result = handler.handle_message(encode_message(bundle))

        # The try block's "ack" must be returned, not masked by the finally
        # block's own exception.
        assert result == "ack"
        handler.logger.error.assert_called_once()
        assert "telemetry" in handler.logger.error.call_args[0][0].lower()

    def test_telemetry_failure_does_not_mask_nack_result(self):
        gauge = MagicMock()
        gauge.record.side_effect = RuntimeError("telemetry backend unavailable")
        handler = make_push_handler(bundles_processing_time_gauge=gauge)
        handler.api.stix2.import_bundle_from_json.side_effect = ValueError(
            "Observable is not correctly formatted"
        )
        bundle = {"type": "bundle", "objects": [{"type": "software", "id": "software--1"}]}

        result = handler.handle_message(encode_message(bundle))

        assert result == "nack"
        # Both the original processing error and the telemetry error are logged.
        assert handler.logger.error.call_count == 2

    def test_telemetry_success_path_unaffected(self):
        handler = make_push_handler()
        bundle = {"type": "bundle", "objects": [{"type": "malware", "id": "malware--1"}]}
        handler.api.stix2.import_bundle_from_json.return_value = (
            [{"id": "malware--1", "type": "malware"}],
            [],
        )

        result = handler.handle_message(encode_message(bundle))

        assert result == "ack"
        handler.bundles_global_counter.add.assert_called_once_with(1)
        handler.bundles_processing_time_gauge.record.assert_called_once()
        handler.logger.error.assert_not_called()
