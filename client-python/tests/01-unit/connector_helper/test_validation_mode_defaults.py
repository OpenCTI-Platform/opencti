"""Tests for validation_mode default behavior in connector helper.

Verifies that the default validation mode is 'draft' both at initialization
and when receiving messages without an explicit validation_mode field.
"""

from unittest import TestCase
from unittest.mock import MagicMock, patch

from pycti.connector.opencti_connector_helper import ListenQueue


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
        self.work_id = None
        self.validation_mode = None
        self.force_validation = None
        self.draft_id = None
        self.playbook = None
        self.enrichment_shared_organizations = None
        self.connect_type = "EXTERNAL_IMPORT"
        self.applicant_id = "test-applicant"
        self.callback = MagicMock(return_value="success")
        self.api = MagicMock()
        self.api_impersonate = MagicMock()


class TestValidationModeDefaults(TestCase):
    """Test that validation_mode defaults to 'draft' in all scenarios."""

    def test_helper_initial_validation_mode_is_draft(self):
        """OpenCTIConnectorHelper.__init__ should default validation_mode to 'draft'."""
        import inspect

        from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper

        source = inspect.getsource(OpenCTIConnectorHelper.__init__)
        assert 'self.validation_mode = "draft"' in source

    def test_data_handler_defaults_validation_mode_to_draft_when_missing(self):
        """When a message has no validation_mode, it should default to 'draft'."""
        helper = DummyHelper()
        listen_queue = ListenQueue.__new__(ListenQueue)
        listen_queue.helper = helper
        listen_queue.pika_connection = MagicMock()
        listen_queue.callback = helper.callback
        listen_queue.connector_applicant_id = "test-connector-applicant"

        # Minimal message without validation_mode in event data
        json_data = {
            "event": {
                "entity_id": "test-entity-id",
                "entity_type": "Report",
                # No "validation_mode" key — should default to "draft"
            },
            "internal": {
                "work_id": "work-123",
                "draft_id": "",
                "applicant_id": None,
            },
        }

        with patch.object(listen_queue, "_set_draft_id"):
            listen_queue._data_handler(json_data)

        assert helper.validation_mode == "draft"

    def test_data_handler_uses_provided_validation_mode(self):
        """When a message contains validation_mode, it should be used."""
        helper = DummyHelper()
        listen_queue = ListenQueue.__new__(ListenQueue)
        listen_queue.helper = helper
        listen_queue.pika_connection = MagicMock()
        listen_queue.callback = helper.callback
        listen_queue.connector_applicant_id = "test-connector-applicant"

        json_data = {
            "event": {
                "entity_id": "test-entity-id",
                "entity_type": "Report",
                "validation_mode": "workbench",
            },
            "internal": {
                "work_id": "work-123",
                "draft_id": "",
                "applicant_id": None,
            },
        }

        with patch.object(listen_queue, "_set_draft_id"):
            listen_queue._data_handler(json_data)

        assert helper.validation_mode == "workbench"
