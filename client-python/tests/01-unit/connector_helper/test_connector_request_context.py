import threading

from pycti.connector.opencti_connector_helper import ListenQueue, OpenCTIConnectorHelper


class _NoopLogger:
    def error(self, *_args, **_kwargs):
        pass


class _NoopMetric:
    def inc(self, *_args, **_kwargs):
        pass


class _FakeWork:
    def to_received(self, *_args, **_kwargs):
        pass

    def to_processed(self, *_args, **_kwargs):
        pass


class _FakeApi:
    def __init__(self):
        self.work = _FakeWork()
        self.draft_id = ""
        self.applicant_id = None

    def set_draft_id(self, draft_id):
        self.draft_id = draft_id

    def set_applicant_id_header(self, applicant_id):
        self.applicant_id = applicant_id


def _helper():
    helper = object.__new__(OpenCTIConnectorHelper)
    helper.work_id = None
    helper.validation_mode = "workbench"
    helper.force_validation = False
    helper.draft_id = None
    helper.playbook = None
    helper.enrichment_shared_organizations = None
    helper.applicant_id = "connector-applicant"
    helper.connect_type = "EXTERNAL_IMPORT"
    helper.api = _FakeApi()
    helper.api_impersonate = _FakeApi()
    helper.metric = _NoopMetric()
    helper.connector_logger = _NoopLogger()
    return helper


def _message(request_id):
    return {
        "event": {
            "marker": request_id,
            "validation_mode": f"validation-{request_id}",
            "force_validation": request_id == "b",
        },
        "internal": {
            "work_id": f"work-{request_id}",
            "draft_id": f"draft-{request_id}",
            "applicant_id": f"applicant-{request_id}",
        },
    }


def _snapshot(helper):
    return {
        "work_id": helper.work_id,
        "draft_id": helper.draft_id,
        "applicant_id": helper.applicant_id,
        "validation_mode": helper.validation_mode,
        "force_validation": helper.force_validation,
    }


def test_data_handler_isolates_overlapping_request_context():
    helper = _helper()
    first_ready = threading.Event()
    second_ready = threading.Event()
    snapshots = {}

    def callback(event_data):
        marker = event_data["marker"]
        if marker == "a":
            first_ready.set()
            second_ready.wait()
        else:
            second_ready.set()
        snapshots[marker] = _snapshot(helper)
        return "done"

    listen_queue = object.__new__(ListenQueue)
    listen_queue.helper = helper
    listen_queue.callback = callback
    listen_queue.connector_applicant_id = "connector-applicant"

    first_thread = threading.Thread(
        target=listen_queue._data_handler, args=(_message("a"),)
    )
    second_thread = threading.Thread(
        target=listen_queue._data_handler, args=(_message("b"),)
    )
    first_thread.start()
    first_ready.wait()
    second_thread.start()
    first_thread.join()
    second_thread.join()

    assert snapshots == {
        "a": {
            "work_id": "work-a",
            "draft_id": "draft-a",
            "applicant_id": "applicant-a",
            "validation_mode": "validation-a",
            "force_validation": False,
        },
        "b": {
            "work_id": "work-b",
            "draft_id": "draft-b",
            "applicant_id": "applicant-b",
            "validation_mode": "validation-b",
            "force_validation": True,
        },
    }


def test_request_context_restores_helper_defaults():
    helper = _helper()

    with helper.request_context():
        helper.work_id = "work-inner"
        helper.draft_id = "draft-inner"
        helper.applicant_id = "applicant-inner"
        assert _snapshot(helper)["work_id"] == "work-inner"

    assert _snapshot(helper) == {
        "work_id": None,
        "draft_id": None,
        "applicant_id": "connector-applicant",
        "validation_mode": "workbench",
        "force_validation": False,
    }
