import logging
from types import SimpleNamespace

from pycti.api.opencti_api_work import OpenCTIApiWork
from pycti.utils.opencti_stix2 import OpenCTIStix2


class _Api:
    def __init__(self):
        self.bundle_send_to_queue = True
        self.app_logger = logging.getLogger("test_opencti_api_work_expectation_batch")
        self.query_calls = []
        self.successful_query_calls = []
        self.external_reference = SimpleNamespace(
            generate_id=lambda *_args, **_kwargs: None
        )
        self.work = OpenCTIApiWork(self)

    def query(self, _query, variables=None, *_args, **_kwargs):
        self.query_calls.append(variables)
        self.successful_query_calls.append(variables)
        return {"data": {"workEdit": {"reportExpectation": variables["id"]}}}

    @staticmethod
    def get_draft_id():
        return ""

    @staticmethod
    def get_attribute_in_extension(_attribute, _entity):
        return None

    @staticmethod
    def logger_class(_name):
        return logging.getLogger("test_opencti_api_work_expectation_batch.worker")


def _reported_expectation_counts(api):
    return [variables.get("expectations", 1) for variables in api.query_calls]


def _successful_reported_expectation_counts(api):
    return [
        variables.get("expectations", 1) for variables in api.successful_query_calls
    ]


def test_expectation_batch_reports_successes_in_bounded_groups():
    api = _Api()

    with api.work.expectation_batch(batch_size=3):
        for _ in range(7):
            api.work.report_expectation("work--1", None)

    assert _reported_expectation_counts(api) == [3, 3, 1]


def test_expectation_batch_flushes_successes_before_error():
    api = _Api()
    error = {"error": "broken", "source": "unit-test"}

    with api.work.expectation_batch(batch_size=10):
        api.work.report_expectation("work--1", None)
        api.work.report_expectation("work--1", None)
        api.work.report_expectation("work--1", error)

    assert _reported_expectation_counts(api) == [2, 1]
    assert api.query_calls[1]["error"] == error


def test_import_bundle_batches_successful_work_expectations():
    api = _Api()
    stix2 = OpenCTIStix2(api)
    stix2._prefetch_import_vocabularies = lambda _items: None
    stix2._prefetch_import_external_references = lambda _items: None
    stix2._prefetch_import_kill_chain_phases = lambda _items: None
    stix2._prefetch_import_labels = lambda _items: None

    def import_item_with_retries(_item, _update, _types, work_id, _bundle_id):
        stix2.opencti.work.report_expectation(work_id, None)
        return None

    stix2.import_item_with_retries = import_item_with_retries
    stix2.import_bundle(
        {
            "type": "bundle",
            "id": "bundle--work-expectations",
            "objects": [
                {"id": f"malware--{index:08d}", "type": "malware"}
                for index in range(101)
            ],
        },
        work_id="work--1",
    )

    assert _reported_expectation_counts(api) == [100, 1]


def test_expectation_batch_falls_back_to_single_reports_on_older_platforms():
    api = _Api()
    original_query = api.query

    def query(query_text, variables=None, *args, **kwargs):
        if variables.get("expectations", 1) > 1:
            api.query_calls.append(variables)
            raise ValueError('Unknown argument "expectations"')
        return original_query(query_text, variables, *args, **kwargs)

    api.query = query

    with api.work.expectation_batch(batch_size=3):
        for _ in range(3):
            api.work.report_expectation("work--1", None)

    assert _reported_expectation_counts(api) == [3, 1, 1, 1]


def test_expectation_batch_retries_only_unreported_chunks_after_failure():
    api = _Api()
    original_query = api.query
    failed_once = False

    def query(query_text, variables=None, *args, **kwargs):
        nonlocal failed_once
        if (
            not failed_once
            and variables.get("expectations", 1) == 3
            and len(api.successful_query_calls) == 1
        ):
            api.query_calls.append(variables)
            failed_once = True
            raise RuntimeError("temporary report failure")
        return original_query(query_text, variables, *args, **kwargs)

    api.query = query

    with api.work.expectation_batch(batch_size=3):
        api.work.report_expectation("work--1", None, expectations=7)

    assert _reported_expectation_counts(api) == [3, 3, 3, 1]
    assert _successful_reported_expectation_counts(api) == [3, 3, 1]


def test_expectation_batch_old_platform_fallback_retries_only_unreported_singles():
    api = _Api()
    original_query = api.query
    failed_single_once = False

    def query(query_text, variables=None, *args, **kwargs):
        nonlocal failed_single_once
        if variables.get("expectations", 1) > 1:
            api.query_calls.append(variables)
            raise ValueError('Unknown argument "expectations"')
        if not failed_single_once and len(api.successful_query_calls) == 1:
            api.query_calls.append(variables)
            failed_single_once = True
            raise RuntimeError("temporary report failure")
        return original_query(query_text, variables, *args, **kwargs)

    api.query = query

    with api.work.expectation_batch(batch_size=3):
        api.work.report_expectation("work--1", None, expectations=3)

    assert _reported_expectation_counts(api) == [3, 1, 1, 1, 1]
    assert _successful_reported_expectation_counts(api) == [1, 1, 1]


def test_expectation_batch_reports_error_even_when_pending_success_flush_fails():
    api = _Api()
    original_query = api.query
    failed_once = False
    error = {"error": "broken", "source": "unit-test"}

    def query(query_text, variables=None, *args, **kwargs):
        nonlocal failed_once
        if (
            not failed_once
            and variables.get("expectations", 1) == 2
            and variables["error"] is None
        ):
            api.query_calls.append(variables)
            failed_once = True
            raise RuntimeError("temporary report failure")
        return original_query(query_text, variables, *args, **kwargs)

    api.query = query

    with api.work.expectation_batch(batch_size=10):
        api.work.report_expectation("work--1", None)
        api.work.report_expectation("work--1", None)
        api.work.report_expectation("work--1", error)

    assert _reported_expectation_counts(api) == [2, 1, 2]
    assert _successful_reported_expectation_counts(api) == [1, 2]
    assert api.successful_query_calls[0]["error"] == error
