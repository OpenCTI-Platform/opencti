import threading

from pycti.api.opencti_api_client import OpenCTIApiClient


def _client():
    client = object.__new__(OpenCTIApiClient)
    client.request_headers = {
        "Authorization": "Bearer test",
        "Content-Type": "application/json",
    }
    return client


def _snapshot(client):
    headers = client.get_request_headers(hide_token=False)
    return {
        "draft_id": client.get_draft_id(),
        "work_id": headers.get("opencti-work-id"),
        "applicant_id": headers.get("opencti-applicant-id"),
        "retry_number": headers.get("opencti-retry-number"),
    }


def test_contextual_request_headers_are_isolated_across_threads():
    client = _client()
    first_ready = threading.Event()
    second_ready = threading.Event()
    snapshots = {}

    def first_request():
        client.set_draft_id("draft--a")
        client.set_work_id("work--a")
        client.set_applicant_id_header("applicant--a")
        client.set_retry_number(1)
        first_ready.set()
        second_ready.wait()
        snapshots["a"] = _snapshot(client)

    def second_request():
        first_ready.wait()
        client.set_draft_id("draft--b")
        client.set_work_id("work--b")
        client.set_applicant_id_header("applicant--b")
        client.set_retry_number(2)
        second_ready.set()
        snapshots["b"] = _snapshot(client)

    first_thread = threading.Thread(target=first_request)
    second_thread = threading.Thread(target=second_request)
    first_thread.start()
    second_thread.start()
    first_thread.join()
    second_thread.join()

    assert snapshots == {
        "a": {
            "draft_id": "draft--a",
            "work_id": "work--a",
            "applicant_id": "applicant--a",
            "retry_number": "1",
        },
        "b": {
            "draft_id": "draft--b",
            "work_id": "work--b",
            "applicant_id": "applicant--b",
            "retry_number": "2",
        },
    }


def test_request_context_restores_previous_header_overrides():
    client = _client()
    client.set_work_id("work--outer")
    client.set_draft_id("draft--outer")

    with client.request_context():
        assert _snapshot(client) == {
            "draft_id": "",
            "work_id": None,
            "applicant_id": None,
            "retry_number": None,
        }
        client.set_work_id("work--inner")
        client.set_draft_id("draft--inner")
        assert _snapshot(client)["work_id"] == "work--inner"
        assert _snapshot(client)["draft_id"] == "draft--inner"

    assert _snapshot(client)["work_id"] == "work--outer"
    assert _snapshot(client)["draft_id"] == "draft--outer"


def test_contextual_setters_do_not_mutate_shared_transport_headers():
    client = _client()

    client.set_work_id("work--1")
    client.set_draft_id("draft--1")

    assert "opencti-work-id" not in client.request_headers
    assert "opencti-draft-id" not in client.request_headers
