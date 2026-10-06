# coding: utf-8
"""Unit tests of the incident and case timeline API (OpenCTI-Platform/opencti#18681)."""

import json
from unittest.mock import MagicMock, patch

import pytest

from pycti import STIX_EXT_OCTI_TIMELINE, OpenCTIApiClient, OpenCTIStix2
from pycti.utils.opencti_stix2_utils import TIMELINE_REQUIRED_IDS

CONTAINER_ID = "c1a1b5c3-38e0-4f0a-9df1-8b7a9e3a4a10"
EVENT = {"id": "e1", "title": "Hosts isolated", "kind": "containment"}


@pytest.fixture
def local_api_client():
    """A real OpenCTIApiClient instance, without hitting the network."""
    with patch.object(OpenCTIApiClient, "_setup_proxy_certificates"):
        client = OpenCTIApiClient(
            url="http://localhost:4000",
            token="test-token",
            ssl_verify=False,
            perform_health_check=False,
        )
        client.app_logger = MagicMock()
        client.query = MagicMock()
        return client


def sent_variables(client):
    return client.query.call_args[0][1]


def sent_query(client):
    return client.query.call_args[0][0]


def test_create_sends_only_the_provided_fields(local_api_client):
    local_api_client.query.return_value = {"data": {"timelineEventAdd": EVENT}}
    result = local_api_client.timeline_event.create(
        container_id=CONTAINER_ID,
        event_time="2026-02-05T10:30:00.000Z",
        title="Hosts isolated",
        kind="containment",
        lane="response",
        external_id="splunk-alert-42",
    )
    assert result["title"] == "Hosts isolated"
    assert "timelineEventAdd" in sent_query(local_api_client)
    assert sent_variables(local_api_client) == {
        "input": {
            "container_id": CONTAINER_ID,
            "event_time": "2026-02-05T10:30:00.000Z",
            "title": "Hosts isolated",
            "kind": "containment",
            "lane": "response",
            "external_id": "splunk-alert-42",
        }
    }


def test_create_sends_the_fields_passed_as_none_as_null(local_api_client):
    local_api_client.query.return_value = {"data": {"timelineEventAdd": EVENT}}
    local_api_client.timeline_event.create(
        container_id=CONTAINER_ID,
        event_time="2026-02-05T10:30:00.000Z",
        title="Hosts isolated",
        external_id="splunk-alert-42",
        element_id=None,
        confidence=None,
        createdBy=None,
    )
    assert sent_variables(local_api_client) == {
        "input": {
            "container_id": CONTAINER_ID,
            "event_time": "2026-02-05T10:30:00.000Z",
            "title": "Hosts isolated",
            "external_id": "splunk-alert-42",
            "element_id": None,
            "confidence": None,
            "createdBy": None,
        }
    }


@pytest.mark.parametrize(
    "missing",
    ["container_id", "event_time", "title"],
)
def test_create_requires_container_time_and_title(local_api_client, missing):
    arguments = {
        "container_id": CONTAINER_ID,
        "event_time": "2026-02-05T10:30:00.000Z",
        "title": "Hosts isolated",
    }
    del arguments[missing]
    assert local_api_client.timeline_event.create(**arguments) is None
    local_api_client.query.assert_not_called()


def test_create_rejects_unknown_lane_and_precision(local_api_client):
    base = {
        "container_id": CONTAINER_ID,
        "event_time": "2026-02-05T10:30:00.000Z",
        "title": "Hosts isolated",
    }
    assert local_api_client.timeline_event.create(**base, lane="timeline") is None
    assert local_api_client.timeline_event.create(**base, precision="minute") is None
    local_api_client.query.assert_not_called()


def test_update_only_sends_editable_fields(local_api_client):
    local_api_client.query.return_value = {"data": {"timelineEventEdit": EVENT}}
    local_api_client.timeline_event.update(
        id="e1", annotation="Confirmed", title="Hosts isolated by the SOC", pinned=True
    )
    assert sent_variables(local_api_client) == {
        "id": "e1",
        "input": {"annotation": "Confirmed", "title": "Hosts isolated by the SOC"},
    }


def test_update_clears_fields_passed_as_none(local_api_client):
    local_api_client.query.return_value = {"data": {"timelineEventEdit": EVENT}}
    local_api_client.timeline_event.update(id="e1", annotation=None, description=None)
    assert sent_variables(local_api_client) == {
        "id": "e1",
        "input": {"annotation": None, "description": None},
    }


def test_update_clears_the_end_time_through_its_flag(local_api_client):
    local_api_client.query.return_value = {"data": {"timelineEventEdit": EVENT}}
    local_api_client.timeline_event.update(id="e1", event_end_time=None)
    assert sent_variables(local_api_client) == {
        "id": "e1",
        "input": {"clear_event_end_time": True},
    }


def test_update_without_fields_does_nothing(local_api_client):
    assert local_api_client.timeline_event.update(id="e1") is None
    local_api_client.query.assert_not_called()


def test_pin_and_hide_default_to_true(local_api_client):
    local_api_client.query.return_value = {"data": {"timelineEventPin": EVENT}}
    local_api_client.timeline_event.pin(id="e1")
    assert "timelineEventPin(id: $id, pinned: $value)" in sent_query(local_api_client)
    assert sent_variables(local_api_client) == {"id": "e1", "value": True}
    local_api_client.query.return_value = {"data": {"timelineEventHide": EVENT}}
    local_api_client.timeline_event.hide(id="e1", hidden=False)
    assert "timelineEventHide(id: $id, hidden: $value)" in sent_query(local_api_client)
    assert sent_variables(local_api_client) == {"id": "e1", "value": False}


def test_delete_returns_the_deleted_id(local_api_client):
    local_api_client.query.return_value = {"data": {"timelineEventDelete": "e1"}}
    assert local_api_client.timeline_event.delete(id="e1") == "e1"


def page(nodes, has_next, end_cursor):
    return {
        "data": {
            "containerTimeline": {
                "edges": [{"node": node} for node in nodes],
                "pageInfo": {
                    "startCursor": None,
                    "endCursor": end_cursor,
                    "hasNextPage": has_next,
                    "hasPreviousPage": False,
                    "globalCount": 3,
                },
            }
        }
    }


def test_list_maps_the_filters_and_iterates_pages(local_api_client):
    local_api_client.query.side_effect = [
        page([{"id": "e1"}, {"id": "e2"}], True, "cursor-1"),
        page([{"id": "e3"}], False, "cursor-2"),
    ]
    events = local_api_client.timeline_event.list(
        container_id=CONTAINER_ID,
        lanes=["response"],
        from_time="2026-02-01T00:00:00.000Z",
        pinned_only=True,
        getAll=True,
    )
    assert [event["id"] for event in events] == ["e1", "e2", "e3"]
    first_call = local_api_client.query.call_args_list[0][0][1]
    assert first_call["id"] == CONTAINER_ID
    assert first_call["lanes"] == ["response"]
    assert first_call["from"] == "2026-02-01T00:00:00.000Z"
    assert first_call["pinnedOnly"] is True
    assert first_call["includeHidden"] is False
    assert local_api_client.query.call_args_list[1][0][1]["after"] == "cursor-1"


def test_default_properties_tell_an_open_window_from_a_point_event(local_api_client):
    # Neither has an end time: only open_ended tells an active deployment or a running hunt from a point event
    properties = local_api_client.timeline_event.properties.split()
    assert "event_end_time" in properties
    assert "open_ended" in properties


def test_list_requires_a_container(local_api_client):
    assert local_api_client.timeline_event.list() is None
    local_api_client.query.assert_not_called()


def test_import_extension_serializes_the_extension(local_api_client):
    local_api_client.query.return_value = {
        "data": {"timelineImport": {"container_id": CONTAINER_ID, "manual_count": 1}}
    }
    extension = {
        "extension_type": "property-extension",
        "events": [],
        "annotations": [],
    }
    local_api_client.timeline_event.import_extension(
        container_id=CONTAINER_ID, extension=extension
    )
    assert sent_variables(local_api_client) == {
        "containerId": CONTAINER_ID,
        "extension": json.dumps(extension),
    }


def timeline_case(extension):
    return {
        "type": "case-incident",
        "id": "case-incident--7ad53e2a-d8f2-4f4d-8a5b-6c2a0a1b9b5f",
        "name": "Ransomware case",
        "extensions": {STIX_EXT_OCTI_TIMELINE: extension},
    }


def test_stix_import_recreates_the_timeline_contributions(local_api_client):
    stix2 = OpenCTIStix2(local_api_client)
    local_api_client.timeline_event.import_extension = MagicMock()
    extension = {
        "extension_type": "property-extension",
        "events": [{"id": "timeline-event--1", "title": "Hosts isolated"}],
        "annotations": [],
    }
    stix2.import_timeline_extension(timeline_case(extension), {"id": CONTAINER_ID})
    local_api_client.timeline_event.import_extension.assert_called_once_with(
        container_id=CONTAINER_ID, extension=extension
    )


def test_stix_import_ignores_empty_extensions_and_other_types(local_api_client):
    stix2 = OpenCTIStix2(local_api_client)
    local_api_client.timeline_event.import_extension = MagicMock()
    empty = {"extension_type": "property-extension", "events": [], "annotations": []}
    stix2.import_timeline_extension(timeline_case(empty), {"id": CONTAINER_ID})
    report = {**timeline_case({"events": [{"id": "x"}]}), "type": "report"}
    stix2.import_timeline_extension(report, {"id": CONTAINER_ID})
    stix2.import_timeline_extension(
        {"type": "incident", "id": "incident--1"}, {"id": CONTAINER_ID}
    )
    local_api_client.timeline_event.import_extension.assert_not_called()


NOTE_ID = "note--3a1b2c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"


def resent_case(extension):
    return {**timeline_case(extension), TIMELINE_REQUIRED_IDS: [NOTE_ID]}


def test_stix_import_of_a_resent_case_waits_for_its_required_elements(
    local_api_client,
):
    stix2 = OpenCTIStix2(local_api_client)
    local_api_client.timeline_event.import_extension = MagicMock()
    local_api_client.opencti_stix_object_or_stix_relationship.list = MagicMock(
        return_value=[]
    )
    extension = {"events": [{"id": "timeline-event--1", "element_ref": NOTE_ID}]}
    with pytest.raises(ValueError, match="MISSING_REFERENCE_ERROR.*" + NOTE_ID):
        stix2.import_timeline_extension(resent_case(extension), {"id": CONTAINER_ID})
    listing = local_api_client.opencti_stix_object_or_stix_relationship.list
    listing.assert_called_once()
    assert listing.call_args.kwargs["filters"]["filters"] == [
        {"key": "ids", "values": [NOTE_ID]}
    ]
    assert listing.call_args.kwargs["getAll"] is True
    local_api_client.timeline_event.import_extension.assert_not_called()


def test_stix_import_of_a_resent_case_imports_once_its_elements_exist(
    local_api_client,
):
    stix2 = OpenCTIStix2(local_api_client)
    local_api_client.timeline_event.import_extension = MagicMock()
    local_api_client.opencti_stix_object_or_stix_relationship.list = MagicMock(
        return_value=[{"id": "f3a1", "standard_id": NOTE_ID, "x_opencti_stix_ids": []}]
    )
    extension = {"events": [{"id": "timeline-event--1", "element_ref": NOTE_ID}]}
    stix2.import_timeline_extension(resent_case(extension), {"id": CONTAINER_ID})
    local_api_client.timeline_event.import_extension.assert_called_once_with(
        container_id=CONTAINER_ID, extension=extension
    )


def test_stix_import_resolves_the_required_elements_in_bulk(local_api_client):
    stix2 = OpenCTIStix2(local_api_client)
    refs = [f"note--{index:08d}-0000-4000-8000-000000000000" for index in range(1200)]

    # Every element exists, the last one under another of its STIX ids (a merged element)
    def found(**kwargs):
        values = kwargs["filters"]["filters"][0]["values"]
        return [
            (
                {
                    "id": "merged",
                    "standard_id": "note--other",
                    "x_opencti_stix_ids": [ref],
                }
                if ref == refs[-1]
                else {"id": ref + "-internal", "standard_id": ref}
            )
            for ref in values
        ]

    listing = MagicMock(side_effect=found)
    local_api_client.opencti_stix_object_or_stix_relationship.list = listing
    assert stix2.find_missing_timeline_refs(refs + [refs[0]]) == []
    # One request per batch of 500 ids, each id asked once
    assert [
        len(call.kwargs["filters"]["filters"][0]["values"])
        for call in listing.call_args_list
    ] == [500, 500, 200]
    listing.side_effect = lambda **kwargs: []
    assert stix2.find_missing_timeline_refs(refs[:2]) == refs[:2]


def test_stix_import_never_waits_for_internal_objects(local_api_client):
    # The lookup only sees STIX objects and relationships: a workspace or a user is never reported missing
    stix2 = OpenCTIStix2(local_api_client)
    listing = MagicMock(return_value=[])
    local_api_client.opencti_stix_object_or_stix_relationship.list = listing
    internal_refs = [
        "workspace--3d1c7b52-5a7e-4c1f-9f0e-2b6a8d4c1e90",
        "user--88ec0c6a-12ce-5e39-b486-354fe4a7084f",
    ]
    assert stix2.find_missing_timeline_refs(internal_refs) == []
    listing.assert_not_called()
    assert stix2.find_missing_timeline_refs(internal_refs + [NOTE_ID]) == [NOTE_ID]
    assert listing.call_args.kwargs["filters"]["filters"][0]["values"] == [NOTE_ID]


def test_stix_import_tolerates_platforms_without_timelines(local_api_client):
    stix2 = OpenCTIStix2(local_api_client)
    local_api_client.timeline_event.import_extension = MagicMock(
        side_effect=ValueError(
            {
                "name": "GRAPHQL_VALIDATION_FAILED",
                "error_message": 'Cannot query field "timelineImport" on type "Mutation".',
            }
        )
    )
    extension = {"events": [{"id": "timeline-event--1"}], "annotations": []}
    stix2.import_timeline_extension(timeline_case(extension), {"id": CONTAINER_ID})
    local_api_client.app_logger.warning.assert_called_once()


def test_stix_import_raises_other_failures(local_api_client):
    stix2 = OpenCTIStix2(local_api_client)
    local_api_client.timeline_event.import_extension = MagicMock(
        side_effect=ValueError({"name": "LOCK_ERROR", "error_message": "Lock timeout"})
    )
    extension = {"events": [{"id": "timeline-event--1"}], "annotations": []}
    with pytest.raises(ValueError):
        stix2.import_timeline_extension(timeline_case(extension), {"id": CONTAINER_ID})
