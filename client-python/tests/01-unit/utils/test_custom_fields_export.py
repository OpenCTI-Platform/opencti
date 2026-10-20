# coding: utf-8
"""Custom field values of an OpenCTI entity are flattened under their field name
for the exports (STIX and CSV)."""

from pycti import OpenCTIStix2


def test_flatten_custom_field_values_sets_each_value_under_its_field_name():
    entity = {
        "id": "entity-id",
        "customFieldValues": [
            {"field_id": "cf-1", "field_name": "x_opencti_cf_score", "int_value": 0},
            {
                "field_id": "cf-2",
                "field_name": "x_opencti_cf_flag",
                "boolean_value": False,
            },
            {
                "field_id": "cf-3",
                "field_name": "x_opencti_cf_tags",
                "int_value": None,
                "string_value": None,
                "select_values": ["a", "b"],
            },
            {
                "field_id": "cf-4",
                "field_name": "x_opencti_cf_due",
                "date_value": "2026-10-12T15:26:00.081Z",
            },
        ],
    }
    assert OpenCTIStix2.flatten_custom_field_values(entity) is entity
    assert entity == {
        "id": "entity-id",
        "x_opencti_cf_score": 0,
        "x_opencti_cf_flag": False,
        "x_opencti_cf_tags": ["a", "b"],
        "x_opencti_cf_due": "2026-10-12T15:26:00.081Z",
    }


def test_flatten_custom_field_values_removes_an_empty_list():
    # Feature flag disabled: the platform returns an empty list
    entity = {"id": "entity-id", "customFieldValues": []}
    assert OpenCTIStix2.flatten_custom_field_values(entity) == {"id": "entity-id"}


def test_flatten_custom_field_values_ignores_an_entity_without_custom_fields():
    entity = {"id": "entity-id"}
    assert OpenCTIStix2.flatten_custom_field_values(entity) == {"id": "entity-id"}
