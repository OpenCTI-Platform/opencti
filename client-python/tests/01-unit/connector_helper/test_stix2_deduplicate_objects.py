from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper


def test_stix2_deduplicate_objects_preserves_first_occurrence_order():
    first = {"id": "indicator--1", "name": "first"}
    duplicate = {"id": "indicator--1", "name": "duplicate"}
    second = {"id": "indicator--2", "name": "second"}

    result = OpenCTIConnectorHelper.stix2_deduplicate_objects(
        [first, duplicate, second, first]
    )

    assert result == [first, second]
    assert result[0] is first
    assert result[1] is second
