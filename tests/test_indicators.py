# coding: utf-8

import json

import pytest
from dateutil.parser import parse
from stix2 import TLP_GREEN, TLP_WHITE

from pycti import OpenCTIApiClient


@pytest.fixture
def api_client():
    return OpenCTIApiClient(
        "https://demo.opencti.io",
        "681b01f9-542d-4c8c-be0c-b6c850b087c8",
        ssl_verify=True,
    )


@pytest.fixture
def test_indicator(api_client):
    # Define the date
    date = parse("2019-12-01").strftime("%Y-%m-%dT%H:%M:%SZ")
    date2 = parse("2021-12-01").strftime("%Y-%m-%dT%H:%M:%SZ")

    marking_definition_green = api_client.marking_definition.read(id=TLP_GREEN["id"])
    marking_definition_white = api_client.marking_definition.read(id=TLP_WHITE["id"])

    # Create the organization
    organization = api_client.identity.create(
        type="Organization", name="Testing Inc.", description="OpenCTI Test Org"
    )
    return api_client.indicator.create(
        name="C2 server of the new campaign",
        description="This is the C2 server of the campaign",
        pattern_type="stix",
        pattern="[domain-name:value = 'www.5z8.info' AND domain-name:resolves_to_refs[*].value = '198.51.100.1/32']",
        x_opencti_main_observable_type="IPv4-Addr",
        confidence=60,
        x_opencti_score=80,
        x_opencti_detection=True,
        valid_from=date,
        valid_until=date2,
        created=date,
        modified=date,
        createdBy=organization["id"],
        objectMarking=[
            marking_definition_green["id"],
            marking_definition_white["id"],
        ],
        update=True,
        # TODO: killChainPhases
    )


def test_create_indicator(test_indicator):
    assert test_indicator["id"] is not None or test_indicator["id"] != ""


def test_read_indicator_by_id(api_client, test_indicator):
    indicator = api_client.indicator.read(id=test_indicator["id"])
    assert indicator["id"] is not None or indicator["id"] != ""
    assert indicator["id"] == test_indicator["id"]


def test_read_indicator_by_filter(api_client, test_indicator):
    indicator2 = api_client.indicator.read(
        filters=[
            {
                "key": "name",
                "values": ["C2 server of the new campaign"],
            }
        ]
    )

    assert indicator2["id"] is not None or indicator2["id"] != ""
    assert indicator2["id"] == test_indicator["id"]


def test_get_100_indicators_with_pagination(api_client):
    # Get 100 Indicators using the pagination
    custom_attributes = """
        id
        revoked
        created
    """

    final_indicators = []
    data = api_client.indicator.list(
        first=50, customAttributes=custom_attributes, withPagination=True
    )
    final_indicators = final_indicators + data["entities"]

    assert len(final_indicators) == 50

    after = data["pagination"]["endCursor"]
    data = api_client.indicator.list(
        first=50,
        after=after,
        customAttributes=custom_attributes,
        withPagination=True,
    )
    final_indicators = final_indicators + data["entities"]

    assert len(final_indicators) == 100


def test_indicator_stix_marshall(api_client):
    with open("tests/data/indicator_stix.json", "r") as content_file:
        content = content_file.read()

    json_data = json.loads(content)

    for indic in json_data["objects"]:
        imported_indicator = api_client.indicator.import_from_stix2(
            stixObject=indic, update=True
        )
        assert imported_indicator is not None
