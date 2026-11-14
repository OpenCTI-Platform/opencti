# coding: utf-8
"""Unit tests covering the asset fields of the System identity.

The 7 asset fields (category, subcategory, internet facing, criticality,
environment, owner, platform) must be forwarded to the `systemAdd` GraphQL
mutation input by `create()`, and read by `import_from_stix2()` from the
top level of a STIX2 identity or from its OpenCTI extension.
"""

from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient, OpenCTIStix2
from pycti.entities.opencti_identity import SYSTEM_ASSET_FIELDS, Identity

OCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"

ASSET_VALUES = {
    "x_opencti_asset_category": "endpoint",
    "x_opencti_asset_subcategory": "server",
    "x_opencti_internet_facing": "yes",
    "x_opencti_criticality": "high",
    "x_opencti_environment": "production",
    "x_opencti_owner": "IT operations",
    "x_opencti_platform": "linux",
}


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
        return client


@pytest.fixture
def opencti_stix2(local_api_client):
    instance = OpenCTIStix2(local_api_client)
    instance.mapping_cache_permanent["vocabularies_definition_fields"] = []
    return instance


def _system_add_response():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"systemAdd": {"id": "identity--fake-id"}}
    }
    return mock_response


def _sent_input(opencti_stix2, call):
    with patch.object(
        opencti_stix2.opencti.session, "post", return_value=_system_add_response()
    ) as mocked_post:
        call(Identity(opencti_stix2.opencti))
    sent = mocked_post.call_args.kwargs["json"]
    assert "systemAdd" in sent["query"]
    return sent["variables"]["input"]


def test_system_asset_fields_list():
    assert set(SYSTEM_ASSET_FIELDS) == set(ASSET_VALUES)


def test_create_system_forwards_asset_fields(opencti_stix2: OpenCTIStix2):
    sent_input = _sent_input(
        opencti_stix2,
        lambda identity: identity.create(type="System", name="srv-01", **ASSET_VALUES),
    )
    for field, value in ASSET_VALUES.items():
        assert sent_input[field] == value


def test_import_system_reads_asset_fields_from_extension(
    opencti_stix2: OpenCTIStix2,
):
    stix_object = {
        "type": "identity",
        "id": "identity--8af97482-121d-53f7-a533-9c48f06b5a38",
        "name": "srv-01",
        "identity_class": "system",
        "extensions": {
            OCTI_EXTENSION_ID: {
                field.replace("x_opencti_", "", 1): value
                for field, value in ASSET_VALUES.items()
            }
        },
    }
    sent_input = _sent_input(
        opencti_stix2,
        lambda identity: identity.import_from_stix2(stixObject=stix_object, extras={}),
    )
    for field, value in ASSET_VALUES.items():
        assert sent_input[field] == value


def test_import_system_reads_top_level_asset_fields(opencti_stix2: OpenCTIStix2):
    stix_object = {
        "type": "identity",
        "id": "identity--8af97482-121d-53f7-a533-9c48f06b5a38",
        "name": "srv-01",
        "identity_class": "system",
        **ASSET_VALUES,
    }
    sent_input = _sent_input(
        opencti_stix2,
        lambda identity: identity.import_from_stix2(stixObject=stix_object, extras={}),
    )
    for field, value in ASSET_VALUES.items():
        assert sent_input[field] == value


def test_import_system_without_asset_fields_sends_none(
    opencti_stix2: OpenCTIStix2,
):
    stix_object = {
        "type": "identity",
        "id": "identity--8af97482-121d-53f7-a533-9c48f06b5a38",
        "name": "srv-01",
        "identity_class": "system",
    }
    sent_input = _sent_input(
        opencti_stix2,
        lambda identity: identity.import_from_stix2(stixObject=stix_object, extras={}),
    )
    for field in SYSTEM_ASSET_FIELDS:
        assert sent_input[field] is None
