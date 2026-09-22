# coding: utf-8
"""Regression tests for https://github.com/OpenCTI-Platform/opencti/issues/17512.

When a STIX object omits ``created_by_ref``, pycti must not turn that absence
into an explicit ``createdBy: null`` in the GraphQL mutation input: the
platform's confidence-based upsert logic treats an explicitly-provided
``null`` as "the connector wants to clear the author", which is not the same
as "the connector did not provide an author at all".
"""

from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient, OpenCTIStix2
from pycti.entities.opencti_vulnerability import Vulnerability
from pycti.utils.opencti_stix2_utils import NOT_PROVIDED


@pytest.fixture
def local_api_client():
    """A real OpenCTIApiClient instance, without hitting the network.

    Named ``local_api_client`` (rather than ``api_client``) to avoid shadowing
    the session-scoped, network-backed ``api_client`` fixture defined in
    ``tests/conftest.py``.
    """
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
    # Pre-seed the vocabulary cache so extract_embedded_relationships() does
    # not attempt a network call to fetch vocabulary categories.
    instance.mapping_cache_permanent["vocabularies_definition_fields"] = []
    return instance


def stix_vulnerability_without_created_by_ref():
    return {
        "type": "vulnerability",
        "id": "vulnerability--3ba4b52a-3c26-4dab-8791-e73a2c7bbc78",
        "name": "CVE-2024-99999",
        # Deliberately no "created_by_ref" (and no extension variant either).
    }


def test_extract_embedded_relationships_marks_created_by_as_not_provided_when_absent(
    opencti_stix2: OpenCTIStix2,
):
    """The "created_by" key is always present in the returned dict, but its
    value is the NOT_PROVIDED sentinel (not None) when the ref is absent, so
    downstream code can distinguish "absent" from "explicitly cleared"."""
    stix_object = stix_vulnerability_without_created_by_ref()

    result = opencti_stix2.extract_embedded_relationships(stix_object)

    assert "created_by" in result
    assert result["created_by"] is NOT_PROVIDED


def test_import_vulnerability_without_created_by_ref_should_not_send_null_createdby(
    opencti_stix2: OpenCTIStix2,
):
    """Regression test for https://github.com/OpenCTI-Platform/opencti/issues/17512.

    Importing a Vulnerability STIX object that omits created_by_ref must not
    result in an explicit "createdBy": None in the mutation input sent to the
    platform: the key must be omitted entirely so the platform can
    distinguish "no author supplied" from "author explicitly cleared".
    """
    stix_object = stix_vulnerability_without_created_by_ref()
    embedded_relationships = opencti_stix2.extract_embedded_relationships(stix_object)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"vulnerabilityAdd": {"id": "vulnerability--fake-id"}}
    }

    with patch.object(
        opencti_stix2.opencti.session, "post", return_value=mock_response
    ) as mocked_post:
        vulnerability = Vulnerability(opencti_stix2.opencti)
        vulnerability.import_from_stix2(
            stixObject=stix_object,
            extras={"created_by_id": embedded_relationships["created_by"]},
        )

    sent_variables = mocked_post.call_args.kwargs["json"]["variables"]
    # The key must be entirely absent from the mutation input when the
    # source STIX object did not provide created_by_ref, so the platform can
    # distinguish "no author supplied" from "remove the author".
    assert "createdBy" not in sent_variables["input"]


def test_import_vulnerability_with_created_by_ref_still_sends_it(
    opencti_stix2: OpenCTIStix2,
):
    """Sanity check: when created_by_ref IS provided, createdBy must still be
    forwarded in the mutation input."""
    stix_object = stix_vulnerability_without_created_by_ref()
    stix_object["created_by_ref"] = "identity--fdd447a8-5588-4be7-9c66-53fe2d6d1424"
    embedded_relationships = opencti_stix2.extract_embedded_relationships(stix_object)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"vulnerabilityAdd": {"id": "vulnerability--fake-id"}}
    }

    with patch.object(
        opencti_stix2.opencti.session, "post", return_value=mock_response
    ) as mocked_post:
        vulnerability = Vulnerability(opencti_stix2.opencti)
        vulnerability.import_from_stix2(
            stixObject=stix_object,
            extras={"created_by_id": embedded_relationships["created_by"]},
        )

    sent_variables = mocked_post.call_args.kwargs["json"]["variables"]
    assert (
        sent_variables["input"]["createdBy"]
        == "identity--fdd447a8-5588-4be7-9c66-53fe2d6d1424"
    )
