# coding: utf-8
"""A Security Coverage Result shared with organizations must keep them on import (#20501)."""

from unittest.mock import MagicMock, patch

import pytest

from pycti import OpenCTIApiClient
from pycti.entities.opencti_security_coverage_result import SecurityCoverageResult

OCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
ORGANIZATION_ID = "identity--f29f12ba-3980-5642-9b3e-d11e9b296aed"


@pytest.fixture
def api_client():
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


def import_and_get_sent_input(api_client, stix_object):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"securityCoverageResultAdd": {"id": "security-coverage-result--fake"}}
    }
    with patch.object(
        api_client.session, "post", return_value=mock_response
    ) as mocked_post:
        SecurityCoverageResult(api_client).import_from_stix2(stixObject=stix_object)
    return mocked_post.call_args.kwargs["json"]["variables"]["input"]


def test_import_security_coverage_result_sends_its_organizations(api_client):
    # The playbook sharing component and the sync put the organizations in the
    # OpenCTI extension of the STIX object
    stix_object = {
        "type": "security-coverage-result",
        "id": "security-coverage-result--6f7a8b9c-1d2e-4f3a-8b4c-5d6e7f8a9b10",
        "name": "Result",
        "result_of_ref": "security-coverage--7a8b9c1d-2e3f-4a4b-9c5d-6e7f8a9b1c20",
        "extensions": {OCTI_EXTENSION: {"granted_refs": [ORGANIZATION_ID]}},
    }

    sent_input = import_and_get_sent_input(api_client, stix_object)

    assert sent_input["objectOrganization"] == [ORGANIZATION_ID]
