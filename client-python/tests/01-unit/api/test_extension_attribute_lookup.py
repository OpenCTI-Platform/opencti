import pytest

from pycti.api.opencti_api_client import OpenCTIApiClient
from pycti.connector.opencti_connector_helper import OpenCTIConnectorHelper

PRIMARY_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"
SECONDARY_EXTENSION_ID = "extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82"


@pytest.mark.parametrize(
    "lookup",
    [
        OpenCTIApiClient.get_attribute_in_extension,
        OpenCTIConnectorHelper.get_attribute_in_extension,
    ],
)
def test_get_attribute_in_extension_preserves_precedence_and_fallback(lookup):
    stix_object = {
        "extensions": {
            PRIMARY_EXTENSION_ID: {"score": 42},
            SECONDARY_EXTENSION_ID: {"score": 43, "secondary_only": 7},
        },
        "score": 44,
        "name": "fallback",
        "type": "indicator",
    }

    assert lookup("score", stix_object) == 42
    assert lookup("secondary_only", stix_object) == 7
    assert lookup("name", stix_object) == "fallback"
    assert lookup("type", stix_object) is None
    assert lookup("missing", stix_object) is None
