import pytest
from stix2 import Bundle

from tests.cases.entities import EntityTestCases
from tests.utils import case_id, cases_of


@pytest.fixture(params=cases_of(EntityTestCases), ids=case_id)
def entity_class(request, api_client):
    entity = request.param(api_client)
    entity.setup()
    yield entity
    entity.teardown()


def test_entity_create(entity_class, api_stix, opencti_splitter):
    class_data = entity_class.data()
    stix_class = entity_class.stix_class()
    if stix_class is None:
        return

    stix_object = stix_class(**class_data)
    bundle = Bundle(objects=[stix_object]).serialize()
    split_bundle = opencti_splitter.split_bundle(bundle, True, None)[0]
    bundles_sent, _ = api_stix.import_bundle_from_json(split_bundle, False, None, None)

    assert len(bundles_sent) == 1
    assert bundles_sent[0]["id"] == stix_object["id"]
    assert bundles_sent[0]["type"] == stix_object["type"]

    entity_class.base_class().delete(id=stix_object["id"])
