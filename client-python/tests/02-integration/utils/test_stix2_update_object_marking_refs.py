import uuid

from pycti.api.opencti_api_client import API_FEATURE_BULK_REF_RELATION_VALIDATION


def test_stix2_update_add_object_marking_refs_supports_bulk_relation_edits(api_client):
    assert api_client.supports_api_feature(API_FEATURE_BULK_REF_RELATION_VALIDATION)

    suffix = uuid.uuid4().hex
    intrusion_set = api_client.intrusion_set.create(
        name=f"Bulk marking intrusion set {suffix}",
        description="Bulk marking regression source",
    )
    tool = api_client.tool.create(
        name=f"Bulk marking tool {suffix}",
        description="Bulk marking regression target",
    )
    relationship = api_client.stix_core_relationship.create(
        fromId=intrusion_set["id"],
        toId=tool["id"],
        relationship_type="uses",
    )
    marking_ids = [
        marking["id"] for marking in api_client.marking_definition.list(first=2)
    ]

    try:
        api_client.stix2.stix2_update.add_object_marking_refs(
            "intrusion-set",
            intrusion_set["id"],
            [{"value": marking_id} for marking_id in marking_ids],
        )
        api_client.stix2.stix2_update.add_object_marking_refs(
            "relationship",
            relationship["id"],
            [{"value": marking_id} for marking_id in marking_ids],
        )

        updated_intrusion_set = api_client.intrusion_set.read(id=intrusion_set["id"])
        updated_relationship = api_client.stix_core_relationship.read(
            id=relationship["id"]
        )

        assert set(updated_intrusion_set["objectMarkingIds"]) == set(marking_ids)
        assert set(updated_relationship["objectMarkingIds"]) == set(marking_ids)
    finally:
        api_client.stix_core_relationship.delete(id=relationship["id"])
        api_client.stix_domain_object.delete(id=intrusion_set["id"])
        api_client.stix_domain_object.delete(id=tool["id"])
