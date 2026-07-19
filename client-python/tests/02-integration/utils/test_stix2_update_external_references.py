import uuid


def test_stix2_update_add_external_references_supports_bulk_relation_edits(api_client):
    suffix = uuid.uuid4().hex
    intrusion_set = api_client.intrusion_set.create(
        name=f"Bulk external ref intrusion set {suffix}",
        description="Bulk external ref regression source",
    )
    tool = api_client.tool.create(
        name=f"Bulk external ref tool {suffix}",
        description="Bulk external ref regression target",
    )
    relationship = api_client.stix_core_relationship.create(
        fromId=intrusion_set["id"],
        toId=tool["id"],
        relationship_type="uses",
    )
    external_reference_ids = []

    try:
        api_client.stix2.stix2_update.add_external_references(
            "intrusion-set",
            intrusion_set["id"],
            [
                {
                    "value": {
                        "source_name": f"bulk-domain-one-{suffix}",
                        "url": f"https://example.test/domain-one/{suffix}",
                    }
                },
                {
                    "value": {
                        "source_name": f"bulk-domain-two-{suffix}",
                        "url": f"https://example.test/domain-two/{suffix}",
                    }
                },
            ],
        )
        api_client.stix2.stix2_update.add_external_references(
            "relationship",
            relationship["id"],
            [
                {
                    "value": {
                        "source_name": f"bulk-relationship-one-{suffix}",
                        "url": f"https://example.test/relationship-one/{suffix}",
                    }
                },
                {
                    "value": {
                        "source_name": f"bulk-relationship-two-{suffix}",
                        "url": f"https://example.test/relationship-two/{suffix}",
                    }
                },
            ],
        )

        updated_intrusion_set = api_client.intrusion_set.read(id=intrusion_set["id"])
        updated_relationship = api_client.stix_core_relationship.read(
            id=relationship["id"]
        )
        external_reference_ids.extend(updated_intrusion_set["externalReferencesIds"])
        external_reference_ids.extend(updated_relationship["externalReferencesIds"])

        assert {
            external_reference["source_name"]
            for external_reference in updated_intrusion_set["externalReferences"]
        } == {
            f"bulk-domain-one-{suffix}",
            f"bulk-domain-two-{suffix}",
        }
        assert {
            external_reference["source_name"]
            for external_reference in updated_relationship["externalReferences"]
        } == {
            f"bulk-relationship-one-{suffix}",
            f"bulk-relationship-two-{suffix}",
        }

        api_client.stix2.stix2_update.remove_external_references(
            "intrusion-set",
            intrusion_set["id"],
            [
                {"id": external_reference_id}
                for external_reference_id in updated_intrusion_set[
                    "externalReferencesIds"
                ]
            ],
        )
        api_client.stix2.stix2_update.remove_external_references(
            "relationship",
            relationship["id"],
            [
                {"id": external_reference_id}
                for external_reference_id in updated_relationship[
                    "externalReferencesIds"
                ]
            ],
        )

        updated_intrusion_set = api_client.intrusion_set.read(id=intrusion_set["id"])
        updated_relationship = api_client.stix_core_relationship.read(
            id=relationship["id"]
        )

        assert updated_intrusion_set["externalReferences"] == []
        assert updated_relationship["externalReferences"] == []
    finally:
        api_client.stix_core_relationship.delete(id=relationship["id"])
        api_client.stix_domain_object.delete(id=intrusion_set["id"])
        api_client.stix_domain_object.delete(id=tool["id"])
        for external_reference_id in external_reference_ids:
            api_client.external_reference.delete(external_reference_id)
