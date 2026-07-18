import uuid


def test_stix2_update_add_labels_supports_prefetch_and_bulk_relation_edits(api_client):
    suffix = uuid.uuid4().hex
    intrusion_set = api_client.intrusion_set.create(
        name=f"Bulk label intrusion set {suffix}",
        description="Bulk label regression source",
    )
    tool = api_client.tool.create(
        name=f"Bulk label tool {suffix}",
        description="Bulk label regression target",
    )
    relationship = api_client.stix_core_relationship.create(
        fromId=intrusion_set["id"],
        toId=tool["id"],
        relationship_type="uses",
    )
    label_ids = []

    try:
        api_client.stix2.stix2_update.add_labels(
            "intrusion-set",
            intrusion_set["id"],
            [
                {"value": f"bulk-domain-one-{suffix}"},
                {"value": f"bulk-domain-two-{suffix}"},
            ],
        )
        api_client.stix2.stix2_update.add_labels(
            "relationship",
            relationship["id"],
            [
                {"value": f"bulk-relationship-one-{suffix}"},
                {"value": f"bulk-relationship-two-{suffix}"},
            ],
        )

        updated_intrusion_set = api_client.intrusion_set.read(id=intrusion_set["id"])
        updated_relationship = api_client.stix_core_relationship.read(
            id=relationship["id"]
        )
        label_ids.extend(updated_intrusion_set["objectLabelIds"])
        label_ids.extend(updated_relationship["objectLabelIds"])

        assert {label["value"] for label in updated_intrusion_set["objectLabel"]} == {
            f"bulk-domain-one-{suffix}",
            f"bulk-domain-two-{suffix}",
        }
        assert {label["value"] for label in updated_relationship["objectLabel"]} == {
            f"bulk-relationship-one-{suffix}",
            f"bulk-relationship-two-{suffix}",
        }
    finally:
        api_client.stix_core_relationship.delete(id=relationship["id"])
        api_client.stix_domain_object.delete(id=intrusion_set["id"])
        api_client.stix_domain_object.delete(id=tool["id"])
        for label_id in label_ids:
            api_client.label.delete(id=label_id)
