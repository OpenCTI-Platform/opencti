import uuid


def test_stix2_update_add_object_refs_supports_bulk_object_relations(api_client):
    suffix = uuid.uuid4().hex
    report = api_client.report.create(
        name=f"Bulk object ref report {suffix}",
        description="Bulk object ref regression",
        published="2026-07-17T00:00:00.000Z",
        report_types=["threat-report"],
    )
    first_target = api_client.attack_pattern.create(
        name=f"Bulk object ref target one {suffix}",
        description="Bulk object ref regression target",
    )
    second_target = api_client.attack_pattern.create(
        name=f"Bulk object ref target two {suffix}",
        description="Bulk object ref regression target",
    )

    try:
        api_client.stix2.stix2_update.add_object_refs(
            "report",
            report["id"],
            [{"value": first_target["id"]}, {"value": second_target["id"]}],
        )

        updated_report = api_client.report.read(id=report["id"])
        assert set(updated_report["objectsIds"]) == {
            first_target["id"],
            second_target["id"],
        }
    finally:
        api_client.stix_domain_object.delete(id=report["id"])
        api_client.stix_domain_object.delete(id=first_target["id"])
        api_client.stix_domain_object.delete(id=second_target["id"])
