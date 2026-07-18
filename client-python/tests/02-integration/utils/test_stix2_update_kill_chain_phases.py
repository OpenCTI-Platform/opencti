import uuid


def test_stix2_update_add_kill_chain_phases_supports_bulk_relation_edits(api_client):
    suffix = uuid.uuid4().hex
    attack_pattern = api_client.attack_pattern.create(
        name=f"Bulk kill chain attack pattern {suffix}",
        description="Bulk kill chain regression object",
    )
    intrusion_set = api_client.intrusion_set.create(
        name=f"Bulk kill chain intrusion set {suffix}",
        description="Bulk kill chain regression relationship source",
    )
    tool = api_client.tool.create(
        name=f"Bulk kill chain tool {suffix}",
        description="Bulk kill chain regression target",
    )
    relationship = api_client.stix_core_relationship.create(
        fromId=intrusion_set["id"],
        toId=tool["id"],
        relationship_type="uses",
    )
    kill_chain_phase_ids = []

    try:
        api_client.stix2.stix2_update.add_kill_chain_phases(
            "attack-pattern",
            attack_pattern["id"],
            [
                {
                    "value": {
                        "kill_chain_name": f"bulk-domain-{suffix}",
                        "phase_name": "phase-one",
                    }
                },
                {
                    "value": {
                        "kill_chain_name": f"bulk-domain-{suffix}",
                        "phase_name": "phase-two",
                    }
                },
            ],
        )
        api_client.stix2.stix2_update.add_kill_chain_phases(
            "relationship",
            relationship["id"],
            [
                {
                    "value": {
                        "kill_chain_name": f"bulk-relationship-{suffix}",
                        "phase_name": "phase-one",
                    }
                },
                {
                    "value": {
                        "kill_chain_name": f"bulk-relationship-{suffix}",
                        "phase_name": "phase-two",
                    }
                },
            ],
        )

        custom_attributes = """
            id
            killChainPhases {
                id
                kill_chain_name
                phase_name
            }
        """
        updated_attack_pattern = api_client.attack_pattern.read(
            id=attack_pattern["id"], customAttributes=custom_attributes
        )
        updated_relationship = api_client.stix_core_relationship.read(
            id=relationship["id"], customAttributes=custom_attributes
        )
        kill_chain_phase_ids.extend(updated_attack_pattern["killChainPhasesIds"])
        kill_chain_phase_ids.extend(updated_relationship["killChainPhasesIds"])

        assert {
            kill_chain_phase["phase_name"]
            for kill_chain_phase in updated_attack_pattern["killChainPhases"]
        } == {"phase-one", "phase-two"}
        assert {
            kill_chain_phase["phase_name"]
            for kill_chain_phase in updated_relationship["killChainPhases"]
        } == {"phase-one", "phase-two"}

        api_client.stix2.stix2_update.remove_kill_chain_phases(
            "attack-pattern",
            attack_pattern["id"],
            [
                {"id": kill_chain_phase_id}
                for kill_chain_phase_id in updated_attack_pattern["killChainPhasesIds"]
            ],
        )
        api_client.stix2.stix2_update.remove_kill_chain_phases(
            "relationship",
            relationship["id"],
            [
                {"id": kill_chain_phase_id}
                for kill_chain_phase_id in updated_relationship["killChainPhasesIds"]
            ],
        )

        updated_attack_pattern = api_client.attack_pattern.read(
            id=attack_pattern["id"], customAttributes=custom_attributes
        )
        updated_relationship = api_client.stix_core_relationship.read(
            id=relationship["id"], customAttributes=custom_attributes
        )

        assert updated_attack_pattern["killChainPhases"] == []
        assert updated_relationship["killChainPhases"] == []
    finally:
        api_client.stix_core_relationship.delete(id=relationship["id"])
        api_client.stix_domain_object.delete(id=attack_pattern["id"])
        api_client.stix_domain_object.delete(id=intrusion_set["id"])
        api_client.stix_domain_object.delete(id=tool["id"])
        for kill_chain_phase_id in kill_chain_phase_ids:
            api_client.kill_chain_phase.delete(id=kill_chain_phase_id)
