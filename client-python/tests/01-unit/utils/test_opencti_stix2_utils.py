from pycti.utils.opencti_stix2_utils import OpenCTIStix2Utils


def test_compute_object_refs_number_counts_reference_fields_without_mutation():
    entity = {
        "id": "report--benchmark",
        "object_refs": ["indicator--1", "indicator--2"],
        "created_by_ref": None,
        "external_references": [{"source_name": "source"}],
        "kill_chain_phases": [{"phase_name": "phase"}],
        "x_opencti_granted_refs": None,
        "name": "benchmark",
    }

    assert OpenCTIStix2Utils.compute_object_refs_number(entity) == 5
    assert entity["created_by_ref"] is None
    assert entity["x_opencti_granted_refs"] is None
