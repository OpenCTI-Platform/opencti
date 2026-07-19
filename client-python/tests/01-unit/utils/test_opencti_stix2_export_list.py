from pycti.utils.opencti_stix2 import OpenCTIStix2


def _helper(entities):
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    helper.export_entities_list = lambda **kwargs: entities
    helper.generate_export = lambda entity: entity
    helper.prepare_export = lambda entity, mode, access_filter: [entity]
    return helper


def test_export_list_deduplicates_objects_and_rewrites_bundle_once():
    entities = [
        {"id": "indicator--1", "type": "indicator"},
        {"id": "indicator--2", "type": "indicator"},
        {"id": "indicator--1", "type": "indicator"},
    ]
    helper = _helper(entities)
    rewrite_sizes = []
    helper._rewrite_embedded_image_uris_in_bundle_for_export = (
        lambda bundle: rewrite_sizes.append(len(bundle["objects"]))
    )

    bundle = helper.export_list(entity_type="Indicator")

    assert [item["id"] for item in bundle["objects"]] == [
        "indicator--1",
        "indicator--2",
    ]
    assert rewrite_sizes == [2]
