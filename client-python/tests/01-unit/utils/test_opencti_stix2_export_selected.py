from pycti.utils.opencti_stix2 import OpenCTIStix2


def _helper():
    helper = OpenCTIStix2.__new__(OpenCTIStix2)
    helper.generate_export = lambda entity: entity
    helper.prepare_export = lambda entity, mode, access_filter: [entity]
    return helper


def test_export_selected_deduplicates_and_rewrites_bundle_once():
    helper = _helper()
    rewrite_sizes = []
    helper._rewrite_embedded_image_uris_in_bundle_for_export = (
        lambda bundle: rewrite_sizes.append(len(bundle["objects"]))
    )
    entities = [
        {"id": "indicator--1", "type": "indicator"},
        {"id": "indicator--2", "type": "indicator"},
        {"id": "indicator--1", "type": "indicator"},
    ]

    bundle = helper.export_selected(entities)

    assert [item["id"] for item in bundle["objects"]] == [
        "indicator--1",
        "indicator--2",
    ]
    assert rewrite_sizes == [2]
