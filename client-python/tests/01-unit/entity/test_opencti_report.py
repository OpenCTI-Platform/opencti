from unittest.mock import MagicMock

from pycti.entities.opencti_report import Report


def opencti_mock(*responses):
    opencti = MagicMock()
    opencti.get_attribute_in_extension.return_value = None
    opencti.process_multiple_fields.side_effect = lambda value: value
    opencti.stix2.convert_markdown.side_effect = lambda value: value
    opencti.query.side_effect = responses
    return opencti


def test_update_without_published_reuses_existing_value():
    opencti = opencti_mock(
        {"data": {"report": {"published": "1970-01-01T00:00:00.000Z"}}},
        {"data": {"reportAdd": {"id": "report--internal"}}},
    )

    result = Report(opencti).import_from_stix2(
        stixObject={"id": "report--standard", "name": "Epoch report"},
        update=True,
    )

    assert result == {"id": "report--internal"}
    assert opencti.query.call_args_list[1].args[1]["input"]["published"] == (
        "1970-01-01T00:00:00.000Z"
    )


def test_update_with_published_does_not_read_existing_report():
    opencti = opencti_mock(
        {"data": {"reportAdd": {"id": "report--internal"}}},
    )

    result = Report(opencti).import_from_stix2(
        stixObject={
            "id": "report--standard",
            "name": "Published report",
            "published": "2026-08-28T00:00:00.000Z",
        },
        update=True,
    )

    assert result == {"id": "report--internal"}
    assert opencti.query.call_count == 1
    assert opencti.query.call_args.args[1]["input"]["published"] == (
        "2026-08-28T00:00:00.000Z"
    )


def test_update_without_published_still_fails_when_report_does_not_exist():
    opencti = opencti_mock({"data": {"report": None}})

    result = Report(opencti).import_from_stix2(
        stixObject={"id": "report--missing", "name": "Missing report"},
        update=True,
    )

    assert result is None
    assert opencti.query.call_count == 1
