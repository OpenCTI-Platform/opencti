import datetime

import pytest

from pycti.utils.opencti_stix2 import OpenCTIStix2


@pytest.fixture
def opencti_stix2(api_client):
    return OpenCTIStix2(api_client)


def test_unknown_type(opencti_stix2: OpenCTIStix2, caplog):
    opencti_stix2.unknown_type({"type": "foo"})
    for record in caplog.records:
        assert record.levelname == "ERROR"
    assert 'Unknown object type "foo", doing nothing...' in caplog.text


def test_convert_markdown(opencti_stix2: OpenCTIStix2):
    result = opencti_stix2.convert_markdown(
        " my <code> is very </special> </code> to me"
    )
    assert " my ` is very </special> ` to me" == result


def test_convert_markdown_typo(opencti_stix2: OpenCTIStix2):
    result = opencti_stix2.convert_markdown(
        " my <code is very </special> </code> to me"
    )
    assert " my <code is very </special> ` to me" == result


def test_format_date_with_tz(opencti_stix2: OpenCTIStix2):
    # Test all 4 format_date cases with timestamp + timezone
    my_datetime = datetime.datetime(
        2021, 3, 5, 13, 31, 19, 42621, tzinfo=datetime.timezone.utc
    )
    my_datetime_str = my_datetime.isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )
    assert my_datetime_str == opencti_stix2.format_date(my_datetime)
    my_date = my_datetime.date()
    my_date_str = "2021-03-05T00:00:00.000Z"
    assert my_date_str == opencti_stix2.format_date(my_date)
    assert my_datetime_str == opencti_stix2.format_date(my_datetime_str)
    assert (
        str(
            datetime.datetime.now(tz=datetime.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "")
        )
        in opencti_stix2.format_date()
    )
    with pytest.raises(ValueError):
        opencti_stix2.format_date("No time")

    # Test all 4 format_date cases with timestamp w/o timezone
    my_datetime = datetime.datetime(2021, 3, 5, 13, 31, 19, 42621)
    my_datetime_str = (
        my_datetime.replace(tzinfo=datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    assert my_datetime_str == opencti_stix2.format_date(my_datetime)
    my_date = my_datetime.date()
    my_date_str = "2021-03-05T00:00:00.000Z"
    assert my_date_str == opencti_stix2.format_date(my_date)
    assert my_datetime_str == opencti_stix2.format_date(my_datetime_str)
    assert (
        str(
            datetime.datetime.now(tz=datetime.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "")
        )
        in opencti_stix2.format_date()
    )
    with pytest.raises(ValueError):
        opencti_stix2.format_date("No time")


def test_filter_objects(opencti_stix2: OpenCTIStix2):
    objects = [{"id": "123"}, {"id": "124"}, {"id": "125"}, {"id": "126"}]
    result = opencti_stix2.filter_objects(["123", "124", "126"], objects)
    assert len(result) == 1
    assert "126" not in result


def test_pick_aliases(opencti_stix2: OpenCTIStix2) -> None:
    stix_object = {}
    assert opencti_stix2.pick_aliases(stix_object) is None
    stix_object["aliases"] = "alias"
    assert opencti_stix2.pick_aliases(stix_object) == "alias"
    stix_object["x_amitt_aliases"] = "amitt_alias"
    assert opencti_stix2.pick_aliases(stix_object) == "amitt_alias"
    stix_object["x_mitre_aliases"] = "mitre_alias"
    assert opencti_stix2.pick_aliases(stix_object) == "mitre_alias"
    stix_object["x_opencti_aliases"] = "opencti_alias"
    assert opencti_stix2.pick_aliases(stix_object) == "opencti_alias"


def test_import_bundle_from_file(opencti_stix2: OpenCTIStix2, caplog) -> None:
    opencti_stix2.import_bundle_from_file("foo.txt")
    for record in caplog.records:
        assert record.levelname == "ERROR"
    assert "The bundle file does not exists" in caplog.text
