import datetime

from pycti import OpenCTIApiClient
from pycti.utils.opencti_stix2 import OpenCTIStix2
import pytest


@pytest.fixture
def api_client():
    return OpenCTIApiClient(
        "https://demo.opencti.io",
        "681b01f9-542d-4c8c-be0c-b6c850b087c8",
        ssl_verify=True,
    )


def test_format_date_with_tz(api_client):
    # Test all 4 format_date cases with timestamp + timezone
    stix = OpenCTIStix2(api_client)
    my_datetime = datetime.datetime(
        2021, 3, 5, 13, 31, 19, 42621, tzinfo=datetime.timezone.utc
    )
    my_datetime_str = my_datetime.isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )
    assert my_datetime_str == stix.format_date(my_datetime)
    my_date = my_datetime.date()
    my_date_str = "2021-03-05T00:00:00.000Z"
    assert my_date_str == stix.format_date(my_date)
    assert my_datetime_str == stix.format_date(my_datetime_str)
    assert (
        str(
            datetime.datetime.now(tz=datetime.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "")
        )
        in stix.format_date()
    )
    with pytest.raises(ValueError):
        stix.format_date("No time")


def test_format_date_without_tz(api_client):
    # Test all 4 format_date cases with timestamp w/o timezone
    stix = OpenCTIStix2(api_client)
    my_datetime = datetime.datetime(2021, 3, 5, 13, 31, 19, 42621)
    my_datetime_str = (
        my_datetime.replace(tzinfo=datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    assert my_datetime_str == stix.format_date(my_datetime)
    my_date = my_datetime.date()
    my_date_str = "2021-03-05T00:00:00.000Z"
    assert my_date_str == stix.format_date(my_date)
    assert my_datetime_str == stix.format_date(my_datetime_str)
    assert (
        str(
            datetime.datetime.now(tz=datetime.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "")
        )
        in stix.format_date()
    )
    with pytest.raises(ValueError):
        stix.format_date("No time")
