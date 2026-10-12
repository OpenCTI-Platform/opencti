import datetime

from pycti.utils.opencti_stix2_utils import EPOCH, OpenCTIStix2Utils

NOW = datetime.datetime(2026, 10, 12, 8, 0, 0)


def test_guess_past_date_returns_the_first_past_date():
    text = "Microsoft Deep Dive Solorigate, retrieved January 20, 2021 and updated 2026-07-31"
    assert OpenCTIStix2Utils.guess_past_date(text, now=NOW) == "2021-01-20T00:00:00Z"


def test_guess_past_date_ignores_future_and_today():
    assert OpenCTIStix2Utils.guess_past_date("published 2026-10-12", now=NOW) is None
    assert (
        OpenCTIStix2Utils.guess_past_date("scheduled for 2031-01-01", now=NOW) is None
    )


def test_guess_past_date_handles_dates_around_the_epoch():
    # datetime.timestamp() raises OSError on Windows for these; the comparison must not use it
    assert (
        OpenCTIStix2Utils.guess_past_date("first seen 1970-01-01", now=NOW)
        == "1970-01-01T00:00:00Z"
    )
    assert (
        OpenCTIStix2Utils.guess_past_date("archive of 1969-12-31", now=NOW)
        == "1969-12-31T00:00:00Z"
    )


def test_guess_past_date_normalises_time_zones():
    assert (
        OpenCTIStix2Utils.guess_past_date("seen 2024-03-05T10:00:00+02:00", now=NOW)
        == "2024-03-05T08:00:00Z"
    )


def test_guess_past_date_without_date_or_text():
    assert OpenCTIStix2Utils.guess_past_date("MITRE ATT&CK", now=NOW) is None
    assert OpenCTIStix2Utils.guess_past_date("", now=NOW) is None
    assert OpenCTIStix2Utils.guess_past_date(None, now=NOW) is None


def test_epoch_is_timezone_independent():
    assert EPOCH == datetime.datetime(1970, 1, 1)
    assert EPOCH.tzinfo is None
