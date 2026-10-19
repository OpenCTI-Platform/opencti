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


def test_guess_past_date_cutoff_is_compared_in_utc():
    # NOW is 2026-10-12 08:00 UTC: the cutoff is 2026-10-11 08:00 UTC
    paris = datetime.timezone(datetime.timedelta(hours=2))
    for now in (NOW, NOW.replace(tzinfo=datetime.timezone.utc).astimezone(paris)):
        assert (
            OpenCTIStix2Utils.guess_past_date("seen 2026-10-11T09:30:00+02:00", now=now)
            == "2026-10-11T07:30:00Z"
        )
        assert (
            OpenCTIStix2Utils.guess_past_date("seen 2026-10-11T11:00:00+02:00", now=now)
            is None
        )
        assert (
            OpenCTIStix2Utils.guess_past_date("seen 2026-10-11T07:59:00", now=now)
            == "2026-10-11T07:59:00Z"
        )


def test_guess_past_date_defaults_to_the_current_time():
    assert (
        OpenCTIStix2Utils.guess_past_date("seen 2000-01-01") == "2000-01-01T00:00:00Z"
    )
    assert OpenCTIStix2Utils.guess_past_date("scheduled for 2999-01-01") is None


def test_guess_past_date_without_date_or_text():
    assert OpenCTIStix2Utils.guess_past_date("MITRE ATT&CK", now=NOW) is None
    assert OpenCTIStix2Utils.guess_past_date("", now=NOW) is None
    assert OpenCTIStix2Utils.guess_past_date(None, now=NOW) is None


def test_epoch_is_timezone_independent():
    assert EPOCH == datetime.datetime(1970, 1, 1)
    assert EPOCH.tzinfo is None
