import datetime

from dateutil.parser import parse


def get_incident_start_date():
    return (
        parse("2019-12-01")
        .replace(tzinfo=datetime.timezone.utc)
        .isoformat(sep="T", timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def get_incident_end_date():
    return (
        parse("2021-12-01")
        .replace(tzinfo=datetime.timezone.utc)
        .isoformat(sep="T", timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def read_marking(api_client, tlp_id: int):
    return api_client.marking_definition.read(id=tlp_id)
