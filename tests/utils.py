import datetime
import time
from typing import Dict, List

from dateutil.parser import parse

from pycti import OpenCTIApiClient, OpenCTIApiConnector, OpenCTIApiWork


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


def read_marking(api_client: OpenCTIApiClient, tlp_id: int):
    return api_client.marking_definition.read(id=tlp_id)


def get_connector_id(connector_name: str, api_connector: OpenCTIApiConnector) -> str:
    connector_list = api_connector.list()
    connector_id = ""
    for connector in connector_list:
        if connector["name"] == connector_name:
            connector_id = connector["id"]

    return connector_id


def get_new_work_id(api_client: OpenCTIApiClient, connector_id: str) -> str:
    worker = OpenCTIApiWork(api_client)
    new_works = worker.get_connector_works(connector_id)
    cnt = 0
    while len(new_works) == 0:
        time.sleep(1)
        # wait 20 seconds for new work to be registered
        cnt += 1
        if cnt > 20:
            assert (
                cnt != cnt
            ), "Connector hasn't registered new work yet. Elapsed time 20s"

        assert (
            len(new_works) == 1
        ), f"Too many jobs were created. Expected 1, Actual: {len(new_works)}"
    return new_works[0]["id"]


def compare_values(original_data: Dict, retrieved_data: Dict, exception_keys: List):
    for key, value in original_data.items():
        # Attributes which aren't present in the final Stix objects
        if key in exception_keys:
            continue

        assert key in retrieved_data, f"Key {key} is not in retrieved_data"

        compare_data = retrieved_data.get(key, None)
        if isinstance(value, str):
            assert (
                value == compare_data
            ), f"Key '{key}': '{value}' does't match value '{retrieved_data[key]}' ({retrieved_data}"
        elif key == "objects" and isinstance(value, list):
            assert isinstance(compare_data, list), f"Key '{key}': is not a list"
            original_ids = set()
            for elem in value:
                if isinstance(elem, dict):
                    original_ids.add(elem.get("id", None))
                elif isinstance(elem, str):
                    original_ids.add(elem)

            retrieved_ids = set()
            for elem in compare_data:
                if isinstance(elem, dict):
                    retrieved_ids.add(elem.get("id", None))
                elif isinstance(elem, str):
                    original_ids.add(elem)

            assert (
                original_ids == retrieved_ids
            ), f"Key '{key}': '{value}' does't match value '{compare_data}'"
        elif isinstance(value, dict):
            assert len(value) == len(
                compare_data
            ), f"Dict '{value}' does not have the same length as '{compare_data}'"
            assert (
                value == compare_data
            ), f"Dict '{value}' does not have the same content as'{compare_data}'"
