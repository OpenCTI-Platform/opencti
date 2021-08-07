import datetime
import time
from typing import List, Dict

from dateutil.parser import parse

from pycti import OpenCTIApiConnector, OpenCTIApiClient


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


def get_connector_works(
    api_client: OpenCTIApiClient, connector_id: str, work_id: str = ""
) -> List[Dict]:
    query = """
    query ConnectorWorksQuery(
          $count: Int
          $orderBy: WorksOrdering
          $orderMode: OrderingMode
          $filters: [WorksFiltering]
        ) {
          works(
            first: $count
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
          ) {
            edges {
              node {
                id
                name
                user {
                  name
                }
                timestamp
                status
                event_source_id
                received_time
                processed_time
                completed_time
                tracking {
                  import_expected_number
                  import_processed_number
                }
                messages {
                  timestamp
                  message
                  sequence
                  source
                }
                errors {
                  timestamp
                  message
                  sequence
                  source
                }
              }
            }
          }
        }
        """
    result = api_client.query(
        query,
        {
            "count": 50,
            "filters": [
                {"key": "connector_id", "values": [connector_id]},
                # {"key": "status", "values": ["wait", "progress", "complete"]},
                # {"key": "event_source_id", "values": [event_source_id]},
                # {"key": "timestamp", "values": [start_time]}
            ],
        },
    )
    result = result["data"]["works"]["edges"]
    return_value = []
    for node in result:
        node = node["node"]
        if work_id != "":
            if node["id"] == work_id:
                return_value.append(node)
        else:
            return_value.append(node)
    return sorted(return_value, key=lambda i: i["timestamp"])


def get_new_work_id(api_client: OpenCTIApiClient, connector_id: str) -> str:
    new_works = get_connector_works(api_client, connector_id)
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


def wait_connector_finish(
    api_client: OpenCTIApiClient, connector_id: str, work_id: str
):
    status = ""
    cnt = 0
    while status != "complete":
        states = get_connector_works(api_client, connector_id, work_id)
        if len(states) > 0:
            assert (
                len(states) == 1
            ), f"Received more than 1 state for work_id. Got: {len(states)}"
            assert (
                states[0]["errors"] == []
            ), f"Unexpected connector error {states[0]['errors']}"
            status = states[0]["status"]

        time.sleep(1)
        # wait 120 seconds for connector to finish
        cnt += 1
        if cnt > 160:
            assert cnt != cnt, "Connector wasn't able to finish. Elapsed time 160s"


def delete_work(api_client: OpenCTIApiClient, work_id: str):
    query = """
    mutation ConnectorWorksMutation($workId: ID!) {
        workEdit(id: $workId) {
            delete
        }
    }"""
    api_client.query(
        query,
        {"workId": work_id},
    )
