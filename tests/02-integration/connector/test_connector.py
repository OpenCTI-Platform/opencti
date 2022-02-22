import pika.exceptions
import pytest
from pytest_cases import fixture, parametrize_with_cases

from pycti import OpenCTIConnector
from tests.cases.connectors import (
    ExternalImportConnector,
    ExternalImportConnectorTest,
    InternalEnrichmentConnector,
    InternalEnrichmentConnectorTest,
    InternalImportConnector,
    InternalImportConnectorTest,
    SimpleConnectorTest,
)
from tests.utils import get_connector_id, get_new_work_id


@fixture
@parametrize_with_cases("connector", cases=SimpleConnectorTest)
def simple_connector(connector, api_connector, api_work):
    connector = OpenCTIConnector(**connector)
    api_connector.register(connector)
    yield connector
    # Unregistering twice just to make sure
    try:
        api_connector.unregister(connector.to_input()["input"]["id"])
    except ValueError:
        # Ignore "Can't find element to delete" error
        pass


@pytest.mark.connectors
def test_register_simple_connector(simple_connector, api_connector, api_work):
    my_connector_id = simple_connector.to_input()["input"]["id"]

    test_connector = ""
    registered_connectors = api_connector.list()
    for registered_connector in registered_connectors:
        if registered_connector["id"] == my_connector_id:
            test_connector = registered_connector["id"]
            break

    assert (
        test_connector == my_connector_id
    ), f"No registered connector with id '{my_connector_id}' found"

    api_connector.unregister(test_connector)

    test_connector = ""
    registered_connectors = api_connector.list()
    for registered_connector in registered_connectors:
        if registered_connector["id"] == my_connector_id:
            test_connector = registered_connector["id"]
            break

    assert test_connector == "", "Connector is still registered"


@fixture
@parametrize_with_cases("data", cases=ExternalImportConnectorTest)
def external_import_connector_data(data, api_client, api_connector, api_work):
    connector = ExternalImportConnector(data["config"], api_client, data["data"])
    connector.run()
    yield data["data"]
    connector.stop()

    # Cleanup finished works
    works = api_work.get_connector_works(connector.helper.connector_id)
    for work in works:
        api_work.delete_work(work["id"])


@pytest.mark.connectors
def test_external_import_connector(
    external_import_connector_data, api_client, api_connector, api_work
):
    connector_name = "TestExternalImport"
    connector_id = get_connector_id(connector_name, api_connector)
    assert connector_id != "", f"{connector_name} could not be found!"

    # Wait until new work is registered
    work_id = get_new_work_id(api_client, connector_id)
    # Wait for opencti to finish processing task
    api_work.wait_for_work_to_finish(work_id)

    status_msg = api_work.get_work(work_id)
    assert (
        status_msg["tracking"]["import_expected_number"] == 2
    ), f"Unexpected number of 'import_expected_number'. Expected 2, Actual {status_msg['tracking']['import_expected_number']}"
    assert (
        status_msg["tracking"]["import_processed_number"] == 2
    ), f"Unexpected number of 'import_processed_number'. Expected 2, Actual {status_msg['tracking']['import_processed_number']}"

    for elem in external_import_connector_data:
        sdo = api_client.stix_domain_object.read(
            filters=[{"key": "name", "values": elem["name"]}]
        )
        if sdo is None:
            continue
        assert (
            sdo is not None
        ), f"Connector was unable to create {elem['type']} via the Bundle"
        assert (
            sdo["entity_type"] == elem["type"]
        ), f"A different {elem['type']} type was created"

        api_client.stix_domain_object.delete(id=sdo["id"])


@fixture
@parametrize_with_cases("data", cases=InternalEnrichmentConnectorTest)
def internal_enrichment_connector_data(data, api_client, api_connector, api_work):
    enrichment_connector = InternalEnrichmentConnector(
        data["config"], api_client, data["data"]
    )

    try:
        enrichment_connector.start()
    except pika.exceptions.AMQPConnectionError:
        enrichment_connector.stop()
        raise ValueError("Connector was not able to establish the connection to pika")

    observable = api_client.stix_cyber_observable.create(**data["data"])
    yield observable["id"]

    api_client.stix_cyber_observable.delete(id=observable["id"])
    enrichment_connector.stop()

    # Cleanup finished works
    works = api_work.get_connector_works(enrichment_connector.helper.connector_id)
    for work in works:
        api_work.delete_work(work["id"])


@pytest.mark.connectors
def test_internal_enrichment_connector(
    internal_enrichment_connector_data, api_connector, api_work, api_client
):
    # Rename variable
    observable_id = internal_enrichment_connector_data
    observable = api_client.stix_cyber_observable.read(id=observable_id)
    assert (
        observable["x_opencti_score"] == 30
    ), f"Score of {observable['value']} is not 30. Instead {observable['x_opencti_score']}"

    connector_name = "SetScore100Enrichment"
    connector_id = get_connector_id(connector_name, api_connector)
    assert connector_id != "", f"{connector_name} could not be found!"

    work_id = api_client.stix_cyber_observable.ask_for_enrichment(
        id=observable_id, connector_id=connector_id
    )

    # Wait for enrichment to finish
    api_work.wait_for_work_to_finish(work_id)

    observable = api_client.stix_cyber_observable.read(id=observable_id)
    assert (
        observable["x_opencti_score"] == 100
    ), f"Score of {observable['value']} is not 100. Instead {observable['x_opencti_score']}"


@fixture
@parametrize_with_cases("data", cases=InternalImportConnectorTest)
def internal_import_connector_data(data, api_client, api_connector, api_work):
    import_connector = InternalImportConnector(
        data["config"], api_client, data["observable"]
    )
    import_connector.start()

    report = api_client.report.create(**data["report"])

    yield report["id"], data

    api_client.stix_domain_object.delete(id=report["id"])
    import_connector.stop()

    # Cleanup finished works
    works = api_work.get_connector_works(import_connector.helper.connector_id)
    for work in works:
        api_work.delete_work(work["id"])


@pytest.mark.connectors
def test_internal_import_connector(
    internal_import_connector_data, api_connector, api_work, api_client
):
    # Rename variable
    report_id, data = internal_import_connector_data
    observable_data = data["observable"]
    file_data = data["import_file"]

    connector_name = "ParseFileTest"
    connector_id = get_connector_id(connector_name, api_connector)
    assert connector_id != "", f"{connector_name} could not be found!"

    api_client.stix_domain_object.add_file(
        id=report_id,
        file_name=file_data,
    )

    # Wait until new work is registered
    work_id = get_new_work_id(api_client, connector_id)
    # Wait for opencti to finish processing task
    api_work.wait_for_work_to_finish(work_id)

    status_msg = api_work.get_work(work_id)
    assert (
        status_msg["tracking"]["import_expected_number"] == 2
    ), f"Unexpected number of 'import_expected_number'. Expected 2, Actual {status_msg['tracking']['import_expected_number']}"
    assert (
        status_msg["tracking"]["import_processed_number"] == 2
    ), f"Unexpected number of 'import_processed_number'. Expected 2, Actual {status_msg['tracking']['import_processed_number']}"

    report = api_client.report.read(id=report_id)
    assert (
        len(report["objects"]) == 1
    ), f"Unexpected referenced objects to report. Expected: 1, Actual: {len(report['objects'])}"

    observable_id = report["objects"][0]["id"]
    observable = api_client.stix_cyber_observable.read(id=observable_id)
    observable_type = observable_data["simple_observable_key"].split(".")[0]
    assert (
        observable["entity_type"] == observable_type
    ), f"Unexpected Observable type, received {observable_type}"
    assert (
        observable["value"] == observable_data["simple_observable_value"]
    ), f"Unexpected Observable value, received {observable['value']}"

    api_client.stix_cyber_observable.delete(id=observable_id)
