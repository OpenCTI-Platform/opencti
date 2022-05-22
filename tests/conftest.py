import pytest
from pytest_cases import fixture

from pycti import (
    OpenCTIApiClient,
    OpenCTIApiConnector,
    OpenCTIApiWork,
    OpenCTIStix2,
    OpenCTIStix2Splitter,
)


@fixture(scope="session")
def api_client():
    return OpenCTIApiClient(
        "https://demo.opencti.io",
        "7e663f91-d048-4a8b-bdfa-cdb55597942b",
        ssl_verify=True,
    )


@fixture(scope="session")
def api_connector(api_client):
    return OpenCTIApiConnector(api_client)


@fixture(scope="session")
def api_work(api_client):
    return OpenCTIApiWork(api_client)


@fixture(scope="session")
def api_stix(api_client):
    return OpenCTIStix2(api_client)


@fixture(scope="session")
def opencti_splitter():
    return OpenCTIStix2Splitter()


def pytest_addoption(parser):
    parser.addoption(
        "--connectors", action="store_true", default=False, help="run connector tests"
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "connectors: mark connector tests to run")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--connectors"):
        return
    skip_connectors = pytest.mark.skip(reason="need --connectors to run")
    for item in items:
        if "connectors" in item.keywords:
            item.add_marker(skip_connectors)
