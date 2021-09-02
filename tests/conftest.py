import pytest
from pytest_cases import fixture
from pycti import OpenCTIApiClient, OpenCTIApiConnector


@fixture(scope="session")
def api_client():
    return OpenCTIApiClient(
        "https://demo.opencti.io",
        "1db04f50-a5cb-4ec3-be29-2fcca533f234"
        ssl_verify=True,
    )


@fixture(scope="session")
def api_connector(api_client):
    return OpenCTIApiConnector(api_client)


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
