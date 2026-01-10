"""OpenCTI Connector package.

This package provides classes and utilities for building OpenCTI connectors.
Connectors are used to import, export, enrich, and stream data to/from the
OpenCTI platform.

Classes:
    OpenCTIConnector: Connector configuration and registration class.
    ConnectorType: Enumeration of supported connector types.
    OpenCTIConnectorHelper: Main helper class for connector development.
    OpenCTIMetricHandler: Prometheus metrics handler for connectors.

Functions:
    get_config_variable: Retrieve configuration from environment or YAML.

Example:
    >>> from pycti.connector import OpenCTIConnectorHelper, get_config_variable
    >>> config = {"opencti": {"url": "...", "token": "..."}, "connector": {...}}
    >>> helper = OpenCTIConnectorHelper(config)
    >>> helper.listen(my_callback)
"""

from pycti.connector.opencti_connector import ConnectorType, OpenCTIConnector
from pycti.connector.opencti_connector_helper import (
    OpenCTIConnectorHelper,
    get_config_variable,
)
from pycti.connector.opencti_metric_handler import OpenCTIMetricHandler

__all__ = [
    "ConnectorType",
    "OpenCTIConnector",
    "OpenCTIConnectorHelper",
    "OpenCTIMetricHandler",
    "get_config_variable",
]

