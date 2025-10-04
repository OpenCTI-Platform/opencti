from enum import Enum

# Scope definition
# EXTERNAL_IMPORT = None
# INTERNAL_IMPORT_FILE = Files mime types to support (application/json, ...)
# INTERNAL_ENRICHMENT = Entity types to support (Report, Hash, ...)
# INTERNAL_EXPORT_FILE = Files mime types to generate (application/pdf, ...)


class ConnectorType(Enum):
    EXTERNAL_IMPORT = "EXTERNAL_IMPORT"  # From remote sources to OpenCTI stix2
    INTERNAL_IMPORT_FILE = (
        "INTERNAL_IMPORT_FILE"  # From OpenCTI file system to OpenCTI stix2
    )
    INTERNAL_ENRICHMENT = "INTERNAL_ENRICHMENT"  # From OpenCTI stix2 to OpenCTI stix2
    INTERNAL_ANALYSIS = "INTERNAL_ANALYSIS"  # From OpenCTI file system or OpenCTI stix2 to OpenCTI file system
    INTERNAL_EXPORT_FILE = (
        "INTERNAL_EXPORT_FILE"  # From OpenCTI stix2 to OpenCTI file system
    )
    STREAM = "STREAM"  # Read the stream and do something


class OpenCTIConnector:
    """Main class for OpenCTI connector

    :param connector_id: id for the connector (valid uuid4)
    :type connector_id: str
    :param connector_name: name for the connector
    :type connector_name: str
    :param connector_type: valid OpenCTI connector type (see `ConnectorType`)
    :type connector_type: str
    :param scope: connector scope
    :type scope: str
    :raises ValueError: if the connector type is not valid
    """

    def __init__(
        self,
        connector_id: str,
        connector_name: str,
        connector_type: str,
        scope: str,
        auto: bool,
        only_contextual: bool,
        playbook_compatible: bool,
        listen_callback_uri=None,
    ):
        self.id = connector_id
        self.name = connector_name
        self.type = ConnectorType(connector_type)
        if self.type is None:
            raise ValueError("Invalid connector type: " + connector_type)
        if scope and len(scope) > 0:
            self.scope = scope.split(",")
        else:
            self.scope = []
        self.auto = auto
        self.only_contextual = only_contextual
        self.playbook_compatible = playbook_compatible
        self.listen_callback_uri = listen_callback_uri

    def to_input(self) -> dict:
        """connector input to use in API query

        :return: dict with connector data
        :rtype: dict
        """
        return {
            "input": {
                "id": self.id,
                "name": self.name,
                "type": self.type.name,
                "scope": self.scope,
                "auto": self.auto,
                "only_contextual": self.only_contextual,
                "playbook_compatible": self.playbook_compatible,
                "listen_callback_uri": self.listen_callback_uri,
            }
        }
