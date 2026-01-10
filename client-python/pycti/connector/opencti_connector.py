"""OpenCTI Connector module.

This module defines the connector types and the main OpenCTIConnector class
used to register and configure connectors with the OpenCTI platform.
"""

from enum import Enum


class ConnectorType(Enum):
    """Enumeration of OpenCTI connector types.

    Each connector type defines a specific data flow pattern:

    - EXTERNAL_IMPORT: Imports data from remote sources into OpenCTI as STIX2
    - INTERNAL_IMPORT_FILE: Converts files from OpenCTI file system to STIX2
    - INTERNAL_ENRICHMENT: Enriches existing STIX2 data with additional information
    - INTERNAL_ANALYSIS: Analyzes files or STIX2 data and produces file output
    - INTERNAL_EXPORT_FILE: Exports STIX2 data to files in OpenCTI file system
    - STREAM: Reads the event stream and performs custom actions

    Scope definition varies by type:
        - EXTERNAL_IMPORT: None (imports everything)
        - INTERNAL_IMPORT_FILE: MIME types to support (e.g., application/json)
        - INTERNAL_ENRICHMENT: Entity types to support (e.g., Report, Hash)
        - INTERNAL_EXPORT_FILE: MIME types to generate (e.g., application/pdf)
    """

    EXTERNAL_IMPORT = "EXTERNAL_IMPORT"
    INTERNAL_IMPORT_FILE = "INTERNAL_IMPORT_FILE"
    INTERNAL_ENRICHMENT = "INTERNAL_ENRICHMENT"
    INTERNAL_ANALYSIS = "INTERNAL_ANALYSIS"
    INTERNAL_EXPORT_FILE = "INTERNAL_EXPORT_FILE"
    STREAM = "STREAM"


class OpenCTIConnector:
    """Main class for OpenCTI connector registration and configuration.

    This class represents a connector instance that can be registered with
    the OpenCTI platform. It holds all configuration parameters needed for
    the connector to operate.

    :param connector_id: Unique identifier for the connector (valid UUID4)
    :type connector_id: str
    :param connector_name: Human-readable name for the connector
    :type connector_name: str
    :param connector_type: Type of connector (see :class:`ConnectorType`)
    :type connector_type: str
    :param scope: Connector scope as a comma-separated string (e.g., "Report,Indicator")
    :type scope: str
    :param auto: Whether the connector runs automatically on matching entities
    :type auto: bool
    :param only_contextual: Whether the connector only processes contextual data
    :type only_contextual: bool
    :param playbook_compatible: Whether the connector can be used in playbooks
    :type playbook_compatible: bool
    :param auto_update: Whether to automatically update existing entities
    :type auto_update: bool
    :param enrichment_resolution: Strategy for resolving enrichment conflicts
    :type enrichment_resolution: str
    :param listen_callback_uri: Optional callback URI for API-based listening
    :type listen_callback_uri: str or None

    :raises ValueError: If the connector type is not a valid ConnectorType value

    Example:
        >>> connector = OpenCTIConnector(
        ...     connector_id="550e8400-e29b-41d4-a716-446655440000",
        ...     connector_name="My Connector",
        ...     connector_type="EXTERNAL_IMPORT",
        ...     scope="Report,Indicator",
        ...     auto=False,
        ...     only_contextual=False,
        ...     playbook_compatible=True,
        ...     auto_update=False,
        ...     enrichment_resolution="none"
        ... )
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
        auto_update: bool,
        enrichment_resolution: str,
        listen_callback_uri=None,
    ):
        """Initialize the OpenCTIConnector instance.

        :param connector_id: Unique identifier for the connector (valid UUID4)
        :type connector_id: str
        :param connector_name: Human-readable name for the connector
        :type connector_name: str
        :param connector_type: Type of connector (see :class:`ConnectorType`)
        :type connector_type: str
        :param scope: Connector scope as a comma-separated string
        :type scope: str
        :param auto: Whether the connector runs automatically
        :type auto: bool
        :param only_contextual: Whether to process only contextual data
        :type only_contextual: bool
        :param playbook_compatible: Whether the connector works with playbooks
        :type playbook_compatible: bool
        :param auto_update: Whether to auto-update existing entities
        :type auto_update: bool
        :param enrichment_resolution: Enrichment conflict resolution strategy
        :type enrichment_resolution: str
        :param listen_callback_uri: Optional callback URI for API listening
        :type listen_callback_uri: str or None

        :raises ValueError: If connector_type is not a valid ConnectorType
        """
        self.id = connector_id
        self.name = connector_name
        self.type = ConnectorType(connector_type)
        if scope:
            self.scope = scope.split(",")
        else:
            self.scope = []
        self.auto = auto
        self.auto_update = auto_update
        self.enrichment_resolution = enrichment_resolution
        self.only_contextual = only_contextual
        self.playbook_compatible = playbook_compatible
        self.listen_callback_uri = listen_callback_uri

    def to_input(self) -> dict:
        """Convert connector configuration to API input format.

        Generates a dictionary structure suitable for use in GraphQL API
        queries to register or update the connector.

        :return: Dictionary containing connector data wrapped in an "input" key
        :rtype: dict

        Example:
            >>> connector.to_input()
            {'input': {'id': '...', 'name': 'My Connector', ...}}
        """
        return {
            "input": {
                "id": self.id,
                "name": self.name,
                "type": self.type.name,
                "scope": self.scope,
                "auto": self.auto,
                "auto_update": self.auto_update,
                "enrichment_resolution": self.enrichment_resolution,
                "only_contextual": self.only_contextual,
                "playbook_compatible": self.playbook_compatible,
                "listen_callback_uri": self.listen_callback_uri,
            }
        }
