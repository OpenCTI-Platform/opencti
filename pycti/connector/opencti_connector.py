from enum import Enum

# Scope definition
# EXTERNAL_IMPORT = None
# INTERNAL_IMPORT_FILE = Files mime types to support (application/json, ...)
# INTERNAL_ENRICHMENT = Entity types to support (Report, Hash, ...)
# INTERNAL_EXPORT_FILE = Files mime types to generate (application/pdf, ...)


class ConnectorType(Enum):
    EXTERNAL_IMPORT = 'EXTERNAL_IMPORT'  # From remote sources to OpenCTI stix2
    INTERNAL_IMPORT_FILE = 'INTERNAL_IMPORT_FILE'  # From OpenCTI file system to OpenCTI stix2
    INTERNAL_ENRICHMENT = 'INTERNAL_ENRICHMENT'  # From OpenCTI stix2 to OpenCTI stix2
    INTERNAL_EXPORT_FILE = 'INTERNAL_EXPORT_FILE'  # From OpenCTI stix2 to OpenCTI file system


class OpenCTIConnector:
    def __init__(self, connector_id: str, connector_name: str, connector_type: str, scope: str):
        self.id = connector_id
        self.name = connector_name
        self.type = ConnectorType(connector_type)
        if self.type is None:
            raise ValueError('Invalid connector type: ' + connector_type)
        self.scope = scope.split(',')

    def to_input(self):
        return {'input': {'id': self.id, 'name': self.name, 'type': self.type.name, 'scope': self.scope}}
