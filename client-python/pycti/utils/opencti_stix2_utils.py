"""STIX2 utility functions and mappings for OpenCTI.

This module provides utility classes and constants for working with STIX2 objects
in OpenCTI, including type mappings, pattern generation, and object reference counting.
"""

from typing import Any, Dict

from stix2 import EqualityComparisonExpression, ObjectPath, ObservationExpression

# Aliases field constants
ALIASES_FIELD = "aliases"
X_OPENCTI_ALIASES_FIELD = "x_opencti_aliases"

SUPPORTED_INTERNAL_OBJECTS = [
    "user",
    "group",
    "capability",
    "role",
    "settings",
    "notification",
    "work",
    "trash",
    "draftworkspace",
    "playbook",
    "deleteoperation",
    "workspace",
    "publicdashboard",
]

STIX_META_OBJECTS = [
    "label",
    "vocabulary",
    "kill-chain-phase",
]

STIX_CORE_OBJECTS = [
    "attack-pattern",
    "campaign",
    "case-incident",
    "x-opencti-case-incident",
    "case-rfi",
    "x-opencti-case-rfi",
    "case-rft",
    "x-opencti-case-rft",
    "channel",
    "course-of-action",
    "data-component",
    "x-mitre-data-component",
    "data-source",
    "x-mitre-data-source",
    "event",
    "external-reference",
    "feedback",
    "x-opencti-feedback",
    "grouping",
    "identity",
    "incident",
    "indicator",
    "infrastructure",
    "intrusion-set",
    "language",
    "location",
    "malware",
    "malware-analysis",
    "marking-definition",
    "narrative",
    "note",
    "observed-data",
    "opinion",
    "report",
    "task",
    "x-opencti-task",
    "threat-actor",
    "tool",
    "vulnerability",
    "security-coverage",
]

SUPPORTED_STIX_ENTITY_OBJECTS = STIX_META_OBJECTS + STIX_CORE_OBJECTS

STIX_CYBER_OBSERVABLE_MAPPING = {
    "autonomous-system": "Autonomous-System",
    "directory": "Directory",
    "domain-name": "Domain-Name",
    "email-addr": "Email-Addr",
    "email-message": "Email-Message",
    "email-mime-part-type": "Email-Mime-Part-Type",
    "artifact": "Artifact",
    "file": "StixFile",
    "x509-certificate": "X509-Certificate",
    "ipv4-addr": "IPv4-Addr",
    "ipv6-addr": "IPv6-Addr",
    "mac-addr": "Mac-Addr",
    "mutex": "Mutex",
    "network-traffic": "Network-Traffic",
    "process": "Process",
    "software": "Software",
    "url": "Url",
    "user-account": "User-Account",
    "windows-registry-key": "Windows-Registry-Key",
    "windows-registry-value-type": "Windows-Registry-Value-Type",
    "hostname": "Hostname",
    "cryptographic-key": "Cryptographic-Key",
    "cryptocurrency-wallet": "Cryptocurrency-Wallet",
    "text": "Text",
    "user-agent": "User-Agent",
    "bank-account": "Bank-Account",
    "phone-number": "Phone-Number",
    "credential": "Credential",
    "tracking-number": "Tracking-Number",
    "payment-card": "Payment-Card",
    "media-content": "Media-Content",
    "simple-observable": "Simple-Observable",
    "persona": "Persona",
    "ssh-key": "SSH-Key",
}

STIX_OBJECTS = (
    SUPPORTED_STIX_ENTITY_OBJECTS  # entities
    + list(STIX_CYBER_OBSERVABLE_MAPPING.keys())  # observables
    + ["relationship", "sighting"]  # relationships
)

PATTERN_MAPPING = {
    "Autonomous-System": ["number"],
    "Directory": ["path"],
    "Domain-Name": ["value"],
    "Email-Addr": ["value"],
    "File_md5": ["hashes", "MD5"],
    "File_sha1": ["hashes", "SHA-1"],
    "File_sha256": ["hashes", "SHA-256"],
    "File_sha512": ["hashes", "SHA-512"],
    "Email-Message_Body": ["body"],
    "Email-Message_Subject": ["subject"],
    "Email-Mime-Part-Type": ["body"],
    "IPv4-Addr": ["value"],
    "IPv6-Addr": ["value"],
    "Mac-Addr": ["value"],
    "Mutex": ["name"],
    "Network-Traffic": ["dst_port"],
    "Process": ["pid"],
    "Software": ["name"],
    "Url": ["value"],
    "User-Account": ["account_login"],
    "Windows-Registry-Key": ["key"],
    "Windows-Registry-Value-Type": ["name"],
    "Hostname": ["value"],
    "Bank-Account": ["iban"],
    "Phone-Number": ["value"],
    "Payment-Card": ["card_number"],
    "Tracking-Number": ["value"],
    "Credential": ["value"],
    "Media-Content": ["url"],
}

OBSERVABLES_VALUE_INT = [
    "Autonomous-System.number",
    "Network-Traffic.dst_port",
    "Process.pid",
]


class OpenCTIStix2Utils:
    """Utility class for STIX2 operations in OpenCTI.

    Provides helper methods for STIX2 conversions and pattern generation,
    including type mappings, observable pattern creation, and reference counting.
    """

    @staticmethod
    def stix_observable_opencti_type(observable_type):
        """Convert STIX observable type to OpenCTI type.

        :param observable_type: STIX observable type
        :type observable_type: str
        :return: Corresponding OpenCTI type or "Unknown"
        :rtype: str
        """
        if observable_type in STIX_CYBER_OBSERVABLE_MAPPING:
            return STIX_CYBER_OBSERVABLE_MAPPING[observable_type]
        else:
            return "Unknown"

    @staticmethod
    def create_stix_pattern(observable_type, observable_value):
        """Create a STIX pattern from an observable type and value.

        :param observable_type: Type of the observable
        :type observable_type: str
        :param observable_value: Value of the observable
        :type observable_value: str
        :return: STIX pattern string or None if type not supported
        :rtype: str or None
        """
        if observable_type in PATTERN_MAPPING:
            lhs = ObjectPath(
                (
                    observable_type.lower()
                    if "_" not in observable_type
                    else observable_type.split("_")[0].lower()
                ),
                PATTERN_MAPPING[observable_type],
            )
            ece = ObservationExpression(
                EqualityComparisonExpression(lhs, observable_value)
            )
            return str(ece)
        else:
            return None

    @staticmethod
    def generate_random_stix_id(stix_type):
        """Generate random stix id (uuid v1) - DEPRECATED.

        This function is deprecated and should not be used anymore.
        Please use the generate_id function for SDO or proper SCO constructor.

        :param stix_type: the stix type
        :raises ValueError: Always raises an error as this function is deprecated
        """
        raise ValueError(
            "This function should not be used anymore, please use the generate_id function for SDO or proper SCO constructor"
        )

    @staticmethod
    def retrieve_class_for_method(
        opencti_api_client, entity: Dict, type_path: str, method: str
    ) -> Any:
        """Retrieve the appropriate API class for a given entity type and method.

        :param opencti_api_client: OpenCTI API client instance
        :type opencti_api_client: OpenCTIApiClient
        :param entity: Entity dictionary containing the type
        :type entity: Dict
        :param type_path: Path to the type field in the entity
        :type type_path: str
        :param method: Name of the method to check for
        :type method: str
        :return: The API class that has the specified method, or None
        :rtype: Any
        """
        if entity is not None and type_path in entity:
            attribute_name = entity[type_path].lower().replace("-", "_")
            if hasattr(opencti_api_client, attribute_name):
                attribute = getattr(opencti_api_client, attribute_name)
                if hasattr(attribute, method):
                    return attribute
        return None

    @staticmethod
    def retrieveClassForMethod(
        openCTIApiClient, entity: Dict, type_path: str, method: str
    ) -> Any:
        """Retrieve the appropriate API class for a given entity type and method.

        .. deprecated::
            Use :meth:`retrieve_class_for_method` instead.

        :param openCTIApiClient: OpenCTI API client instance
        :type openCTIApiClient: OpenCTIApiClient
        :param entity: Entity dictionary containing the type
        :type entity: Dict
        :param type_path: Path to the type field in the entity
        :type type_path: str
        :param method: Name of the method to check for
        :type method: str
        :return: The API class that has the specified method, or None
        :rtype: Any
        """
        return OpenCTIStix2Utils.retrieve_class_for_method(
            openCTIApiClient, entity, type_path, method
        )

    @staticmethod
    def compute_object_refs_number(entity: Dict):
        """Compute the number of object references in an entity.

        :param entity: Entity dictionary to analyze
        :type entity: Dict
        :return: Total number of references
        :rtype: int
        """
        refs_number = 0
        for key in list(entity.keys()):
            if key.endswith("_refs") and entity[key] is not None:
                refs_number += len(entity[key])
            elif key.endswith("_ref"):
                refs_number += 1
            elif key == "external_references" and entity[key] is not None:
                refs_number += len(entity[key])
            elif key == "kill_chain_phases" and entity[key] is not None:
                refs_number += len(entity[key])
        return refs_number


# Types that use x_opencti_aliases instead of aliases
# Based on opencti-graphql/src/schema/stixDomainObject.ts resolveAliasesField()
_X_OPENCTI_ALIASES_TYPES = frozenset(
    ["course-of-action", "vulnerability", "grouping", "identity", "location"]
)

# Types that support aliases (from STIX_DOMAIN_OBJECT_ALIASED in stixDomainObject.ts)
_STIX_ALIASED_TYPES = frozenset(
    [
        "attack-pattern",
        "campaign",
        "channel",
        "x-opencti-channel",
        "course-of-action",
        "event",
        "x-opencti-event",
        "grouping",
        "identity",
        "incident",
        "infrastructure",
        "intrusion-set",
        "location",
        "malware",
        "narrative",
        "x-opencti-narrative",
        "threat-actor",
        "tool",
        "vulnerability",
    ]
)


def resolve_aliases_field(stix_type: str) -> str:
    """Resolve the correct aliases field name for a given STIX type.

    OpenCTI uses two different field names for aliases depending on the entity type:
    - `aliases`: Standard STIX field used by most SDO types (Attack-Pattern, Campaign,
      Infrastructure, Intrusion-Set, Malware, Threat-Actor-Group, Tool, Incident, etc.)
    - `x_opencti_aliases`: OpenCTI extension field used by Course-Of-Action, Vulnerability,
      Grouping, Identity types (Individual, Sector, System, Organization), and Location types
      (Region, Country, Administrative-Area, City, Position)

    This mirrors the logic in opencti-graphql/src/schema/stixDomainObject.ts resolveAliasesField()

    Note: This function is case-insensitive.

    :param stix_type: The STIX object type (e.g., "malware", "vulnerability", "identity")
    :type stix_type: str
    :return: The aliases field name to use ("aliases" or "x_opencti_aliases")
    :rtype: str

    Example:
        >>> resolve_aliases_field("malware")
        'aliases'
        >>> resolve_aliases_field("Vulnerability")
        'x_opencti_aliases'
        >>> resolve_aliases_field("IDENTITY")
        'x_opencti_aliases'
    """
    if stix_type.lower() in _X_OPENCTI_ALIASES_TYPES:
        return X_OPENCTI_ALIASES_FIELD
    return ALIASES_FIELD


def is_stix_object_aliased(stix_type: str) -> bool:
    """Check if a STIX object type supports aliases.

    Returns True for entity types that have an aliases field in OpenCTI.

    Note: This function is case-insensitive.

    :param stix_type: The STIX object type (e.g., "malware", "indicator", "identity")
    :type stix_type: str
    :return: True if the type supports aliases, False otherwise
    :rtype: bool

    Example:
        >>> is_stix_object_aliased("malware")
        True
        >>> is_stix_object_aliased("Malware")
        True
        >>> is_stix_object_aliased("indicator")
        False
    """
    return stix_type.lower() in _STIX_ALIASED_TYPES
