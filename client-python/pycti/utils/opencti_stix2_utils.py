from typing import Any, Dict

from stix2 import EqualityComparisonExpression, ObjectPath, ObservationExpression

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
    "imei": "IMEI",
    "iccid": "ICCID",
    "imsi": "IMSI",
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
    "User-Account": ["acount_login"],
    "Windows-Registry-Key": ["key"],
    "Windows-Registry-Value-Type": ["name"],
    "Hostname": ["value"],
    "Bank-Account": ["iban"],
    "Phone-Number": ["value"],
    "Payment-Card": ["card_number"],
    "Tracking-Number": ["value"],
    "Credential": ["value"],
    "Media-Content": ["url"],
    "IMEI": ["value"],
    "ICCID": ["value"],
    "IMSI": ["value"],
}

OBSERVABLES_VALUE_INT = [
    "Autonomous-System.number",
    "Network-Traffic.dst_port",
    "Process.pid",
]


class OpenCTIStix2Utils:
    """Utility class for STIX2 operations in OpenCTI

    Provides helper methods for STIX2 conversions and pattern generation.
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
    def retrieveClassForMethod(
        openCTIApiClient, entity: Dict, type_path: str, method: str
    ) -> Any:
        """Retrieve the appropriate API class for a given entity type and method.

        :param openCTIApiClient: OpenCTI API client instance
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
            attributeName = entity[type_path].lower().replace("-", "_")
            if hasattr(openCTIApiClient, attributeName):
                attribute = getattr(openCTIApiClient, attributeName)
                if hasattr(attribute, method):
                    return attribute
        return None

    @staticmethod
    def compute_object_refs_number(entity: Dict):
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
