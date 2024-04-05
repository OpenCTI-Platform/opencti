from typing import Any, Dict

from stix2 import EqualityComparisonExpression, ObjectPath, ObservationExpression

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
}

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
}

OBSERVABLES_VALUE_INT = [
    "Autonomous-System.number",
    "Network-Traffic.dst_port",
    "Process.pid",
]


class OpenCTIStix2Utils:
    @staticmethod
    def stix_observable_opencti_type(observable_type):
        if observable_type in STIX_CYBER_OBSERVABLE_MAPPING:
            return STIX_CYBER_OBSERVABLE_MAPPING[observable_type]
        else:
            return "Unknown"

    @staticmethod
    def create_stix_pattern(observable_type, observable_value):
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

    """Generate random stix id (uuid v1)
    This id will stored and resolved by openCTI
    We will stored only 5 stix of this type to prevent database flooding
    :param stix_type: the stix type
    """

    @staticmethod
    def generate_random_stix_id(stix_type):
        raise ValueError(
            "This function should not be used anymore, please use the generate_id function for SDO or proper SCO constructor"
        )

    @staticmethod
    def retrieveClassForMethod(
        openCTIApiClient, entity: Dict, type_path: str, method: str
    ) -> Any:
        if entity is not None and type_path in entity:
            attributeName = entity[type_path].lower().replace("-", "_")
            if hasattr(openCTIApiClient, attributeName):
                attribute = getattr(openCTIApiClient, attributeName)
                if hasattr(attribute, method):
                    return attribute
        return None
