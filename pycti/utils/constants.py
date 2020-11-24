"""These are the custom STIX properties and observation types used internally by OpenCTI.

"""
from enum import Enum


class StixCyberObservableTypes(Enum):
    AUTONOMOUS_SYSTEM = "Autonomous-System"
    DIRECTORY = "Directory"
    DOMAIN_NAME = "Domain-Name"
    EMAIL_ADDR = "Email-Addr"
    EMAIL_MESSAGE = "Email-Message"
    EMAIL_MIME_PART_TYPE = "Email-Mime-Part-Type"
    ARTIFACT = "Artifact"
    FILE = "File"
    X509_CERTIFICATE = "X509-Certificate"
    IPV4_ADDR = "IPv4-Addr"
    IPV6_ADDR = "IPv6-Addr"
    MAC_ADDR = "Mac-Addr"
    MUTEX = "Mutex"
    NETWORK_TRAFFIC = "Network-Traffic"
    PROCESS = "Process"
    SOFTWARE = "Software"
    URL = "Url"
    USER_ACCOUNT = "User-Account"
    WINDOWS_REGISTRY_KEY = "Windows-Registry-Key"
    WINDOWS_REGISTRY_VALUE_TYPE = "Windows-Registry-Value-Type"
    X509_V3_EXTENSIONS_TYPE_ = "X509-V3-Extensions-Type"
    X_OPENCTI_HOSTNAME = "X-OpenCTI-Hostname"
    X_OPENCTI_CRYPTOGRAPHIC_KEY = "X-OpenCTI-Cryptographic-Key"
    X_OPENCTI_CRYPTOCURRENCY_WALLET = "X-OpenCTI-Cryptocurrency-Wallet"
    X_OPENCTI_TEXT = "X-OpenCTI-Text"
    X_OPENCTI_USER_AGENT = "X-OpenCTI-User-Agent"
    X_OPENCTI_SIMPLE_OBSERVABLE = "X-OpenCTI-Simple-Observable"

    @classmethod
    def has_value(cls, value):
        lower_attr = list(map(lambda x: x.lower(), cls._value2member_map_))
        return value.lower() in lower_attr


class IdentityTypes(Enum):
    SECTOR = "Sector"
    ORGANIZATION = "Organization"
    INDIVIDUAL = "Individual"

    @classmethod
    def has_value(cls, value):
        lower_attr = list(map(lambda x: x.lower(), cls._value2member_map_))
        return value.lower() in lower_attr


class LocationTypes(Enum):
    CITY = "City"
    COUNTRY = "Country"
    REGION = "Region"
    POSITION = "Position"

    @classmethod
    def has_value(cls, value):
        lower_attr = list(map(lambda x: x.lower(), cls._value2member_map_))
        return value.lower() in lower_attr


class ContainerTypes(Enum):
    NOTE = "Note"
    OBSERVED_DATA = "Observed-Data"
    OPINION = "Opinion"
    REPORT = "Report"

    @classmethod
    def has_value(cls, value):
        lower_attr = list(map(lambda x: x.lower(), cls._value2member_map_))
        return value.lower() in lower_attr
