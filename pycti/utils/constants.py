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
    HOSTNAME = "Hostname"
    CRYPTOGRAPHIC_KEY = "Cryptographic-Key"
    CRYPTOCURRENCY_WALLET = "Cryptocurrency-Wallet"
    TEXT = "Text"
    USER_AGENT = "User-Agent"
    BANK_ACCOUNT = "Bank-Account"
    PHONE_NUMBER = "Phone-Number"
    PAYMENT_CARD = "Payment-Card"
    MEDIA_CONTENT = "Media-Content"
    SIMPLE_OBSERVABLE = "Simple-Observable"

    @classmethod
    def has_value(cls, value):
        lower_attr = list(map(lambda x: x.lower(), cls._value2member_map_))
        return value.lower() in lower_attr


class IdentityTypes(Enum):
    SECTOR = "Sector"
    ORGANIZATION = "Organization"
    INDIVIDUAL = "Individual"
    SYSTEM = "System"

    @classmethod
    def has_value(cls, value):
        lower_attr = list(map(lambda x: x.lower(), cls._value2member_map_))
        return value.lower() in lower_attr


class LocationTypes(Enum):
    REGION = "Region"
    COUNTRY = "Country"
    ADMINISTRATIVE_AREA = "Administrative-Area"
    CITY = "City"
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
    GROUPING = "Grouping"
    CASE = "Case"

    @classmethod
    def has_value(cls, value):
        lower_attr = list(map(lambda x: x.lower(), cls._value2member_map_))
        return value.lower() in lower_attr


class StixMetaTypes(Enum):
    MARKING_DEFINITION = "Marking-Definition"
    LABEL = "Label"
    EXTERNAL_REFERENCE = "External-Reference"
    KILL_CHAIN_PHASE = "Kill-Chain-Phase"

    @classmethod
    def has_value(cls, value):
        lower_attr = list(map(lambda x: x.lower(), cls._value2member_map_))
        return value.lower() in lower_attr


class MultipleStixCyberObservableRelationship(Enum):
    OPERATING_SYSTEM = "operating-system"
    CONTAINS = "contains"
    RESOLVES_TO = "obs_resolves-to"
    BELONGS_TO = "obs_belongs-to"
    TO = "to"
    CC = "cc"
    BCC = "bcc"
    ENCAPSULATES = "encapsulates"
    OPENED_CONNECTION = "opened-connection"
    CHILD = "child"
    BODY_MULTIPART = "body-multipart"
    VALUES = "values"
    LINKED = "linked-to"

    @classmethod
    def has_value(cls, value):
        lower_attr = list(map(lambda x: x.lower(), cls._value2member_map_))
        return value.lower() in lower_attr
