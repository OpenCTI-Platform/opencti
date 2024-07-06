"""These are the custom STIX properties and observation types used internally by OpenCTI.

"""

from enum import Enum

from stix2 import CustomObject, CustomObservable, ExternalReference
from stix2.properties import (
    ListProperty,
    ReferenceProperty,
    StringProperty,
    TimestampProperty,
)
from stix2.utils import NOW


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
    CREDENTIAL = "Credential"
    TRACKING_NUMBER = "Tracking-Number"
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


class ThreatActorTypes(Enum):
    THREAT_ACTOR_GROUP = "Threat-Actor-Group"
    THREAT_ACTOR_INDIVIDUAL = "Threat-Actor-Individual"

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


class MultipleRefRelationship(Enum):
    OPERATING_SYSTEM = "operating-system"
    SAMPLE = "sample"
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
    SERVICE_DDL = "service-dll"
    INSTALLED_SOFTWARE = "installed-software"
    RELATION_ANALYSIS_SCO = "analysis-sco"

    @classmethod
    def has_value(cls, value):
        lower_attr = list(map(lambda x: x.lower(), cls._value2member_map_))
        return value.lower() in lower_attr


# Custom objects


@CustomObject(
    "case-incident",
    [
        ("name", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        ("description", StringProperty()),
        ("severity", StringProperty()),
        ("priority", StringProperty()),
        ("response_types", ListProperty(StringProperty)),
        ("x_opencti_workflow_id", StringProperty()),
        ("x_opencti_assignee_ids", ListProperty(StringProperty)),
        ("external_references", ListProperty(ExternalReference)),
        (
            "object_refs",
            ListProperty(
                ReferenceProperty(valid_types=["SCO", "SDO", "SRO"], spec_version="2.1")
            ),
        ),
    ],
)
class CustomObjectCaseIncident:
    """Case-Incident object."""

    pass


@CustomObject(
    "case-rfi",
    [
        ("name", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        ("description", StringProperty()),
        ("severity", StringProperty()),
        ("priority", StringProperty()),
        ("information_types", ListProperty(StringProperty)),
        ("x_opencti_workflow_id", StringProperty()),
        ("x_opencti_assignee_ids", ListProperty(StringProperty)),
        ("external_references", ListProperty(ExternalReference)),
        (
            "object_refs",
            ListProperty(
                ReferenceProperty(valid_types=["SCO", "SDO", "SRO"], spec_version="2.1")
            ),
        ),
    ],
)
class CustomObjectCaseRfit:
    """Case-Rfi object."""

    pass


@CustomObject(
    "task",
    [
        ("name", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        ("description", StringProperty()),
        (
            "due_date",
            TimestampProperty(
                default=lambda: NOW, precision="millisecond", precision_constraint="min"
            ),
        ),
        ("x_opencti_workflow_id", StringProperty()),
        ("x_opencti_assignee_ids", ListProperty(StringProperty)),
        (
            "object_refs",
            ListProperty(
                ReferenceProperty(valid_types=["SCO", "SDO", "SRO"], spec_version="2.1")
            ),
        ),
    ],
)
class CustomObjectTask:
    """Task object."""

    pass


@CustomObject(
    "channel",
    [
        ("name", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        ("description", StringProperty()),
        ("aliases", ListProperty(StringProperty)),
        ("channel_types", ListProperty(StringProperty)),
        ("x_opencti_workflow_id", StringProperty()),
        ("x_opencti_assignee_ids", ListProperty(StringProperty)),
        ("external_references", ListProperty(ExternalReference)),
    ],
)
class CustomObjectChannel:
    """Channel object."""

    pass


# Custom observables


@CustomObservable(
    "hostname",
    [
        ("value", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["value"],
)
class CustomObservableHostname:
    """Hostname observable."""

    pass


@CustomObservable(
    "text",
    [
        ("value", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["value"],
)
class CustomObservableText:
    """Text observable."""

    pass


@CustomObservable(
    "payment-card",
    [
        ("value", StringProperty(required=True)),
        ("card_number", StringProperty(required=True)),
        ("expiration_date", StringProperty(required=False)),
        ("cvv", StringProperty(required=False)),
        ("holder_name", StringProperty(required=False)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["card_number"],
)
class CustomObservablePaymentCard:
    """Payment card observable."""

    pass


@CustomObservable(
    "bank-account",
    [
        ("value", StringProperty(required=True)),
        ("iban", StringProperty(required=True)),
        ("bic", StringProperty(required=False)),
        ("account_number", StringProperty(required=False)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["iban"],
)
class CustomObservableBankAccount:
    """Bank Account observable."""

    pass


@CustomObservable(
    "credential",
    [
        ("value", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["value"],
)
class CustomObservableCredential:
    """Credential observable."""

    pass


@CustomObservable(
    "cryptocurrency-wallet",
    [
        ("value", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["value"],
)
class CustomObservableCryptocurrencyWallet:
    """Cryptocurrency wallet observable."""

    pass


@CustomObservable(
    "phone-number",
    [
        ("value", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["value"],
)
class CustomObservablePhoneNumber:
    """Phone number observable."""

    pass


@CustomObservable(
    "tracking-number",
    [
        ("value", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["value"],
)
class CustomObservableTrackingNumber:
    """Tracking number observable."""

    pass


@CustomObservable(
    "user-agent",
    [
        ("value", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["value"],
)
class CustomObservableUserAgent:
    """User-Agent observable."""

    pass


@CustomObservable(
    "media-content",
    [
        ("title", StringProperty()),
        ("description", StringProperty()),
        ("content", StringProperty()),
        ("media_category", StringProperty()),
        ("url", StringProperty(required=True)),
        ("publication_date", TimestampProperty()),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["url"],
)
class CustomObservableMediaContent:
    """Media-Content observable."""

    pass
