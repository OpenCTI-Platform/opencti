"""These are the custom STIX properties and observation types used internally by OpenCTI."""

from enum import Enum

from stix2 import CustomObject, CustomObservable, ExternalReference
from stix2.properties import (
    ListProperty,
    ReferenceProperty,
    StringProperty,
    TimestampProperty,
)
from stix2.utils import NOW


class CaseInsensitiveEnum(Enum):
    """Base Enum class with case-insensitive value lookup."""

    @classmethod
    def has_value(cls, value: str) -> bool:
        """Check if the enum contains the given value (case-insensitive).

        :param value: Value to check
        :type value: str
        :return: True if value exists in enum, False otherwise
        :rtype: bool
        """
        lower_values = [v.lower() for v in cls._value2member_map_]
        return value.lower() in lower_values


class StixCyberObservableTypes(CaseInsensitiveEnum):
    """Enumeration of STIX Cyber Observable types supported by OpenCTI."""

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
    PERSONA = "Persona"
    SSH_KEY = "SSH-Key"


class IdentityTypes(CaseInsensitiveEnum):
    """Enumeration of Identity types supported by OpenCTI."""

    SECTOR = "Sector"
    ORGANIZATION = "Organization"
    INDIVIDUAL = "Individual"
    SYSTEM = "System"
    SECURITYPLATFORM = "SecurityPlatform"


class ThreatActorTypes(CaseInsensitiveEnum):
    """Enumeration of Threat Actor types supported by OpenCTI."""

    THREAT_ACTOR_GROUP = "Threat-Actor-Group"
    THREAT_ACTOR_INDIVIDUAL = "Threat-Actor-Individual"


class LocationTypes(CaseInsensitiveEnum):
    """Enumeration of Location types supported by OpenCTI."""

    REGION = "Region"
    COUNTRY = "Country"
    ADMINISTRATIVE_AREA = "Administrative-Area"
    CITY = "City"
    POSITION = "Position"


class ContainerTypes(CaseInsensitiveEnum):
    """Enumeration of Container types supported by OpenCTI."""

    NOTE = "Note"
    OBSERVED_DATA = "Observed-Data"
    OPINION = "Opinion"
    REPORT = "Report"
    GROUPING = "Grouping"
    CASE = "Case"


class StixMetaTypes(CaseInsensitiveEnum):
    """Enumeration of STIX Meta Object types supported by OpenCTI."""

    MARKING_DEFINITION = "Marking-Definition"
    LABEL = "Label"
    EXTERNAL_REFERENCE = "External-Reference"
    KILL_CHAIN_PHASE = "Kill-Chain-Phase"


class MultipleRefRelationship(CaseInsensitiveEnum):
    """Enumeration of relationship types that can have multiple references."""

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
    SERVICE_DLL = "service-dll"
    INSTALLED_SOFTWARE = "installed-software"
    RELATION_ANALYSIS_SCO = "analysis-sco"


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
    """Custom STIX2 Case-Incident object for OpenCTI.

    Represents a case-incident container with associated metadata including
    name, description, severity, priority, and response types.

    :param name: Name of the case incident (required)
    :type name: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param description: Description of the case incident
    :type description: str
    :param severity: Severity level of the incident
    :type severity: str
    :param priority: Priority level of the incident
    :type priority: str
    :param response_types: List of response types
    :type response_types: list
    :param x_opencti_workflow_id: OpenCTI workflow identifier
    :type x_opencti_workflow_id: str
    :param x_opencti_assignee_ids: List of assignee identifiers
    :type x_opencti_assignee_ids: list
    :param external_references: List of external references
    :type external_references: list
    :param object_refs: List of referenced STIX objects
    :type object_refs: list
    """

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
class CustomObjectCaseRfi:
    """Custom STIX2 Case-RFI (Request For Information) object for OpenCTI.

    Represents a request for information container with associated metadata
    including name, description, severity, priority, and information types.

    :param name: Name of the RFI case (required)
    :type name: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param description: Description of the RFI case
    :type description: str
    :param severity: Severity level of the RFI
    :type severity: str
    :param priority: Priority level of the RFI
    :type priority: str
    :param information_types: List of information types requested
    :type information_types: list
    :param x_opencti_workflow_id: OpenCTI workflow identifier
    :type x_opencti_workflow_id: str
    :param x_opencti_assignee_ids: List of assignee identifiers
    :type x_opencti_assignee_ids: list
    :param external_references: List of external references
    :type external_references: list
    :param object_refs: List of referenced STIX objects
    :type object_refs: list
    """

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
    """Custom STIX2 Task object for OpenCTI.

    Represents a task with associated metadata including name, description,
    due date, and assignees.

    :param name: Name of the task (required)
    :type name: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param description: Description of the task
    :type description: str
    :param due_date: Due date timestamp for the task
    :type due_date: datetime
    :param x_opencti_workflow_id: OpenCTI workflow identifier
    :type x_opencti_workflow_id: str
    :param x_opencti_assignee_ids: List of assignee identifiers
    :type x_opencti_assignee_ids: list
    :param object_refs: List of referenced STIX objects
    :type object_refs: list
    """

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
    """Custom STIX2 Channel object for OpenCTI.

    Represents a communication channel with associated metadata including
    name, description, aliases, and channel types.

    :param name: Name of the channel (required)
    :type name: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param description: Description of the channel
    :type description: str
    :param aliases: List of alternative names for the channel
    :type aliases: list
    :param channel_types: List of channel types
    :type channel_types: list
    :param x_opencti_workflow_id: OpenCTI workflow identifier
    :type x_opencti_workflow_id: str
    :param x_opencti_assignee_ids: List of assignee identifiers
    :type x_opencti_assignee_ids: list
    :param external_references: List of external references
    :type external_references: list
    """

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
    """Custom STIX2 Hostname observable for OpenCTI.

    Represents a hostname cyber observable with its associated value.

    :param value: The hostname value (required)
    :type value: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param object_marking_refs: List of marking definition references
    :type object_marking_refs: list
    """

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
    """Custom STIX2 Text observable for OpenCTI.

    Represents a generic text cyber observable with its associated value.

    :param value: The text value (required)
    :type value: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param object_marking_refs: List of marking definition references
    :type object_marking_refs: list
    """

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
    """Custom STIX2 Payment Card observable for OpenCTI.

    Represents a payment card cyber observable with card details.

    :param value: Display value for the payment card (required)
    :type value: str
    :param card_number: The payment card number (required)
    :type card_number: str
    :param expiration_date: Card expiration date
    :type expiration_date: str
    :param cvv: Card verification value
    :type cvv: str
    :param holder_name: Name of the card holder
    :type holder_name: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param object_marking_refs: List of marking definition references
    :type object_marking_refs: list
    """

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
    """Custom STIX2 Bank Account observable for OpenCTI.

    Represents a bank account cyber observable with account details.

    :param value: Display value for the bank account (required)
    :type value: str
    :param iban: International Bank Account Number (required)
    :type iban: str
    :param bic: Bank Identifier Code
    :type bic: str
    :param account_number: Bank account number
    :type account_number: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param object_marking_refs: List of marking definition references
    :type object_marking_refs: list
    """

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
    """Custom STIX2 Credential observable for OpenCTI.

    Represents a credential cyber observable such as a password or access token.

    :param value: The credential value (required)
    :type value: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param object_marking_refs: List of marking definition references
    :type object_marking_refs: list
    """

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
    """Custom STIX2 Cryptocurrency Wallet observable for OpenCTI.

    Represents a cryptocurrency wallet address cyber observable.

    :param value: The wallet address value (required)
    :type value: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param object_marking_refs: List of marking definition references
    :type object_marking_refs: list
    """

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
    """Custom STIX2 Phone Number observable for OpenCTI.

    Represents a phone number cyber observable.

    :param value: The phone number value (required)
    :type value: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param object_marking_refs: List of marking definition references
    :type object_marking_refs: list
    """

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
    """Custom STIX2 Tracking Number observable for OpenCTI.

    Represents a tracking number cyber observable (e.g., package tracking).

    :param value: The tracking number value (required)
    :type value: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param object_marking_refs: List of marking definition references
    :type object_marking_refs: list
    """

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
    """Custom STIX2 User-Agent observable for OpenCTI.

    Represents a User-Agent string cyber observable from HTTP headers.

    :param value: The User-Agent string value (required)
    :type value: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param object_marking_refs: List of marking definition references
    :type object_marking_refs: list
    """

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
    """Custom STIX2 Media-Content observable for OpenCTI.

    Represents a media content cyber observable such as articles or posts.

    :param title: Title of the media content
    :type title: str
    :param description: Description of the media content
    :type description: str
    :param content: The actual content body
    :type content: str
    :param media_category: Category of the media
    :type media_category: str
    :param url: URL of the media content (required)
    :type url: str
    :param publication_date: Publication date timestamp
    :type publication_date: datetime
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param object_marking_refs: List of marking definition references
    :type object_marking_refs: list
    """

    pass


@CustomObservable(
    "persona",
    [
        ("persona_name", StringProperty(required=True)),
        ("persona_type", StringProperty(required=True)),
        ("spec_version", StringProperty(fixed="2.1")),
        (
            "object_marking_refs",
            ListProperty(
                ReferenceProperty(valid_types="marking-definition", spec_version="2.1")
            ),
        ),
    ],
    ["persona_name", "persona_type"],
)
class CustomObservablePersona:
    """Custom STIX2 Persona observable for OpenCTI.

    Represents a persona or online identity cyber observable.

    :param persona_name: Name of the persona (required)
    :type persona_name: str
    :param persona_type: Type of the persona (required)
    :type persona_type: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param object_marking_refs: List of marking definition references
    :type object_marking_refs: list
    """

    pass


@CustomObservable(
    "cryptographic-key",
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
class CustomObservableCryptographicKey:
    """Custom STIX2 Cryptographic-Key observable for OpenCTI.

    Represents a cryptographic key cyber observable such as API keys or encryption keys.

    :param value: The cryptographic key value (required)
    :type value: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param object_marking_refs: List of marking definition references
    :type object_marking_refs: list
    """

    pass


@CustomObservable(
    "ssh-key",
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
class CustomObservableSshKey:
    """Custom STIX2 SSH-Key observable for OpenCTI.

    Represents an SSH key cyber observable such as public or private SSH keys.

    :param value: The SSH key value (required)
    :type value: str
    :param spec_version: STIX specification version, fixed to "2.1"
    :type spec_version: str
    :param object_marking_refs: List of marking definition references
    :type object_marking_refs: list
    """

    pass
