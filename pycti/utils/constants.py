"""These are the custom STIX properties and observation types used internally by OpenCTI.

"""
from enum import Enum


class ObservableTypes(Enum):
    """These are the possible values for OpenCTI's observable types.

    Use in conjunction with the STIX custom property `x_opencti_observable_type`.

    ref: https://github.com/OpenCTI-Platform/opencti/blob/8854c2576dc17da9da54e54b116779bd2131617c/opencti-front/src/private/components/report/ReportAddObservable.js

    NOTE: should this be a mapping between the stix2 SDO objects (i.e. stix2/v20/sdo.py)?
    """

    AUTONOMOUS_SYSTEM = "Autonomous-System"
    DOMAIN = "Domain"
    EMAIL_ADDR = "Email-Address"
    EMAIL_SUBJECT = "Email-Subject"
    DIRECTORY = "Directory"
    FILE_NAME = "File-Name"
    FILE_PATH = "File-Path"
    FILE_HASH_MD5 = "File-MD5"
    FILE_HASH_SHA1 = "File-SHA1"
    FILE_HASH_SHA256 = "File-SHA256"
    IPV4_ADDR = "IPv4-Addr"
    IPV6_ADDR = "IPv6-Addr"
    MAC_ADDR = "Mac-Addr"
    MUTEX = "Mutex"
    PDB_PATH = "PDB-Path"
    REGISTRY_KEY = "Registry-Key"
    REGISTRY_VALUE = "Registry-Key-Value"
    URL = "URL"
    WIN_SERVICE_NAME = "Windows-Service-Name"
    WIN_SERVICE_DISPLAY = "Windows-Service-Display-Name"
    WIN_SCHEDULED_TASK = "Windows-Scheduled-Task"
    X509_CERT_ISSUER = "X509-Certificate-Issuer"
    X509_CERT_SN = "X509-Certificate-Serial-Number"

    @classmethod
    def has_value(cls, value):
        lower_attr = list(map(lambda x: x.lower(), cls._value2member_map_))
        return value in lower_attr


class IdentityTypes(Enum):
    SECTOR = "Sector"
    REGION = "Region"
    COUNTRY = "Country"
    CITY = "City"
    ORGANIZATION = "Organization"
    USER = "User"

    @classmethod
    def has_value(cls, value):
        lower_attr = list(map(lambda x: x.lower(), cls._value2member_map_))
        return value in lower_attr


class StixObservableRelationTypes(Enum):
    LINKED = "linked"
    RESOLVES = "resolves"
    BELONGS = "belongs"
    CONTAINS = "contains"
    CORRESPONDS = "corresponds"

    @classmethod
    def has_value(cls, value):
        lower_attr = list(map(lambda x: x.lower(), cls._value2member_map_))
        return value in lower_attr


class CustomProperties:
    """These are the custom properties used by OpenCTI.
    """

    # internal id used by OpenCTI - this will be auto generated
    ID = "x_opencti_id"

    # List of files
    FILES = "x_opencti_files"

    # This should be set on all reports to one of the following values:
    #  "external"
    #  "internal"
    REPORT_CLASS = "x_opencti_report_class"

    # use with observed_data and indicators
    INDICATOR_PATTERN = "x_opencti_indicator_pattern"
    PATTERN_TYPE = "x_opencti_pattern_type"
    OBSERVABLE_TYPE = "x_opencti_observable_type"
    OBSERVABLE_VALUE = "x_opencti_observable_value"
    DETECTION = "x_opencti_detection"
    CREATE_OBSERVABLES = "x_opencti_observables_create"
    CREATE_INDICATOR = "x_opencti_indicator_create"

    # custom created and modified dates
    # use with STIX "kill chain" and "external reference" objects
    CREATED = "x_opencti_created"
    MODIFIED = "x_opencti_modified"

    # use with attack pattern
    EXTERNAL_ID = "x_opencti_external_id"

    # use with vulnerability
    BASE_SCORE = "x_opencti_base_score"
    BASE_SEVERITY = "x_opencti_base_severity"
    ATTACK_VECTOR = "x_opencti_attack_vector"
    INTEGRITY_IMPACT = "x_opencti_integrity_impact"
    AVAILABILITY_IMPACT = "x_opencti_availability_impact"

    # use with intrusion-set, campaign, relation
    FIRST_SEEN = "x_opencti_first_seen"
    LAST_SEEN = "x_opencti_last_seen"

    # use with marking definitions
    COLOR = "x_opencti_color"
    LEVEL = "x_opencti_level"  # should be an integer

    # use with kill chain
    PHASE_ORDER = "x_opencti_phase_order"

    # use with relation
    WEIGHT = "x_opencti_weight"
    SCORE = "x_opencti_score"
    ROLE_PLAYED = "x_opencti_role_played"
    EXPIRATION = "x_opencti_expiration"
    SOURCE_REF = "x_opencti_source_ref"
    TARGET_REF = "x_opencti_target_ref"
    IGNORE_DATES = "x_opencti_ignore_dates"
    NEGATIVE = "x_opencti_false_positive"

    # generic property - applies to most SDOs
    ALIASES = "x_opencti_aliases"

    # applies to STIX Identity
    ORG_CLASS = "x_opencti_organization_class"
    IDENTITY_TYPE = (
        "x_opencti_identity_type"  # this overrides the stix 'identity_class' property!
    )
    TAG_TYPE = "x_opencti_tags"

    # applies to STIX report
    OBJECT_STATUS = "x_opencti_object_status"
    SRC_CONF_LEVEL = "x_opencti_source_confidence_level"
    GRAPH_DATA = "x_opencti_graph_data"

    # applies to STIX note
    NAME = "x_opencti_name"
