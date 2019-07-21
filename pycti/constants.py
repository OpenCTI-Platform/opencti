"""These are the custom STIX properties and observation types used internally by OpenCTI.

"""


class ObservableTypes:
    """These are the possible values for OpenCTI's observable types.

    Use in conjuction with the STIX custom property 'x_opencti_observable_type'.

    ref: https://github.com/OpenCTI-Platform/opencti/blob/8854c2576dc17da9da54e54b116779bd2131617c/opencti-front/src/private/components/report/ReportAddObservable.js

    NOTE: should this be a mapping between the stix2 SDO objects (i.e. stix2/v20/sdo.py)?

    """
    DOMAIN = "Domain"
    EMAIL_ADDR = "Email-Address"
    EMAIL_SUBJECT = "Email-Subject"
    FILE_NAME = "File-Name"
    FILE_PATH = "File-Path"
    FILE_HASH_MD5 = "File-MD5"
    FILE_HASH_SHA1 = "File-SHA1"
    FILE_HASH_SHA256 = "File-SHA256"
    IPV4_ADDR = "IPv4-Addr"
    IPV6_ADDR = "IPv6-Addr"
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


class CustomProperties:
    """These are the custom properies used by OpenCTI.

    """

    # internal id used by OpenCTI - this will be auto generated
    ID = 'x_opencti_id'

    # This should be set on all reports to one of the following values:
    #  "external"
    #  "internal"
    REPORT_CLASS = 'x_opencti_report_class'

    # These values should be set on all stix Indicator objects as custom properties.
    # See constants.ObservableTypes for possible types
    OBSERVABLE_TYPE = 'x_opencti_observable_type'
    OBSERVABLE_VALUE = 'x_opencti_observable_value'

    # custom created and modified dates
    # use with STIX "kill chain" and "external reference" objects
    CREATED = 'x_opencti_created'
    MODIFIED = 'x_opencti_modified'

    # use with intrusion-set, campaign, relation
    FIRST_SEEN = 'x_opencti_first_seen'
    LAST_SEEN = 'x_opencti_last_seen'

    # use with marking deinitions
    COLOR = 'x_opencti_color'
    LEVEL = 'x_opencti_level'  # should be an integer

    # use with kill chain
    PHASE_ORDER = 'x_opencti_phase_order'

    # use with relation
    WEIGHT = 'x_opencti_weight'
    SCORE = 'x_opencti_score'
    ROLE_PLAYED = 'x_opencti_role_played'
    EXPIRATION = 'x_opencti_expiration'
    SOURCE_REF = 'x_opencti_source_ref'
    TARGET_REF = 'x_opencti_target_ref'

    # generic property - applies to most SDOs
    ALIASES = 'x_opencti_aliases'

    # applies to STIX Identity
    ORG_CLASS = 'x_opencti_organization_class'
    IDENTITY_TYPE = 'x_opencti_identity_type'  # this overrides the stix 'identity_class' property!

    # applies to STIX report
    OBJECT_STATUS = 'x_opencti_object_status'
    SRC_CONF_LEVEL = 'x_opencti_source_confidence_level'
    GRAPH_DATA = 'x_opencti_graph_data'
