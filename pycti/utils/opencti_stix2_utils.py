import uuid
from stix2 import (
    ObjectPath,
    EqualityComparisonExpression,
    ObservationExpression,
    CustomObservable,
    ExternalReference,
    properties,
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
}


class OpenCTIStix2Utils:
    @staticmethod
    def create_stix_pattern(observable_type, observable_value):
        if observable_type in PATTERN_MAPPING:
            lhs = ObjectPath(
                observable_type.lower()
                if "_" not in observable_type
                else observable_type.split("_")[0].lower(),
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
        new_uuid = str(uuid.uuid1())
        return stix_type + "--" + new_uuid


@CustomObservable(
    "x-opencti-simple-observable",
    [
        ("key", properties.StringProperty(required=True)),
        ("value", properties.StringProperty(required=True)),
        ("description", properties.StringProperty()),
        (
            "created_by_ref",
            properties.ReferenceProperty(valid_types="identity", spec_version="2.1"),
        ),
        ("x_opencti_score", properties.IntegerProperty()),
        ("x_opencti_create_indicator", properties.BooleanProperty()),
        ("labels", properties.ListProperty(properties.StringProperty)),
        ("external_references", properties.ListProperty(ExternalReference)),
        (
            "object_marking_refs",
            properties.ListProperty(
                properties.ReferenceProperty(
                    valid_types="marking-definition", spec_version="2.1"
                )
            ),
        ),
    ],
)
class SimpleObservable:
    pass
