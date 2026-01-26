import sys

from stix2 import (
    EqualityComparisonExpression,
    ObjectPath,
    ObservationExpression,
    OrBooleanExpression,
)
from stix2patterns.validator import run_validator

from utils.runtime_utils import return_data

PATTERN_MAPPING = {
    "Autonomous-System": ["number"],
    "Directory": ["path"],
    "Domain-Name": ["value"],
    "Email-Addr": ["value"],
    "Email-Message_body": ["body"],
    "Email-Message_subject": ["subject"],
    "Email-Mime-Part-Type": ["body"],
    "File_name": ["name"],
    "File_md5": ["hashes", "MD5"],
    "File_sha1": ["hashes", "SHA-1"],
    "File_sha256": ["hashes", "SHA-256"],
    "File_sha512": ["hashes", "SHA-512"],
    "IPv4-Addr": ["value"],
    "IPv6-Addr": ["value"],
    "Mac-Addr": ["value"],
    "Mutex": ["name"],
    "Text": ["value"],
    "Hostname": ["value"],
    "Network-Traffic": ["dst_port"],
    "Process": ["command_line"],
    "Process_pid": ["pid"],
    "Software": ["name"],
    "Url": ["value"],
    "Cryptographic-Key": ["value"],
    "Cryptocurrency-Wallet": ["value"],
    "User-Account": ["account_login"],
    "User-Agent": ["value"],
    "Windows-Registry-Key": ["key"],
    "Windows-Registry-Value-Type": ["name"],
    "Bank-Account": ["iban"],
    "Phone-Number": ["value"],
    "Tracking-Number": ["value"],
    "Credential": ["value"],
    "Payment-Card": ["card_number"],
    "Media-Content": ["url"],
    "Persona": ["persona_name", "persona_type"],
    "X509-Certificate_md5": ["hashes", "MD5"],
    "X509-Certificate_sha1": ["hashes", "SHA-1"],
    "X509-Certificate_sha256": ["hashes", "SHA-256"],
    "X509-Certificate_sha512": ["hashes", "SHA-512"],
    "X509-Certificate_subject": ["subject"],
    "X509-Certificate_issuer": ["issuer"],
    "SSH-Key_sha256": ["fingerprint_sha256"],
    "SSH-Key_md5": ["fingerprint_MD5"],
    "IMEI": ["value"],
    "ICCID": ["value"],
    "IMSI": ["value"]
}


def generate_part(observable_type, observable_value):
    if observable_type in PATTERN_MAPPING:
        lhs = ObjectPath(
            (
                observable_type.lower()
                if "_" not in observable_type
                else observable_type.split("_")[0].lower()
            ),
            PATTERN_MAPPING[observable_type],
        )
        return EqualityComparisonExpression(lhs, observable_value)
    return None


def stix2_create_pattern(observable_type, observable_value):
    if observable_type == "check":
        return {"status": "success", "data": "check"}
    pattern = None
    if "__" in observable_type:
        observable_types = observable_type.split("__")
        observable_values = observable_value.split("__")
        length = len(observable_types)
        parts = []
        for i in range(length):
            part = generate_part(observable_types[i], observable_values[i])
            if part is not None:
                parts.append(part)
        if len(parts) > 0:
            pattern = ObservationExpression(OrBooleanExpression(parts))
    else:
        ece = generate_part(observable_type, observable_value)
        if ece is not None:
            pattern = ObservationExpression(ece)
    if pattern is not None:
        errors = run_validator(str(pattern))
        if len(errors) > 0:
            return {
                "status": "error",
                "message": "Invalid generated pattern",
                "errors": errors,
            }
        else:
            return {"status": "success", "data": str(pattern)}
    else:
        errors = [{"FAIL": f"Cant process type {observable_type}"}]
        return {
            "status": "unknown",
            "message": "Cant generate pattern",
            "errors": errors,
        }


if __name__ == "__main__":
    if len(sys.argv) <= 2:
        return_data(
            {
                "status": "error",
                "message": "Missing argument to the Python script",
                "errors": [],
            }
        )

    data = stix2_create_pattern(sys.argv[1], sys.argv[2])
    return_data(data)
