import sys

import stix2
from stix2.pattern_visitor import create_pattern_object

from lib.messages import MISSING_ARGUMENT
from lib.utils import return_data

PATTERN_MAPPING = {
    "directory:path": {"type": "Directory", "attribute": "value"},
    "file:hashes.'MD5'": {"type": "StixFile", "attribute": "md5"},
    "file:hashes.'SHA-1'": {"type": "StixFile", "attribute": "sha1"},
    "file:hashes.'SHA-256'": {"type": "StixFile", "attribute": "sha256"},
    "file:hashes.'SHA-512'": {"type": "StixFile", "attribute": "sha512"},
    "file:name": {"type": "StixFile", "attribute": "name"},
    "ipv4-addr:value": {"type": "IPv4-Addr", "attribute": "value"},
    "ipv6-addr:value": {"type": "IPv6-Addr", "attribute": "value"},
    "domain-name:value": {"type": "Domain-Name", "attribute": "value"},
    "url:value": {"type": "Url", "attribute": "value"},
    "email-addr:value": {"type": "Email-Addr", "attribute": "value"},
    "email-message:body": {"type": "Email-Message", "attribute": "body"},
}


def main():
    if len(sys.argv) <= 1:
        return_data(MISSING_ARGUMENT)

    if sys.argv[1] == "check":
        return_data({"status": "success"})

    observable_type = None
    observable_attribute = None
    observable_value = None
    pattern = create_pattern_object(sys.argv[1])
    if pattern.operand.operator == "=":
        # get the object type (here 'file') and check that it is a standard observable type
        object_type = pattern.operand.lhs.object_type_name
        if object_type in stix2.OBJ_MAP_OBSERVABLE:
            # get the left hand side as string and use it for looking up the correct OpenCTI name
            lhs = str(pattern.operand.lhs)
            print(lhs)
            if lhs in PATTERN_MAPPING:
                print(pattern.operand.rhs)
                # the type and value can now be set
                observable_type = PATTERN_MAPPING[lhs]["type"]
                observable_attribute = PATTERN_MAPPING[lhs]["attribute"]
                observable_value = pattern.operand.rhs.value
    if observable_type is not None and observable_value is not None:
        return_data(
            {
                "status": "success",
                "data": [
                    {
                        "type": observable_type,
                        "attribute": observable_attribute,
                        "value": observable_value,
                    }
                ],
            }
        )
    else:
        return_data({"status": "unknown", "data": None})


if __name__ == "__main__":
    main()
