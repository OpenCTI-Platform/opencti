import sys
import json
import stix2

from stix2.pattern_visitor import create_pattern_object

STIX2OPENCTI = {
    'file:hashes.md5': 'File-MD5',
    'file:hashes.sha1': 'File-SHA1',
    'file:hashes.sha256': 'File-SHA256',
    'file:name': 'File-Name',
    'ipv4-addr:value': 'IPv4-Addr',
    'ipv6-addr:value': 'IPv6-Addr',
    'domain:value': 'Domain',
    'url:value': 'URL',
    'directory:value': 'Directory',
    'domain-name:value': 'Domain',
    'email-addr:value': 'Email-Address',
    'email-message:subject': 'Email-Subject'
}


def return_data(data):
    print(json.dumps(data))
    sys.stdout.flush()
    exit(0)


def main():
    if len(sys.argv) <= 1:
        return_data({'status': 'error', 'message': 'Missing argument to the Python script'})

    if sys.argv[1] == 'check':
        return_data({'status': 'success'})

    indicator_type = None
    indicator_value = None
    pattern = create_pattern_object(sys.argv[1])
    if pattern.operand.operator == '=':
        # get the object type (here 'file') and check that it is a standard observable type
        object_type = pattern.operand.lhs.object_type_name
        if object_type in stix2.OBJ_MAP_OBSERVABLE:
            # get the left hand side as string and use it for looking up the correct OpenCTI name
            lhs = str(pattern.operand.lhs).lower()  # this is "file:hashes.md5" from the reference pattern
            if lhs in STIX2OPENCTI:
                # the type and value can now be set
                indicator_type = STIX2OPENCTI[lhs]
                indicator_value = pattern.operand.rhs.value
    if indicator_type is not None and indicator_value is not None:
        return_data({'status': 'success', 'data': [{'type': indicator_type, 'value': indicator_value}]})
    else:
        return_data({'status': 'unknown', 'data': None})


if __name__ == "__main__":
    main()
