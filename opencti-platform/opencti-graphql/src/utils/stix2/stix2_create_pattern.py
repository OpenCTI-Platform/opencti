import sys
import json

from stix2 import ObjectPath, EqualityComparisonExpression, ObservationExpression

OPENCTISTIX2 = {
    'autonomous-system': {'type': 'autonomous-system', 'path': ['number'], 'transform': {'operation': 'remove_string', 'value': 'AS'}},
    'mac-addr': {'type': 'mac-addr', 'path': ['value']},
    'domain': {'type': 'domain-name', 'path': ['value']},
    'ipv4-addr': {'type': 'ipv4-addr', 'path': ['value']},
    'ipv6-addr': {'type': 'ipv6-addr', 'path': ['value']},
    'url': {'type': 'url', 'path': ['value']},
    'email-address': {'type': 'email-addr', 'path': ['value']},
    'email-subject': {'type': 'email-message', 'path': ['subject']},
    'mutex': {'type': 'mutex', 'path': ['name']},
    'file-name': {'type': 'file', 'path': ['name']},
    'file-path': {'type': 'file', 'path': ['name']},
    'file-md5': {'type': 'file', 'path': ['hashes', 'MD5']},
    'file-sha1': {'type': 'file', 'path': ['hashes', 'SHA1']},
    'file-sha256': {'type': 'file', 'path': ['hashes', 'SHA256']},
    'directory': {'type': 'directory', 'path': ['path']},
    'registry-key': {'type': 'windows-registry-key', 'path': ['key']},
    'registry-key-value': {'type': 'windows-registry-value-type', 'path': ['data']},
    'pdb-path': {'type': 'file', 'path': ['name']},
    'windows-service-name': {'type': 'windows-service-ext', 'path': ['service_name']},
    'windows-service-display-name': {'type': 'windows-service-ext', 'path': ['display_name']},
    'x509-certificate-issuer': {'type': 'x509-certificate', 'path': ['issuer']},
    'x509-certificate-serial-number': {'type': 'x509-certificate', 'path': ['serial_number']}
}


def return_data(data):
    print(json.dumps(data))
    sys.stdout.flush()
    exit(0)


def main():
    if len(sys.argv) <= 2:
        return_data({'status': 'error', 'message': 'Missing argument to the Python script'})

    if sys.argv[1] == 'check':
        return_data({'status': 'success'})

    observable_type = sys.argv[1]
    observable_value = sys.argv[2]
    if observable_type in OPENCTISTIX2:
        if 'transform' in OPENCTISTIX2[observable_type]:
            if OPENCTISTIX2[observable_type]['transform']['operation'] == 'remove_string':
                observable_value = observable_value.replace(OPENCTISTIX2[observable_type]['transform']['value'], '')

        lhs = ObjectPath(OPENCTISTIX2[observable_type]['type'], OPENCTISTIX2[observable_type]['path'])
        ece = ObservationExpression(EqualityComparisonExpression(lhs, observable_value))
        return_data({'status': 'success', 'data': str(ece)})
    else:
        return_data({'status': 'unknown', 'data': None})


if __name__ == "__main__":
    main()
