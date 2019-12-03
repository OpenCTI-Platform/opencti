# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = 'https://demo.opencti.io'
api_token = '616e214c-8d86-4226-a653-c521f4ec90d9'

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# File to import
file_to_import = './enterprise-attack.json'

# Import the bundle
opencti_api_client.stix2.import_bundle_from_file(
    file_to_import,
    True,
    [
        'identity',
        'attack-pattern',
        'course-of-action',
        'intrusion-set',
        'malware',
        'tool',
        'report'
    ])