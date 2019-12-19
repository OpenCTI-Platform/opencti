# coding: utf-8

from dateutil.parser import parse
from pycti import OpenCTIApiClient

# Variables
api_url = 'https://demo.opencti.io'
api_token = 'fa63eb1f-bf14-4777-9190-43b4571cbc8b'

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Create the malware
malware = opencti_api_client.malware.create(
    name='My new malware',
    description='A new evil tool.'
)

# Create the tag (if not exists)

# Add the tag

# Print
print(malware)