# coding: utf-8

from pycti import OpenCTIApiClient

# Variables
api_url = 'https://demo.opencti.io'
api_token = '22566f94-9091-49ba-b583-efd76cf8b29c'

# OpenCTI initialization
opencti_api_client = OpenCTIApiClient(api_url, api_token)

# Get the intrusion set APT28
intrusion_set = opencti_api_client.intrusion_set.read(filters=[{'key': 'name', 'values': ['APT28']}])

# Get all reports
reports = opencti_api_client.report.list(
    filters=[{'key': 'knowledgeContains', 'values': [intrusion_set['id']]}],
    orderBy='published',
    orderMode='asc'
)

# Print
for report in reports:
    print('[' + report['stix_id_key'] + '] ' + report['name'] + ' (' + report['published'] + ')')