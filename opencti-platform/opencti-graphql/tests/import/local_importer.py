import os

from pycti.api.opencti_api_client import OpenCTIApiClient


class TestLocalImporter:

    def __init__(self):
        self.api_url = "http://localhost:4000"
        self.api_token = "bfa014e0-e02e-4aa6-a42b-603b19dcf159"
        self.config_file_path = os.path.dirname(os.path.abspath(__file__)) + '/CERTFR-2020-CTI-001-STIX2_v2.json'

    def inject(self):
        opencti_api_client = OpenCTIApiClient(self.api_url, self.api_token)
        opencti_api_client.stix2_import_bundle_from_file(self.config_file_path)


if __name__ == '__main__':
    try:
        testLocalImporter = TestLocalImporter()
        testLocalImporter.inject()
    except Exception as e:
        print(e)
        exit(0)
