import logging
import os
import sys

from pycti.api.opencti_api_client import OpenCTIApiClient


class TestLocalImporter:
    def __init__(self, api_url, api_token, config_file_path):
        self.api_url = api_url
        self.api_token = api_token
        self.config_file_path = config_file_path

    def inject(self):
        opencti_api_client = OpenCTIApiClient(self.api_url, self.api_token)
        opencti_api_client.stix2.import_bundle_from_file(
            self.config_file_path, update=True
        )


if __name__ == "__main__":
    try:
        api_url = sys.argv[1]
        api_token = sys.argv[2]
        file_path = sys.argv[3]
        config_file_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "../..", file_path
        )
        testLocalImporter = TestLocalImporter(api_url, api_token, config_file_path)
        testLocalImporter.inject()
    except Exception as e:
        logging.exception(str(e))
        exit(1)
