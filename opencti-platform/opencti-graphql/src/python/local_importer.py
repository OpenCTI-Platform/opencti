import logging
import os
import sys

from pycti.api.opencti_api_client import OpenCTIApiClient


class TestLocalImporter:  # pylint: disable=too-few-public-methods
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
        TestLocalImporter(
            api_url=sys.argv[1],
            api_token=sys.argv[2],
            config_file_path=os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "../..",
                sys.argv[3].lstrip(os.path.sep),
            ),
        ).inject()
    except Exception as e:  # pylint: disable=broad-except
        logging.exception(str(e))
        sys.exit(1)
