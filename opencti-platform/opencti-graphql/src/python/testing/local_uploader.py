import json
import logging
import sys

from pycti.api.opencti_api_client import OpenCTIApiClient


class TestLocalExporter:
    def __init__(self, api_url, api_token, entity_id, file_name, file_markings):
        self.api_url = api_url
        self.api_token = api_token
        self.entity_id = entity_id
        self.file_name = file_name
        self.file_markings = file_markings

    def upload(self):
        opencti_api_client = OpenCTIApiClient(self.api_url, self.api_token)

        # Upload the given file to the entity
        opencti_api_client.stix_domain_object.add_file(
            id=self.entity_id,
            file_name=self.file_name,
            file_markings=self.file_markings,
        )

if __name__ == "__main__":
    try:
        TestLocalExporter(
            api_url=sys.argv[1],
            api_token=sys.argv[2],
            entity_id=sys.argv[3],
            file_name=sys.argv[4],
            file_markings=sys.argv[5],
        ).upload()
    except Exception as e:  # pylint: disable=broad-except
        logging.exception(str(e))
        sys.exit(1)
