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
        # Generate a json bundle from openCTI
        bundle = opencti_api_client.stix2.get_stix_bundle_or_object_from_entity_id(
            entity_type="Malware", entity_id=self.entity_id, mode="full"
        )
        json_bundle = json.dumps(bundle, indent=4)
        # Upload the export inside the entity to ack like an import
        opencti_api_client.stix_domain_object.push_entity_export(
            entity_id=self.entity_id,
            file_name=self.file_name,
            data=json_bundle,
            file_markings=self.file_markings,
        )
        # Upload it like a simple file to import
        opencti_api_client.upload_file(file_name=self.file_name, data=json_bundle)

    def upload_list(self):
        opencti_api_client = OpenCTIApiClient(self.api_url, self.api_token)
        # Generate a json bundle from openCTI
        bundle = opencti_api_client.stix2.export_list("Malware")
        json_bundle = json.dumps(bundle, indent=4)
        # Upload the export inside the entity to ack like an import
        opencti_api_client.stix_domain_object.push_list_export(
            "Malware", self.file_name, json_bundle
        )
        # Upload it like a simple file to import
        opencti_api_client.upload_file(file_name=self.file_name, data=json_bundle)


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
