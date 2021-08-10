import json
import logging
import sys

from pycti import OpenCTIConnectorHelper, OpenCTIApiClient


class TestLocalSynchronizer:
    def __init__(self, api_url, api_token):
        self.api_url = api_url
        self.api_token = api_token
        self.opencti_api_client = OpenCTIApiClient(api_url, api_token)
        config = {
            'opencti': {
                'url': self.api_url,
                'token': self.api_token
            },
            'connector': {
                'id': '673ba380-d229-4160-9213-ac5afdaabf96',
                'type': 'STREAM',
                'name': 'Synchronizer',
                'scope': 'synchronizer',
                'confidence_level': 15,
                'log_level': 'info'
            }
        }
        self.helper = OpenCTIConnectorHelper(config)

    def _process_message(self, msg):
        if msg.event == "create" or msg.event == "update" or msg.event == "merge" or msg.event == "delete":
            logging.info("Processing event " + msg.id)
            data = json.loads(msg.data)
            if msg.event == "create":
                bundle = {"type": "bundle", "x_opencti_event_version": data["version"], "objects": [data["data"]]}
                self.opencti_api_client.stix2.import_bundle(bundle)
            elif msg.event == "update":
                bundle = {"type": "bundle", "x_opencti_event_version": data["version"], "objects": [data["data"]]}
                self.opencti_api_client.stix2.import_bundle(bundle, True)
            elif msg.event == "merge":
                sources = data["data"]["x_opencti_context"]["sources"]
                object_ids = list(map(lambda element: element["id"], sources))
                self.helper.api.stix_core_object.merge(id=data["data"]["id"], object_ids=object_ids)
            elif msg.event == "delete":
                self.helper.api.stix.delete(id=data["data"]["id"])

    def sync(self):
        self.helper.listen_stream(self._process_message, self.api_url, self.api_token, False, '0')


if __name__ == "__main__":
    try:
        api_url = sys.argv[1]
        api_token = sys.argv[2]

        testLocalSynchronizer = TestLocalSynchronizer(api_url, api_token)
        testLocalSynchronizer.sync()
    except Exception as e:
        logging.exception(str(e))
        exit(1)
