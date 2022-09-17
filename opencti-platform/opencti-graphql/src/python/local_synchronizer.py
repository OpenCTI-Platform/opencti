import json
import logging
import os
import sys
import jsonpatch

from pycti import OpenCTIApiClient, OpenCTIConnectorHelper


# pylint: disable-next=too-few-public-methods
# pylint: disable-next=too-many-instance-attributes
class TestLocalSynchronizer:
    def __init__(  # pylint: disable=too-many-arguments
        self,
        source_url,
        source_token,
        target_url,
        target_token,
        consuming_count,
        start_timestamp,
        recover_timestamp,
        live_stream_id=None,
    ):
        self.source_url = source_url
        self.source_token = source_token
        self.target_url = target_url
        self.target_token = target_token
        self.live_stream_id = live_stream_id
        self.count_number = 0
        self.consuming_count = consuming_count
        self.start_timestamp = start_timestamp
        self.recover_timestamp = recover_timestamp
        self.stream = None
        # Source
        config = {
            "id": "673ba380-d229-4160-9213-ac5afdaabf96",
            "type": "STREAM",
            "name": "Synchronizer",
            "scope": "synchronizer",
            "confidence_level": 15,
            "live_stream_id": self.live_stream_id,
            "log_level": "info",
        }
        self.opencti_source_client = OpenCTIApiClient(source_url, source_token)
        self.opencti_source_helper = OpenCTIConnectorHelper(
            {
                "opencti": {"url": self.source_url, "token": self.source_token},
                "connector": config,
            }
        )
        # Target
        self.opencti_target_client = OpenCTIApiClient(target_url, target_token)
        self.opencti_target_helper = OpenCTIConnectorHelper(
            {
                "opencti": {"url": self.target_url, "token": self.target_token},
                "connector": config,
            }
        )

    def _process_message(self, msg):
        if msg.event in ("create", "update", "merge", "delete"):
            logging.info("%s", f"Processing event {msg.id}")
            self.count_number += 1
            data = json.loads(msg.data)
            if msg.event == "create":
                bundle = {
                    "type": "bundle",
                    "x_opencti_event_version": data["version"],
                    "objects": [data["data"]],
                }
                self.opencti_target_client.stix2.import_bundle(bundle)
            elif msg.event == "update":
                previous = jsonpatch.apply_patch(
                    data["data"], data["context"]["reverse_patch"]
                )
                current = data["data"]
                # In case of update always apply operation to the previous id
                current["id"] = previous["id"]
                bundle = {
                    "type": "bundle",
                    "x_opencti_event_version": data["version"],
                    "objects": [current],
                }
                self.opencti_target_client.stix2.import_bundle(bundle, True)
            elif msg.event == "merge":
                sources = data["context"]["sources"]
                object_ids = list(map(lambda element: element["id"], sources))
                self.opencti_target_helper.api.stix_core_object.merge(
                    id=data["data"]["id"], object_ids=object_ids
                )
            elif msg.event == "delete":
                self.opencti_target_helper.api.stix.delete(id=data["data"]["id"])
            if self.count_number >= self.consuming_count:
                self.stream.stop()

    def sync(self):
        # Reset the connector state if exists
        self.opencti_source_helper.set_state(None)
        # Start to listen the stream from start specified parameter
        self.stream = self.opencti_source_helper.listen_stream(
            self._process_message,
            self.source_url,
            self.source_token,
            False,
            self.start_timestamp,
            self.live_stream_id,
            True,
            False,
            self.recover_timestamp,
        )
        self.stream.join()


if __name__ == "__main__":
    try:
        TestLocalSynchronizer(
            source_url=sys.argv[1],
            source_token=sys.argv[2],
            target_url=sys.argv[3],
            target_token=sys.argv[4],
            consuming_count=int(sys.argv[5]),
            start_timestamp=sys.argv[6],
            recover_timestamp=sys.argv[7] if len(sys.argv) > 7 else None,
            live_stream_id=sys.argv[8] if len(sys.argv) > 8 else None,
        ).sync()
        os._exit(0)  # pylint: disable=protected-access
    except Exception as e:  # pylint: disable=broad-except
        logging.exception(str(e))
        sys.exit(1)
