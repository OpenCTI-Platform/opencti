import json
import logging
import os
import sys

import jsonpatch
from pycti import OpenCTIApiClient, OpenCTIConnectorHelper

OPENCTI_EXTENSION = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


def _octi_extension(stix_object):
    return stix_object.get("extensions", {}).get(OPENCTI_EXTENSION, {})


# Multi-valued attributes an upsert only adds to, by upsert key: identity (alternative
# standard ids, aliases) and access restrictions (markings, organization sharing)
REMOVABLE_FIELDS = {
    "x_opencti_stix_ids": lambda stix_object: _octi_extension(stix_object).get(
        "stix_ids"
    ),
    "aliases": lambda stix_object: stix_object.get("aliases"),
    "x_opencti_aliases": lambda stix_object: _octi_extension(stix_object).get(
        "aliases"
    ),
    "objectMarking": lambda stix_object: stix_object.get("object_marking_refs"),
    "objectOrganization": lambda stix_object: _octi_extension(stix_object).get(
        "granted_refs"
    ),
}


def _merge_operations(carried, removals):
    # The operations the event carries are kept; a removal for the same key removes both lists
    operations = [dict(operation) for operation in carried]
    for removal in removals:
        same = next(
            (
                operation
                for operation in operations
                if operation.get("operation") == "remove"
                and operation.get("key") == removal["key"]
            ),
            None,
        )
        if same is None:
            operations.append(removal)
        else:
            carried_values = same.get("value")
            values = carried_values if isinstance(carried_values, list) else []
            same["value"] = list(dict.fromkeys([*values, *removal["value"]]))
    return operations


def _upsert_removals(previous, current):
    removals = []
    for upsert_key, read in REMOVABLE_FIELDS.items():
        current_values = read(current) or []
        removed_values = [
            value for value in (read(previous) or []) if value not in current_values
        ]
        if removed_values:
            removals.append(
                {"key": upsert_key, "value": removed_values, "operation": "remove"}
            )
    return removals


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
            type = data["data"]["type"]
            if type == "internal-relationship":
                return
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
                # An upsert only adds these values: the ones the update removed are removed explicitly
                removals = _upsert_removals(previous, current)
                if removals:
                    extension = current.setdefault("extensions", {}).setdefault(
                        OPENCTI_EXTENSION, {}
                    )
                    extension["opencti_upsert_operations"] = _merge_operations(
                        extension.get("opencti_upsert_operations") or [], removals
                    )
                bundle = {
                    "type": "bundle",
                    "x_opencti_event_version": data["version"],
                    "objects": [current],
                }
                self.opencti_target_client.stix2.import_bundle(bundle, True)
            elif msg.event == "merge":
                sources = data["context"]["sources"]
                object_ids = list(map(lambda element: element["id"], sources))
                self.opencti_target_helper.api.stix.merge(
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
