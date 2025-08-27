import base64
import datetime
import json
import threading
from dataclasses import dataclass
from typing import Any, Dict, Union, Literal

import pika
from pycti import OpenCTIApiClient, OpenCTIStix2Splitter


@dataclass(unsafe_hash=True)
class PushHandler:  # pylint: disable=too-many-instance-attributes
    logger: Any
    log_level: str
    json_logging: bool
    opencti_url: str
    opencti_token: str
    ssl_verify: Union[bool, str]
    push_exchange: str
    push_routing: str
    pika_parameters: pika.ConnectionParameters
    bundles_global_counter: Any
    bundles_processing_time_gauge: Any

    def __post_init__(self) -> None:
        self.local_api = threading.local()

    # OpenCTIClient is not thread safe, use a thread local to ensure to work on a dedicated client when creating and sending a request
    def get_api_client(self) -> OpenCTIApiClient:
        if not hasattr(self.local_api, "client"):
            self.local_api.client = OpenCTIApiClient(
                url=self.opencti_url,
                token=self.opencti_token,
                log_level=self.log_level,
                json_logging=self.json_logging,
                ssl_verify=self.ssl_verify,
        )
        return self.local_api.client

    def handle_message(
            self,
            body: str,
    ) -> Literal["ack", "nack", "requeue"]:
        try:
            data: Dict[str, Any] = json.loads(body)
        except Exception as e:
            self.logger.error(
                "Could not process message",
                {"body": body, "exception": e},
            )
            # Nack message, no requeue for this unprocessed message
            return "nack"

        imported_items = []
        start_processing = datetime.datetime.now()
        try:
            api = self.get_api_client()
            # Set the API headers
            api.set_applicant_id_header(data.get("applicant_id"))
            api.set_playbook_id_header(data.get("playbook_id"))
            api.set_event_id(data.get("event_id"))
            api.set_draft_id(data.get("draft_id"))
            api.set_synchronized_upsert_header(data.get("synchronized", False))
            api.set_previous_standard_header(data.get("previous_standard"))

            # Execute the import
            work_id = data.get("work_id")
            types = (
                data["entities_types"]
                if "entities_types" in data and len(data["entities_types"]) > 0
                else None
            )
            raw_content = base64.b64decode(data["content"]).decode("utf-8")
            content = json.loads(raw_content)
            event_type = data.get("type", "bundle")
            if event_type == "bundle":
                # Event type bundle
                # Standard event with STIX information
                if "objects" not in content or len(content["objects"]) == 0:
                    raise ValueError("JSON data type is not a STIX2 bundle")
                if len(content["objects"]) == 1 or data.get("no_split", False):
                    update = data.get("update", False)
                    imported_items = api.stix2.import_bundle_from_json(
                        raw_content, update, types, work_id
                    )
                else:
                    # As bundle is received as complete, split and requeue
                    # Create a specific channel to push the split bundles
                    with pika.BlockingConnection(self.pika_parameters) as push_pika_connection:
                        with push_pika_connection.channel() as push_channel:
                            try:
                                push_channel.confirm_delivery()
                            except Exception as err:  # pylint: disable=broad-except
                                self.logger.warning(str(err))
                            # Instance spliter and split the big bundle
                            event_version = content.get("x_opencti_event_version")
                            stix2_splitter = OpenCTIStix2Splitter()
                            expectations, _, bundles = (
                                stix2_splitter.split_bundle_with_expectations(
                                    content, False, event_version
                                )
                            )
                            # Add expectations to the work
                            if work_id is not None:
                                api.work.add_expectations(work_id, expectations)
                            # For each split bundle, send it to the same queue
                            for bundle in bundles:
                                text_bundle = json.dumps(bundle)
                                data["content"] = base64.b64encode(
                                    text_bundle.encode("utf-8", "escape")
                                ).decode("utf-8")
                                push_channel.basic_publish(
                                    exchange=self.push_exchange,
                                    routing_key=self.push_routing,
                                    body=json.dumps(data),
                                    properties=pika.BasicProperties(
                                        delivery_mode=2,
                                        content_encoding="utf-8",  # make message persistent
                                    ),
                                )
            # Event type event
            # Specific OpenCTI event operation with specific operation
            elif event_type == "event":
                match content["type"]:
                    # Standard knowledge
                    case "create" | "update":
                        bundle = {
                            "type": "bundle",
                            "objects": [content["data"]],
                        }
                        imported_items = api.stix2.import_bundle(
                            bundle, True, types, work_id
                        )
                    # Specific knowledge merge
                    case "merge":
                        # Start with a merge
                        target_id = content["data"]["id"]
                        source_ids = list(
                            map(
                                lambda source: source["id"],
                                content["context"]["sources"],
                            )
                        )
                        merge_object = content["data"]
                        merge_object["opencti_operation"] = event_type
                        merge_object["merge_target_id"] = target_id
                        merge_object["merge_source_ids"] = source_ids
                        bundle = {
                            "type": "bundle",
                            "objects": [merge_object],
                        }
                        imported_items = api.stix2.import_bundle(
                            bundle, True, types, work_id
                        )
                    # All standard operations
                    case (
                    "delete"  # Standard delete
                    | "restore"  # Restore an operation from trash
                    | "delete_force"  # Delete with no trash
                    | "share"  # Share an element
                    | "unshare"  # Unshare an element
                    | "rule_apply"  # Applying a rule (start engine)
                    | "rule_clear"  # Clearing a rule (stop engine)
                    | "rules_rescan"  # Rescan a rule (massive operation in UI)
                    | "enrichment"  # Ask for enrichment (massive operation in UI)
                    | "clear_access_restriction"  # Clear access members (massive operation in UI)
                    | "revert_draft"  # Cancel draft modification (massive operation in UI)
                    ):
                        data_object = content["data"]
                        data_object["opencti_operation"] = event_type
                        bundle = {
                            "type": "bundle",
                            "objects": [data_object],
                        }
                        imported_items = api.stix2.import_bundle(
                            bundle, True, types, work_id
                        )
                    case _:
                        raise ValueError(
                            "Unsupported operation type", {"event_type": event_type}
                        )
            else:
                raise ValueError("Unsupported event type", {"event_type": event_type})

            return "ack"
        except Exception as ex:
            # Technical unmanaged exception
            self.logger.error(
                "Error executing data handling", {"reason": str(ex)}
            )
            # Nack message and discard
            return "nack"
        finally:
            self.bundles_global_counter.add(len(imported_items))
            processing_delta = datetime.datetime.now() - start_processing
            self.bundles_processing_time_gauge.record(processing_delta.seconds)
