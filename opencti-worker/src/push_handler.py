import base64
import datetime
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Union

import pika
from pika.adapters.blocking_connection import BlockingChannel
from pika.exceptions import NackError, UnroutableError
from pycti import OpenCTIApiClient, OpenCTIStix2Splitter, __version__

# Objects imported together at most, whatever the number of messages they come in
MAX_GROUP_OBJECTS = 2000


@dataclass(unsafe_hash=True)
class PushHandler:  # pylint: disable=too-many-instance-attributes
    logger: Any
    log_level: str
    json_logging: bool
    opencti_url: str
    opencti_token: str
    ssl_verify: Union[bool, str]
    connector_id: str
    push_exchange: str
    listen_exchange: str
    push_routing: str
    dead_letter_routing: str
    pika_parameters: pika.ConnectionParameters
    bundles_global_counter: Any
    bundles_processing_time_gauge: Any
    objects_max_refs: int

    def __post_init__(self) -> None:
        self._batch_supported: Optional[bool] = None
        self._batch_checked_at = 0.0
        self.api = OpenCTIApiClient(
            url=self.opencti_url,
            token=self.opencti_token,
            log_level=self.log_level,
            json_logging=self.json_logging,
            ssl_verify=self.ssl_verify,
            provider="worker/" + __version__,
        )

    def send_bundle_to_specific_queue(
        self,
        push_channel: BlockingChannel,
        exchange: str,
        routing_key: str,
        data: Any,
        bundle: Any,
        is_split_bundle=False,
    ):
        text_bundle = json.dumps(bundle)
        data["content"] = base64.b64encode(
            text_bundle.encode("utf-8", "escape")
        ).decode("utf-8")

        # Send the message
        retry_count = 0
        while True:
            try:
                push_channel.basic_publish(
                    exchange=exchange,
                    routing_key=routing_key,
                    body=json.dumps(data),
                    properties=pika.BasicProperties(
                        delivery_mode=2,
                        content_encoding="utf-8",  # make message persistent
                    ),
                )
                return
            except (UnroutableError, NackError) as err:
                retry_count = retry_count + 1
                self.logger.info(
                    "Unable to send bundle, retrying...",
                    {
                        "retry_count": retry_count,
                        "routing_key": routing_key,
                        "is_split_bundle": is_split_bundle,
                    },
                )
                self.logger.debug("Unable to send bundle error", {"error": str(err)})
                time.sleep(10)

    def send_to_dead_letter(self, data: Dict[str, Any], items: List[Any]) -> None:
        """Send rejected items (too large, too many retries) to the dead letter queue."""
        if len(items) == 0:
            return
        with pika.BlockingConnection(self.pika_parameters) as push_pika_connection:
            with push_pika_connection.channel() as push_channel:
                try:
                    push_channel.confirm_delivery()
                except Exception as err:  # pylint: disable=broad-except
                    self.logger.warning(str(err))
                for item in items:
                    rejection_info = item.setdefault("rejection_info", {})
                    rejection_info["original_connector_id"] = self.connector_id
                    self.logger.warning(
                        "Detected a bundle too large, sending it to dead letter queue...",
                        {"bundle_id": item["id"], "connector_id": self.connector_id},
                    )
                    self.send_bundle_to_specific_queue(
                        push_channel,
                        self.listen_exchange,
                        self.dead_letter_routing,
                        data,
                        item,
                    )

    def batch_import_supported(self) -> bool:
        """Whether the platform takes lock-free batch imports (checked again every 5 minutes when not)."""
        now = time.monotonic()
        if self._batch_supported is None or (
            not self._batch_supported and now - self._batch_checked_at > 300
        ):
            self._batch_checked_at = now
            try:
                self.api.send_query(
                    "mutation { lockfreeImport(operations: []) { status } }"
                )
                self._batch_supported = True
            except Exception:  # pylint: disable=broad-except
                self._batch_supported = False
            self.logger.info(
                "Batch import support", {"supported": self._batch_supported}
            )
        return self._batch_supported

    @staticmethod
    def _batch_key(data: Dict[str, Any]):
        """Messages with the same key are imported together; None when a message goes on its own."""
        if data.get("type", "bundle") != "bundle" or data.get("draft_id"):
            return None
        return (
            data.get("applicant_id"),
            data.get("playbook_id"),
            data.get("event_id"),
            data.get("work_id"),
            data.get("synchronized", False),
            data.get("previous_standard"),
            data.get("update", False),
            tuple(data.get("entities_types") or []),
        )

    def handle_batch(
        self, bodies: List[str]
    ) -> List[Literal["ack", "nack", "requeue"]]:
        """Handle messages received together: consecutive bundles with the same context are imported as one
        bundle through the lock-free batch import, every other message on its own."""
        if not self.batch_import_supported():
            return [self.handle_message(body) for body in bodies]
        parsed = []
        for body in bodies:
            try:
                data = json.loads(body)
                content = json.loads(base64.b64decode(data["content"]).decode("utf-8"))
                key = self._batch_key(data)
                objects = content.get("objects") or []
                if key is None or len(objects) == 0:
                    key = None
                parsed.append((key, data, objects))
            except Exception:  # pylint: disable=broad-except
                parsed.append((None, None, None))
        results: List[Literal["ack", "nack", "requeue"]] = []
        index = 0
        while index < len(bodies):
            key = parsed[index][0]
            end = index + 1
            objects = len(parsed[index][2] or [])
            while (
                key is not None
                and end < len(bodies)
                and parsed[end][0] == key
                and objects + len(parsed[end][2]) <= MAX_GROUP_OBJECTS
            ):
                objects += len(parsed[end][2])
                end += 1
            if end - index == 1 and objects <= 1:
                results.append(self.handle_message(bodies[index]))
            else:
                results.extend(self._handle_group(bodies[index:end], parsed[index:end]))
            index = end
        return results

    def _handle_group(self, bodies, parsed) -> List[Literal["ack", "nack", "requeue"]]:
        start_processing = datetime.datetime.now()
        imported_items = []
        objects = []
        seen = set()
        alone = []  # messages repeating an object of the group: on their own, after
        for position, (_, _, message_objects) in enumerate(parsed):
            if any(o.get("id") in seen for o in message_objects):
                alone.append(position)
                continue
            for o in message_objects:
                seen.add(o.get("id"))
            objects.extend(message_objects)
        data = parsed[0][1]
        try:
            self.api.set_applicant_id_header(data.get("applicant_id"))
            self.api.set_playbook_id_header(data.get("playbook_id"))
            self.api.set_event_id(data.get("event_id"))
            self.api.set_draft_id(data.get("draft_id"))
            self.api.set_synchronized_upsert_header(data.get("synchronized", False))
            self.api.set_previous_standard_header(data.get("previous_standard"))
            work_id = data.get("work_id")
            self.api.set_work_id(work_id)
            types = data["entities_types"] if data.get("entities_types") else None
            bundle = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "objects": objects,
            }
            self.api.batch_import_enabled = True
            try:
                imported_items, rejected = self.api.stix2.import_bundle(
                    bundle,
                    data.get("update", False),
                    types,
                    work_id,
                    self.objects_max_refs,
                )
            finally:
                self.api.batch_import_enabled = False
            self.send_to_dead_letter(data, rejected)
            results: List[Literal["ack", "nack", "requeue"]] = ["ack"] * len(bodies)
        except Exception as ex:  # pylint: disable=broad-except
            self.logger.error(
                "Error importing messages together, importing them one by one",
                {"reason": str(ex), "messages": len(bodies)},
            )
            return [self.handle_message(body) for body in bodies]
        finally:
            try:
                self.bundles_global_counter.add(len(imported_items))
                processing_delta = datetime.datetime.now() - start_processing
                self.bundles_processing_time_gauge.record(processing_delta.seconds)
            except Exception as telemetry_ex:  # pylint: disable=broad-except
                self.logger.error(
                    "Failed to record bundle processing telemetry",
                    {"reason": str(telemetry_ex)},
                )
        for position in alone:
            results[position] = self.handle_message(bodies[position])
        return results

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
            # Set the API headers
            self.api.set_applicant_id_header(data.get("applicant_id"))
            self.api.set_playbook_id_header(data.get("playbook_id"))
            self.api.set_event_id(data.get("event_id"))
            self.api.set_draft_id(data.get("draft_id"))
            self.api.set_synchronized_upsert_header(data.get("synchronized", False))
            self.api.set_previous_standard_header(data.get("previous_standard"))
            work_id = data.get("work_id")
            self.api.set_work_id(work_id)

            # Execute the import
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
                    # Several objects in one message: imported together when the platform can
                    self.api.batch_import_enabled = (
                        len(content["objects"]) > 1
                        and not data.get("draft_id")
                        and self.batch_import_supported()
                    )
                    try:
                        imported_items, too_large_items_bundles = (
                            self.api.stix2.import_bundle_from_json(
                                raw_content,
                                update,
                                types,
                                work_id,
                                self.objects_max_refs,
                            )
                        )
                    finally:
                        self.api.batch_import_enabled = False
                    self.send_to_dead_letter(data, too_large_items_bundles)
                else:
                    # As bundle is received as complete, split and requeue
                    self.logger.warning(
                        "Received a multi-object bundle without no_split, splitting in worker",
                        {
                            "connector_id": self.connector_id,
                            "work_id": work_id,
                            "object_count": len(content["objects"]),
                        },
                    )
                    # Create a specific channel to push the split bundles
                    with pika.BlockingConnection(
                        self.pika_parameters
                    ) as push_pika_connection:
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
                                work_alive = self.api.work.add_expectations(
                                    work_id, expectations
                                )
                                if not work_alive:
                                    return "ack"
                            # For each split bundle, send it to the same queue
                            for bundle in bundles:
                                self.send_bundle_to_specific_queue(
                                    push_channel,
                                    self.push_exchange,
                                    self.push_routing,
                                    data,
                                    bundle,
                                    True,
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
                        imported_items = self.api.stix2.import_bundle(
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
                        merge_object["opencti_operation"] = content["type"]
                        merge_object["merge_target_id"] = target_id
                        merge_object["merge_source_ids"] = source_ids
                        bundle = {
                            "type": "bundle",
                            "objects": [merge_object],
                        }
                        imported_items = self.api.stix2.import_bundle(
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
                        | "add_related_covered_entities"  # Create has-covered relationships
                        | "revert_draft"  # Cancel draft modification (massive operation in UI)
                    ):
                        data_object = content["data"]
                        data_object["opencti_operation"] = content["type"]
                        bundle = {
                            "type": "bundle",
                            "objects": [data_object],
                        }
                        imported_items = self.api.stix2.import_bundle(
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
            self.logger.error("Error executing data handling", {"reason": str(ex)})
            # Nack message and discard
            return "nack"
        finally:
            try:
                self.bundles_global_counter.add(len(imported_items))
                processing_delta = datetime.datetime.now() - start_processing
                self.bundles_processing_time_gauge.record(processing_delta.seconds)
            except Exception as telemetry_ex:  # pylint: disable=broad-except
                self.logger.error(
                    "Failed to record bundle processing telemetry",
                    {"reason": str(telemetry_ex)},
                )
