import base64
import datetime
import json
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import (
    Any,
    Dict,
    Iterator,
    List,
    Literal,
    NamedTuple,
    Optional,
    Tuple,
    Union,
)

import pika
from pika.adapters.blocking_connection import BlockingChannel
from pika.exceptions import NackError, UnroutableError
from pycti import OpenCTIApiClient, OpenCTIStix2Splitter, __version__

# Objects imported together at most, whatever the number of messages they come in
MAX_GROUP_OBJECTS = 2000
# An item whose reference does not exist yet (another worker may still be importing it) is sent again through the
# queue, and imported again no sooner than these seconds later; after the last, the usual retries and error report
MISSING_REF_DEFERRAL_DELAYS = (1, 2, 4, 8, 16)
MAX_MISSING_REF_DEFERRALS = len(MISSING_REF_DEFERRAL_DELAYS)
# An empty batch import: answered by a platform that has the lock-free batch import, refused by any other
LOCKFREE_IMPORT_PROBE_QUERY = "mutation { lockfreeImport(operations: []) { status } }"
# While the platform has no batch import, it is checked again this often
BATCH_SUPPORT_RECHECK_SECONDS = 300

MessageResult = Literal["ack", "nack", "requeue"]
# The context of a bundle message (applicant, work, update...): messages sharing it can be imported together
GroupKey = Tuple[Any, ...]


class ParsedMessage(NamedTuple):
    """A message received in a batch, read to group it with others."""

    group_key: Optional[GroupKey]  # None: handled on its own
    data: Dict[str, Any]  # empty when the message cannot be read
    objects: List[Any]


def _missing_ref_deferrals(data: Dict[str, Any]) -> Any:
    """How many times the message's items were sent again for a missing reference."""
    return data.get("missing_ref_deferrals", 0)


def _retry_at(data: Dict[str, Any]) -> Any:
    """When the items of a message sent again for a missing reference are due (0: now)."""
    return data.get("missing_ref_retry_at") or 0


def _new_bundle(objects: List[Any]) -> Dict[str, Any]:
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def _group_end(messages: List[ParsedMessage], start: int) -> int:
    """End (exclusive) of the group starting at start: the next messages with the same key, as long as the group
    holds at most MAX_GROUP_OBJECTS objects."""
    key = messages[start].group_key
    object_count = len(messages[start].objects)
    end = start + 1
    while (
        end < len(messages)
        and messages[end].group_key == key
        and object_count + len(messages[end].objects) <= MAX_GROUP_OBJECTS
    ):
        object_count += len(messages[end].objects)
        end += 1
    return end


def _group_objects(messages: List[ParsedMessage]) -> Tuple[List[Any], List[int]]:
    """The objects of a group, and the positions of the messages repeating an object of an earlier one: those are
    left out, to go on their own."""
    objects: List[Any] = []
    seen_ids = set()
    repeating: List[int] = []
    for position, message in enumerate(messages):
        if any(o.get("id") in seen_ids for o in message.objects):
            repeating.append(position)
            continue
        for o in message.objects:
            seen_ids.add(o.get("id"))
        objects.extend(message.objects)
    return objects, repeating


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

    @contextmanager
    def _confirmed_push_channel(self) -> Iterator[BlockingChannel]:
        """A channel of its own to publish with, deliveries confirmed when the broker allows it."""
        with pika.BlockingConnection(self.pika_parameters) as push_pika_connection:
            with push_pika_connection.channel() as push_channel:
                try:
                    push_channel.confirm_delivery()
                except Exception as err:  # pylint: disable=broad-except
                    self.logger.warning(str(err))
                yield push_channel

    def send_to_dead_letter(self, data: Dict[str, Any], items: List[Any]) -> None:
        """Send rejected items (too large, too many retries) to the dead letter queue."""
        if len(items) == 0:
            return
        with self._confirmed_push_channel() as push_channel:
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
        if self._batch_support_check_due(now):
            self._batch_checked_at = now
            self._batch_supported = self._probe_batch_import()
            self.logger.info(
                "Batch import support", {"supported": self._batch_supported}
            )
        return bool(self._batch_supported)

    def _batch_support_check_due(self, now: float) -> bool:
        if self._batch_supported is None:
            return True
        return (
            not self._batch_supported
            and now - self._batch_checked_at > BATCH_SUPPORT_RECHECK_SECONDS
        )

    def _probe_batch_import(self) -> bool:
        try:
            self.api.send_query(LOCKFREE_IMPORT_PROBE_QUERY)
            return True
        except Exception:  # pylint: disable=broad-except
            return False

    @staticmethod
    def _batch_key(data: Dict[str, Any]) -> Optional[GroupKey]:
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
            _missing_ref_deferrals(data),
        )

    def send_deferred(self, data: Dict[str, Any]) -> None:
        """Send the items of the last batch import whose references did not exist yet to the end of the queue,
        as one message: by the time it comes back, what they reference has been imported. Their expectations
        stay open until then."""
        items = self.api.stix2.last_batch_deferred
        if len(items) == 0:
            return
        deferrals = _missing_ref_deferrals(data) + 1
        self.logger.info(
            "Sending items with missing references to the queue again",
            {"items": len(items), "deferrals": deferrals},
        )
        retry_delay = MISSING_REF_DEFERRAL_DELAYS[deferrals - 1]
        message = {
            **data,
            "missing_ref_deferrals": deferrals,
            "missing_ref_retry_at": time.time() + retry_delay,
            "no_split": True,
        }
        self.send_to_queue_end([(message, items)])

    def send_to_queue_end(
        self, messages: List[Tuple[Dict[str, Any], List[Any]]]
    ) -> None:
        """Publish (message data, objects) pairs at the end of the push queue, each as one bundle message."""
        with self._confirmed_push_channel() as push_channel:
            for data, objects in messages:
                self.send_bundle_to_specific_queue(
                    push_channel,
                    self.push_exchange,
                    self.push_routing,
                    data,
                    _new_bundle(objects),
                    True,
                )

    @staticmethod
    def wait_for_retry(messages: List[Dict[str, Any]]) -> None:
        """Items sent again for a missing reference come back as soon as the queue reaches them: when that is
        sooner than their delay, wait for the rest of it."""
        retry_at = max(_retry_at(data) for data in messages)
        remaining = min(retry_at - time.time(), MISSING_REF_DEFERRAL_DELAYS[-1])
        if remaining > 0:
            time.sleep(remaining)

    def handle_batch(self, bodies: List[str]) -> List[MessageResult]:
        """Handle messages received together: consecutive bundles with the same context are imported as one
        bundle through the lock-free batch import, every other message on its own."""
        if not self.batch_import_supported():
            return [self.handle_message(body) for body in bodies]
        messages = [self._parse_for_grouping(body) for body in bodies]
        # Messages sent again for a missing reference and not due yet: when others of the batch are, the others are
        # imported now and these go back to the end of the queue as they are, instead of holding the whole batch
        # until their delay. A batch with nothing due waits for it (the queue has nothing else to give).
        now = time.time()
        not_due = {
            position
            for position, message in enumerate(messages)
            if message.data and _retry_at(message.data) > now
        }
        if len(not_due) == 0 or len(not_due) == len(messages):
            return self._handle_groups(bodies, messages)
        self.send_to_queue_end(
            [
                (dict(messages[position].data), messages[position].objects)
                for position in sorted(not_due)
            ]
        )
        due = [position for position in range(len(messages)) if position not in not_due]
        due_results = self._handle_groups(
            [bodies[position] for position in due],
            [messages[position] for position in due],
        )
        # The messages sent back to the queue are done with here
        results: List[MessageResult] = ["ack"] * len(messages)
        for position, result in zip(due, due_results):
            results[position] = result
        return results

    def _parse_for_grouping(self, body: str) -> ParsedMessage:
        """Read a message's context and objects; a message that cannot be grouped gets no key."""
        try:
            data = json.loads(body)
            content = json.loads(base64.b64decode(data["content"]).decode("utf-8"))
            key = self._batch_key(data)
            objects = content.get("objects") or []
            if len(objects) == 0:
                key = None
            return ParsedMessage(key, data, objects)
        except Exception:  # pylint: disable=broad-except
            # Handled on its own, which reports what is wrong with it
            return ParsedMessage(None, {}, [])

    def _handle_groups(
        self, bodies: List[str], messages: List[ParsedMessage]
    ) -> List[MessageResult]:
        """Import consecutive messages sharing their context as one group, every other message on its own."""
        results: List[MessageResult] = []
        start = 0
        while start < len(messages):
            if messages[start].group_key is None:
                results.append(self.handle_message(bodies[start]))
                start += 1
                continue
            # A message alone with one object too goes through the batch import: an item with a missing reference
            # is then sent again through the queue rather than retried in the worker
            end = _group_end(messages, start)
            results.extend(self._handle_group(bodies[start:end], messages[start:end]))
            start = end
        return results

    def _handle_group(
        self, bodies: List[str], messages: List[ParsedMessage]
    ) -> List[MessageResult]:
        """Import the objects of messages sharing their context as one bundle. A message repeating an object of
        the group is handled on its own, after; when the import fails, every message is handled on its own.
        """
        start_processing = datetime.datetime.now()
        imported_items: List[Any] = []
        objects, repeating = _group_objects(messages)
        data = messages[0].data
        self.wait_for_retry([message.data for message in messages])
        try:
            self._set_api_context(data)
            imported_items, rejected = self._import_group(data, objects)
            self.send_to_dead_letter(data, rejected)
            self.send_deferred(data)
        except Exception as ex:  # pylint: disable=broad-except
            self.logger.error(
                "Error importing messages together, importing them one by one",
                {"reason": str(ex), "messages": len(bodies)},
            )
            return [self.handle_message(body) for body in bodies]
        finally:
            self._record_processing_telemetry(len(imported_items), start_processing)
        results: List[MessageResult] = ["ack"] * len(bodies)
        for position in repeating:
            results[position] = self.handle_message(bodies[position])
        return results

    def _set_api_context(self, data: Dict[str, Any]) -> None:
        """Send the next requests as the message asks: applicant, playbook, event, draft, work..."""
        self.api.set_applicant_id_header(data.get("applicant_id"))
        self.api.set_playbook_id_header(data.get("playbook_id"))
        self.api.set_event_id(data.get("event_id"))
        self.api.set_draft_id(data.get("draft_id"))
        self.api.set_synchronized_upsert_header(data.get("synchronized", False))
        self.api.set_previous_standard_header(data.get("previous_standard"))
        self.api.set_work_id(data.get("work_id"))

    def _import_group(
        self, data: Dict[str, Any], objects: List[Any]
    ) -> Tuple[List[Any], List[Any]]:
        """Import the objects of a group as one bundle through the batch import: (imported, rejected) items."""
        types = data["entities_types"] if data.get("entities_types") else None
        bundle = _new_bundle(objects)
        with self._batch_import_mode(True, data):
            imported_items, rejected = self.api.stix2.import_bundle(
                bundle,
                data.get("update", False),
                types,
                data.get("work_id"),
                self.objects_max_refs,
            )
        return imported_items, rejected

    @contextmanager
    def _batch_import_mode(self, enabled: bool, data: Dict[str, Any]) -> Iterator[None]:
        """The client's batch import settings for one import of the message, reset after it. Items with a missing
        reference are left to the worker, to send again through the queue, until the last deferral.
        """
        self.api.batch_import_enabled = enabled
        self.api.defer_missing_references = (
            _missing_ref_deferrals(data) < MAX_MISSING_REF_DEFERRALS
        )
        try:
            yield
        finally:
            self.api.batch_import_enabled = False
            self.api.defer_missing_references = False

    def _batch_import_wanted(self, data: Dict[str, Any], object_count: int) -> bool:
        """Whether a message imported on its own goes through the batch import: when it holds several objects
        (or an item sent again for a missing reference, so that it can be sent again) and the platform can.
        """
        if not (object_count > 1 or _missing_ref_deferrals(data) > 0):
            return False
        if data.get("draft_id"):
            return False
        return self.batch_import_supported()

    def _record_processing_telemetry(
        self, imported_count: int, start_processing: datetime.datetime
    ) -> None:
        try:
            self.bundles_global_counter.add(imported_count)
            processing_delta = datetime.datetime.now() - start_processing
            self.bundles_processing_time_gauge.record(processing_delta.seconds)
        except Exception as telemetry_ex:  # pylint: disable=broad-except
            self.logger.error(
                "Failed to record bundle processing telemetry",
                {"reason": str(telemetry_ex)},
            )

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
        self.wait_for_retry([data])
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
                    batch_import = self._batch_import_wanted(
                        data, len(content["objects"])
                    )
                    with self._batch_import_mode(batch_import, data):
                        imported_items, too_large_items_bundles = (
                            self.api.stix2.import_bundle_from_json(
                                raw_content,
                                update,
                                types,
                                work_id,
                                self.objects_max_refs,
                            )
                        )
                    self.send_to_dead_letter(data, too_large_items_bundles)
                    self.send_deferred(data)
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
