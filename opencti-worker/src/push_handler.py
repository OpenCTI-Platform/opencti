import base64
import datetime
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

import pika
from pika.adapters.blocking_connection import BlockingChannel
from pika.exceptions import NackError, UnroutableError
from pycti import OpenCTIApiClient, OpenCTIStix2Splitter, __version__


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
    # Batch import telemetry, optional/unused when batching is disabled.
    batch_size_histogram: Any = None
    batch_items_counter: Any = None
    batch_fallback_counter: Any = None

    def __post_init__(self) -> None:
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

    # STIX object types whose creation is cheap/idempotent enough that a reference to
    # them never needs to gate batching: always pre-existing, never a same-batch
    # dependency (unlike a ref to another leaf object created in the same window).
    FREE_REF_TYPE_PREFIXES = ("identity--", "marking-definition--")

    # *_ref/*_refs keys that OpenCTIStix2.import_observable() resolves inline via the
    # create() mutation's own input variables. Any other *_ref/*_refs key requires a
    # separate follow-up mutation using the object's real id, which capture-mode's
    # dry run (fake id) cannot safely trigger. Keep in sync with the exclusion list in
    # import_observable (client-python/pycti/utils/opencti_stix2.py).
    SAFE_OBSERVABLE_REF_KEYS = (
        "created_by_ref",
        "object_marking_refs",
        "x_opencti_created_by_ref",
        "x_opencti_granted_refs",
    )

    @classmethod
    def _has_only_free_refs(cls, stix_object: Dict[str, Any]) -> bool:
        """True when every `*_ref`/`*_refs` field on this object (if any) is in
        SAFE_OBSERVABLE_REF_KEYS and points only to a FREE_REF_TYPE_PREFIXES object.
        Fails closed on anything else (unknown key, wrong ref type, malformed value)."""
        for key, value in stix_object.items():
            if not (key.endswith("_ref") or key.endswith("_refs")) or not value:
                continue
            if key not in cls.SAFE_OBSERVABLE_REF_KEYS:
                return False
            refs = value if isinstance(value, list) else [value]
            for ref in refs:
                if not isinstance(ref, str) or not ref.startswith(
                    cls.FREE_REF_TYPE_PREFIXES
                ):
                    return False
        return True

    @staticmethod
    def _extract_batch_candidate(
        data: Dict[str, Any], content: Dict[str, Any]
    ) -> Optional[Tuple[Dict[str, Any], bool]]:
        """Return (stix_object, needs_free_ref_check) for the single STIX object this
        message would create/update, or None if not a single-object candidate:
        - type == "bundle" holding exactly one object.
        - type == "event" with content.type in ("create", "update"), the shape used
          by opencti-graphql's syncManager.js; always needs the free-ref check since
          no x_opencti_seq is computed for it.
        """
        event_type = data.get("type", "bundle")
        if event_type == "bundle":
            objects = content.get("objects", [])
            if len(objects) != 1:
                return None
            seq = content.get("x_opencti_seq")
            return objects[0], seq not in (None, 1)
        if event_type == "event" and content.get("type") in ("create", "update"):
            obj = content.get("data")
            if not isinstance(obj, dict):
                return None
            return obj, True
        return None

    def is_batchable(self, body: str) -> bool:
        """Structural pre-filter: only messages that resolve to a single
        dependency-free STIX object (see _extract_batch_candidate) are candidates for
        accumulation. Whether the STIX type itself is actually
        supported for batching is decided later, in bulk, at flush time (see
        handle_message_batch / OpenCTIStix2.try_capture_batchable_item) - this keeps
        the per-message check on the hot path cheap.
        """
        try:
            data: Dict[str, Any] = json.loads(body)
            raw_content = base64.b64decode(data["content"]).decode("utf-8")
            content = json.loads(raw_content)
            candidate = self._extract_batch_candidate(data, content)
            if candidate is None:
                return False
            stix_object, needs_free_ref_check = candidate
            if needs_free_ref_check:
                return self._has_only_free_refs(stix_object)
            return True
        except Exception:  # pylint: disable=broad-except
            return False

    def _prepare_batchable_entry(self, body: str) -> Optional[Dict[str, Any]]:
        """Try to build the (kind, input, work_id) payload for one accumulated message.
        Returns None if the item is not actually batchable (wrong/unsupported STIX type,
        or needs more than one mutation call) - the caller must then fall back to the
        normal handle_message() path for this specific message."""
        try:
            data: Dict[str, Any] = json.loads(body)
            raw_content = base64.b64decode(data["content"]).decode("utf-8")
            content = json.loads(raw_content)
        except Exception:  # pylint: disable=broad-except
            return None
        candidate = self._extract_batch_candidate(data, content)
        if candidate is None:
            return None
        stix_object, needs_free_ref_check = candidate
        if needs_free_ref_check and not self._has_only_free_refs(stix_object):
            return None
        work_id = data.get("work_id")
        self.api.set_applicant_id_header(data.get("applicant_id"))
        self.api.set_playbook_id_header(data.get("playbook_id"))
        self.api.set_event_id(data.get("event_id"))
        self.api.set_draft_id(data.get("draft_id"))
        self.api.set_synchronized_upsert_header(data.get("synchronized", False))
        self.api.set_previous_standard_header(data.get("previous_standard"))
        self.api.set_work_id(work_id)
        update = data.get("update", False)
        types = (
            data["entities_types"]
            if "entities_types" in data and len(data["entities_types"]) > 0
            else None
        )
        try:
            captured = self.api.stix2.try_capture_batchable_item(
                stix_object, update, types, content.get("id")
            )
        except Exception:  # pylint: disable=broad-except
            # Defensive: never let a capture-mode failure crash the batch flush -
            # just fall back to the normal handle_message() path for this item.
            return None
        if captured is None:
            return None
        return {
            "kind": captured["kind"],
            "input": captured["input"],
            "work_id": work_id,
        }

    def handle_message_batch(
        self,
        bodies: List[str],
    ) -> List[Literal["ack", "nack", "requeue"]]:
        """Process an accumulated window of leaf (dependency-free) messages with a
        single stixObjectsBatchImport call instead of N separate GraphQL calls.
        Index-aligned with `bodies`: every message still gets its own ack/nack/requeue
        decision and its own work expectation report, exactly as today.
        A message whose item turns out not to be batchable falls back to the normal,
        unchanged handle_message() path so it is never silently dropped.
        """
        results: List[Any] = [None] * len(bodies)
        batchable: List[Dict[str, Any]] = []
        for index, body in enumerate(bodies):
            entry = self._prepare_batchable_entry(body)
            if entry is None:
                results[index] = self.handle_message(body)
            else:
                batchable.append({"index": index, **entry})

        # Items that the fast, structural is_batchable() pre-filter accepted but that
        # _prepare_batchable_entry() then rejected on the deeper check (unsupported
        # STIX subtype, capture failure, ...) and so fell back to handle_message().
        fallback_count = len(bodies) - len(batchable)
        if fallback_count > 0 and self.batch_fallback_counter is not None:
            self.batch_fallback_counter.add(fallback_count)

        if not batchable:
            return results

        items = [
            {"kind": entry["kind"], "input": entry["input"]} for entry in batchable
        ]
        if self.batch_size_histogram is not None:
            self.batch_size_histogram.record(len(items))
        try:
            response = self.api.query(
                """
                mutation StixObjectsBatchImportWorker(
                    $items: [StixBatchImportItemInput!]!
                ) {
                    stixObjectsBatchImport(items: $items) {
                        id
                        success
                        error
                    }
                }
                """,
                {"items": items},
            )
            batch_results = response["data"]["stixObjectsBatchImport"]
        except Exception as ex:  # pylint: disable=broad-except
            # Whole batch call failed (network/timeout/...): requeue every message in
            # the batch, AMQP redelivery will retry them (no message loss, matches the
            # not-yet-processed semantics of today's single-item path on a hard
            # failure).
            self.logger.error(
                "Batch import call failed, requeueing batch", {"exception": str(ex)}
            )
            if self.batch_items_counter is not None:
                self.batch_items_counter.add(len(batchable), {"outcome": "call_failed"})
            for entry in batchable:
                results[entry["index"]] = "requeue"
            return results

        for entry, item_result in zip(batchable, batch_results):
            work_id = entry["work_id"]
            outcome = "success" if item_result.get("success") else "item_failed"
            if self.batch_items_counter is not None:
                self.batch_items_counter.add(1, {"outcome": outcome})
            if item_result.get("success"):
                if work_id is not None:
                    self.api.work.report_expectation(work_id, None)
            else:
                if work_id is not None:
                    self.api.work.report_expectation(
                        work_id,
                        {
                            "error": item_result.get("error"),
                            "source": "Batch import",
                        },
                    )
            # Per-item failures are reported and acked (no retry/backoff), matching
            # today's terminal/non-retryable-error behaviour.
            results[entry["index"]] = "ack"
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
                    imported_items, too_large_items_bundles = (
                        self.api.stix2.import_bundle_from_json(
                            raw_content, update, types, work_id, self.objects_max_refs
                        )
                    )
                    if len(too_large_items_bundles) > 0:
                        with pika.BlockingConnection(
                            self.pika_parameters
                        ) as push_pika_connection:
                            with push_pika_connection.channel() as push_channel:
                                try:
                                    push_channel.confirm_delivery()
                                except Exception as err:  # pylint: disable=broad-except
                                    self.logger.warning(str(err))
                                for too_large_item_bundle in too_large_items_bundles:
                                    rejection_info = too_large_item_bundle.setdefault(
                                        "rejection_info", {}
                                    )
                                    rejection_info["original_connector_id"] = (
                                        self.connector_id
                                    )
                                    self.logger.warning(
                                        "Detected a bundle too large, sending it to dead letter queue...",
                                        {
                                            "bundle_id": too_large_item_bundle["id"],
                                            "connector_id": self.connector_id,
                                        },
                                    )
                                    self.send_bundle_to_specific_queue(
                                        push_channel,
                                        self.listen_exchange,
                                        self.dead_letter_routing,
                                        data,
                                        too_large_item_bundle,
                                    )
                else:
                    # As bundle is received as complete, split and requeue
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
                        # import_bundle() returns a (imported, too_large) 2-tuple;
                        # destructure so imported_items is the item list, not the
                        # tuple itself (len() below must reflect real counts, not 2).
                        imported_items, _ = self.api.stix2.import_bundle(
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
                        # import_bundle() returns a (imported, too_large) 2-tuple;
                        # destructure so imported_items is the item list, not the
                        # tuple itself (len() below must reflect real counts, not 2).
                        imported_items, _ = self.api.stix2.import_bundle(
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
                        data_object["opencti_operation"] = content["type"]
                        bundle = {
                            "type": "bundle",
                            "objects": [data_object],
                        }
                        # import_bundle() returns a (imported, too_large) 2-tuple;
                        # destructure so imported_items is the item list, not the
                        # tuple itself (len() below must reflect real counts, not 2).
                        imported_items, _ = self.api.stix2.import_bundle(
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
            self.bundles_global_counter.add(len(imported_items))
            processing_delta = datetime.datetime.now() - start_processing
            # total_seconds() (not the .seconds attribute, which truncates to whole
            # seconds and would report 0 for the vast majority of sub-second calls) -
            # converted to milliseconds to match the backend's opencti_api_latency
            # histogram convention.
            self.bundles_processing_time_gauge.record(
                processing_delta.total_seconds() * 1000
            )
