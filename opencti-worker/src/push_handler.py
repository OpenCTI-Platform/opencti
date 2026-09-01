import base64
import datetime
import itertools
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Union

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
    # POC (plan 0009 P3): thread width for the level-parallel import of an inline bundle
    # (message flagged bundle_inline by the platform). 1 = strictly sequential levels.
    bundle_parallelism: int = 8
    # POC (plan 0009 §9.6.6/§9.6.9): how an inline bundle is grouped into concurrent waves.
    # "chunks" (default, recommended) = accumulate objects in nb_deps order up to
    # bundle_parallelism and submit that chunk, barrier, repeat: the wave size is CHOSEN
    # instead of being dictated by the graph's shape, so small bundles are not fragmented
    # into width-1 waves and huge bundles are not submitted wholesale. Consecutive
    # dependent objects land in the same chunk, hence very likely in the same sequencer
    # batch, where the planner's producer->consumer edges order them.
    # "levels" = one wave per nb_deps value (strict: no intra-bundle race possible, but
    # width is whatever the graph gives: measured median 2, 43.5% of waves width 1).
    # "phases" = entities, then relationships, then containers/rel-on-rel (D1 mirror).
    # "all" = no barrier, everything submitted at once, executor-bounded.
    bundle_wave_policy: str = "chunks"
    # POC (plan 0009 §9.6.7): treat ANY multi-object bundle as inline, whatever its origin.
    # Required because external connectors (and the bench replay) publish straight to
    # RabbitMQ through pycti, never through the platform's pushBundleToWorker, so the
    # platform-side bundle_intake marker never reaches them. With this on, a multi-object
    # message (no_split from the connector, or unflagged) is imported in place by waves
    # instead of being imported sequentially / split and requeued.
    bundle_inline: bool = False

    def __post_init__(self) -> None:
        self.api = OpenCTIApiClient(
            url=self.opencti_url,
            token=self.opencti_token,
            log_level=self.log_level,
            json_logging=self.json_logging,
            ssl_verify=self.ssl_verify,
            provider="worker/" + __version__,
        )
        self.bundle_executor = ThreadPoolExecutor(
            max_workers=max(1, self.bundle_parallelism),
            thread_name_prefix="bundle-inline",
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

    def send_too_large_to_dead_letter(
        self, data: Dict[str, Any], too_large_items_bundles: List[Any]
    ) -> None:
        if len(too_large_items_bundles) == 0:
            return
        with pika.BlockingConnection(self.pika_parameters) as push_pika_connection:
            with push_pika_connection.channel() as push_channel:
                try:
                    push_channel.confirm_delivery()
                except Exception as err:  # pylint: disable=broad-except
                    self.logger.warning(str(err))
                for too_large_item_bundle in too_large_items_bundles:
                    rejection_info = too_large_item_bundle.setdefault("rejection_info", {})
                    rejection_info["original_connector_id"] = self.connector_id
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

    # Option B (plan 0009 s9.8.3): suffix in place every ref pointing to a member of the
    # bundle. Only *_ref / *_refs keys are touched (the object's own id and every non-ref
    # field stay pristine); the platform strips the mark at its write boundary, so it can
    # never persist in ES.
    MEMBER_REF_MARK = "||M||"

    def mark_member_refs(self, node: Any, member_ids: set) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                is_ref_key = key.endswith("_ref") or key.endswith("_refs")
                if is_ref_key and isinstance(value, str):
                    if value in member_ids:
                        node[key] = value + self.MEMBER_REF_MARK
                elif is_ref_key and isinstance(value, list):
                    node[key] = [
                        (
                            item + self.MEMBER_REF_MARK
                            if isinstance(item, str) and item in member_ids
                            else item
                        )
                        for item in value
                    ]
                elif isinstance(value, (dict, list)):
                    self.mark_member_refs(value, member_ids)
        elif isinstance(node, list):
            for item in node:
                self.mark_member_refs(item, member_ids)

    def build_waves(self, bundles: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Group the split mini-bundles into the concurrent waves to submit.

        The splitter returns them sorted by nb_deps (dependencies before dependents), and
        every policy preserves that order; they differ only in where the barriers fall.
        """
        if self.bundle_wave_policy == "chunks":
            # POC (plan 0009 §9.6.9): fixed-size waves in dependency order. Size is a
            # choice (bundle_parallelism), not a property of the bundle's shape.
            size = max(1, self.bundle_parallelism)
            return [bundles[i : i + size] for i in range(0, len(bundles), size)]
        keyed = sorted(
            ((self.wave_key(b), b) for b in bundles), key=lambda pair: pair[0]
        )
        return [
            [pair[1] for pair in group]
            for _, group in itertools.groupby(keyed, key=lambda pair: pair[0])
        ]

    def wave_key(self, mini_bundle: Dict[str, Any]) -> int:
        # POC (plan 0009 §9.6.6): the wave a mini-bundle belongs to; waves import
        # concurrently, with a barrier between waves (see bundle_wave_policy).
        if self.bundle_wave_policy == "all":
            return 0
        obj = mini_bundle["objects"][0]
        if self.bundle_wave_policy == "phases":
            obj_type = obj.get("type")
            if obj_type in ("relationship", "sighting"):
                endpoint_refs = [
                    str(obj.get("source_ref", "")),
                    str(obj.get("target_ref", "")),
                    str(obj.get("sighting_of_ref", "")),
                ]
                if any(ref.startswith("relationship--") for ref in endpoint_refs):
                    return 2  # relationship whose endpoint is a relationship
                return 1
            if len(obj.get("object_refs") or []) > 0:
                return 2  # containers
            return 0  # entities
        # default "levels": one wave per nb_deps value (equal counts form an antichain)
        return obj.get("nb_deps", mini_bundle.get("x_opencti_seq", 0))

    def import_bundle_inline(
        self,
        content: Dict[str, Any],
        data: Dict[str, Any],
        work_id: Any,
        types: Any,
    ) -> List[Any]:
        # POC (plan 0009 P3, bundle-level intake): the platform pushed the bundle WHOLE
        # (bundle_inline). Split it here (same splitter as the historic requeue path, same
        # expectation counting) but import in place instead of requeueing: mini-bundles
        # sharing one nb_deps value (x_opencti_seq) form an antichain (A depends on B
        # implies nb_deps(A) > nb_deps(B)), so each level imports concurrently on the
        # bundle executor, with a barrier between levels: producers are committed before
        # their consumers fly, which preserves the intra-bundle ordering the queue used to
        # provide, while offering the platform level-width concurrent arrivals.
        update = data.get("update", False)
        event_version = content.get("x_opencti_event_version")
        stix2_splitter = OpenCTIStix2Splitter()
        expectations, _, bundles = stix2_splitter.split_bundle_with_expectations(
            content, False, event_version
        )
        if work_id is not None:
            work_alive = self.api.work.add_expectations(work_id, expectations)
            if not work_alive:
                return []
        imported_items: List[Any] = []
        too_large_items_bundles: List[Any] = []
        # Option B (plan 0009 s9.8.3, suffix transport): suffix every ref id that points to
        # an object of THIS bundle with ||M|| ("travels with me"). The platform strips the
        # mark at its write boundary and uses it to classify missing refs with certainty
        # (defer on queued producer, final on dead producer) instead of burning retries;
        # unmarked refs keep today's external retry path. O(refs) cost, works for any
        # bundle size (no header, no size cap). Suffix, not prefix: type-prefix routing
        # keeps working on a not-yet-stripped id.
        member_ids = {
            obj["id"] for obj in content.get("objects", []) if "id" in obj
        }
        for mini_bundle in bundles:
            for obj in mini_bundle.get("objects", []):
                self.mark_member_refs(obj, member_ids)
        # bundles come out sorted by nb_deps (the splitter sorts): group into waves per
        # the policy; python's stable sort keeps the nb_deps submission order inside a wave
        waves = self.build_waves(bundles)
        # Traceable proof that the inline path actually RAN (and how wide its waves were):
        # a marker present in the image is not a marker reached at runtime (plan 0009 §9.6.7).
        self.logger.info(
            "Inline bundle import",
            {
                "objects": expectations,
                "waves": len(waves),
                "widths": [len(w) for w in waves][:12],
                "policy": self.bundle_wave_policy,
            },
        )
        # Per-object isolation (s9.8.4): pycti reports and drops failed objects internally
        # (import_item), so a future raising here is an ESCAPED error (transport, bundle
        # format). It must never abort the remaining waves nor discard the bundle message:
        # log, report the expectation for that object, and continue.
        for level_bundles in waves:
            futures = [
                self.bundle_executor.submit(
                    self.api.stix2.import_bundle_from_json,
                    json.dumps(mini_bundle),
                    update,
                    types,
                    work_id,
                    self.objects_max_refs,
                )
                for mini_bundle in level_bundles
            ]
            for future in futures:
                try:
                    items, too_large = future.result()
                    imported_items.extend(items)
                    too_large_items_bundles.extend(too_large)
                except Exception as err:  # pylint: disable=broad-except
                    self.logger.error(
                        "Inline object import failed, continuing the bundle",
                        {"error": str(err)},
                    )
                    if work_id is not None:
                        try:
                            self.api.work.report_expectation(
                                work_id, {"error": str(err), "source": "inline import"}
                            )
                        except Exception:  # pylint: disable=broad-except
                            pass
        # dead-letter forwarding after the levels, from the handler thread (one connection)
        self.send_too_large_to_dead_letter(data, too_large_items_bundles)
        return imported_items

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
                objects_count = len(content["objects"])
                # POC (plan 0009 P3): inline when the platform flagged it, or when the
                # worker knob is on and the message actually carries several objects.
                inline = objects_count > 1 and (
                    data.get("bundle_inline", False) or self.bundle_inline
                )
                if inline:
                    imported_items = self.import_bundle_inline(
                        content, data, work_id, types
                    )
                elif objects_count == 1 or data.get("no_split", False):
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
