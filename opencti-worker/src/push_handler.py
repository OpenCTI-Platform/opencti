import base64
import datetime
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional, Union

import pika
import requests as http_requests
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
    opencti_ng_url: Optional[str] = None
    opencti_ng_token: Optional[str] = None

    def __post_init__(self) -> None:
        self.api = OpenCTIApiClient(
            url=self.opencti_url,
            token=self.opencti_token,
            log_level=self.log_level,
            json_logging=self.json_logging,
            ssl_verify=self.ssl_verify,
            provider="worker/" + __version__,
        )

    def _push_to_opencti_ng(self, bundle: dict, ingest_ids: list | None = None) -> dict:
        """POST a STIX bundle to opencti-ng.

        Args:
            bundle: The STIX 2.1 bundle dict.
            ingest_ids: Optional list of STIX IDs to ingest (partial retry).
                        None/empty = ingest all objects.

        Returns the raw response dict with keys:
          ingestion_id (str), status (str), total (int),
          ingested (int, optional), errors (list[dict])
        """
        url = f"{self.opencti_ng_url}/api/v1/stix/bundle"
        headers = {
            "Authorization": f"Bearer {self.opencti_ng_token}",
            "Content-Type": "application/json",
            "User-Agent": f"opencti-worker/{__version__}",
        }
        payload = {"bundle": bundle}
        if ingest_ids:
            payload["ingest_ids"] = ingest_ids
        response = http_requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=300,
        )
        response.raise_for_status()
        result = response.json()

        # If async, poll until complete
        if result.get("status") == "processing":
            ingestion_id = result["ingestion_id"]
            result = self._poll_ingestion(ingestion_id)

        return result

    def _poll_ingestion(self, ingestion_id: str) -> dict:
        """Poll an async ingestion job until it completes or fails.

        Uses long-polling (?timeout=30) to minimize latency — the server
        holds the request until the job completes or the timeout expires.

        Args:
            ingestion_id: The ingestion ID (format: ingestion--{uuid}).

        Returns the final result dict.
        """
        # Extract UUID from ingestion--{uuid} format
        job_uuid = ingestion_id.replace("ingestion--", "")
        url = f"{self.opencti_ng_url}/api/v1/ingestions/{job_uuid}?timeout=30"
        headers = {
            "Authorization": f"Bearer {self.opencti_ng_token}",
            "User-Agent": f"opencti-worker/{__version__}",
        }
        while True:
            response = http_requests.get(url, headers=headers, timeout=60)
            response.raise_for_status()
            result = response.json()
            status = result.get("status")
            if status in ("completed", "failed"):
                return result
            # Still processing — log progress and long-poll again
            progress = result.get("progress", 0)
            total = result.get("total", 0)
            self.logger.info(
                "opencti-ng ingestion in progress",
                {
                    "ingestion_id": ingestion_id,
                    "progress": progress,
                    "total": total,
                },
            )

    def send_bundle_to_specific_queue(
        self,
        push_channel: BlockingChannel,
        exchange: str,
        routing_key: str,
        data: Any,
        bundle: Any,
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
            except (UnroutableError, NackError):
                retry_count = retry_count + 1
                self.logger.info(
                    "Unable to send bundle, retrying...", {"retry_count": retry_count}
                )
                time.sleep(10)

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
                if self.opencti_ng_url is not None:
                    # opencti-ng handles the full bundle in one shot (no splitting needed)
                    nb_objects = len(content["objects"])
                    # The work already counts 1 expectation for this bundle message.
                    # Replace it with per-object expectations: add (N - 1) additional.
                    if work_id is not None and nb_objects > 1:
                        self.api.work.add_expectations(work_id, nb_objects - 1)
                    try:
                        result = self._push_to_opencti_ng(content)
                        ingested = result.get("ingested", 0)
                        total = result.get("total", nb_objects)
                        ng_errors = result.get("errors", [])
                        error_count = sum(
                            g.get("count", 0) for g in ng_errors
                        )
                        skipped = total - ingested - error_count
                        imported_items = ["ok"] * ingested
                        if work_id is not None:
                            # Build error list for bulk reporting
                            error_list = []
                            for err_group in ng_errors:
                                err_msg = err_group.get("message", "unknown error")
                                for stix_id in err_group.get("ids", []):
                                    error_list.append({
                                        "error": err_msg,
                                        "source": stix_id,
                                    })
                            # Report all success + errors in one call
                            self.api.work.report_expectations(
                                work_id,
                                success=ingested + max(0, skipped),
                                errors=error_list if error_list else None,
                            )
                        if ng_errors:
                            self.logger.warning(
                                "opencti-ng ingestion completed with errors",
                                {
                                    "ingested": ingested,
                                    "skipped": skipped,
                                    "errors": error_count,
                                },
                            )
                    except Exception as ng_error:
                        # HTTP-level failure — report all objects as failed
                        if work_id is not None:
                            error_list = [
                                {
                                    "error": str(ng_error),
                                    "source": "opencti-ng ingestion",
                                }
                                for _ in range(nb_objects)
                            ]
                            self.api.work.report_expectations(
                                work_id,
                                success=0,
                                errors=error_list,
                            )
                        raise
                elif len(content["objects"]) == 1 or data.get("no_split", False):
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
                        merge_object["opencti_operation"] = event_type
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
                        data_object["opencti_operation"] = event_type
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
            self.bundles_global_counter.add(len(imported_items))
            processing_delta = datetime.datetime.now() - start_processing
            self.bundles_processing_time_gauge.record(processing_delta.seconds)
