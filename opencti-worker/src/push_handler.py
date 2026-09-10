import base64
import datetime
import itertools
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Union

import pika
from opentelemetry import metrics as otel_metrics
from pika.adapters.blocking_connection import BlockingChannel
from pika.exceptions import NackError, UnroutableError
from pycti import OpenCTIApiClient, OpenCTIStix2Splitter, __version__

from http_pool import tune_session_pool
from ingest_pools import ChunkEntry, ChunkJob, get_ingest_pools, submit_bundle_atomic

# Chunked-path timing telemetry (user ask 2026-09-07): where a bundle's wall time
# goes worker-side, to correlate with the platform series (burst/famine reading).
# Instruments created at import time bind late to the provider set in worker.py
# (OTel proxy meter), same pattern as worker.py's own module-level instruments.
chunked_meter = otel_metrics.get_meter(__name__)
chunked_split_seconds = chunked_meter.create_histogram(
    name="opencti_worker_chunked_split_seconds",
    unit="s",
    description="Split + dependency collection + chunk building time per bundle (queue_thread work)",
)
chunked_post_seconds = chunked_meter.create_histogram(
    name="opencti_worker_chunked_post_seconds",
    unit="s",
    description="Pool pick + submit-lock wait + chunk posting time per bundle (backpressure included)",
)
chunked_bundle_seconds = chunked_meter.create_histogram(
    name="opencti_worker_chunked_bundle_seconds",
    unit="s",
    description="Full bundle wall time from split start to bundle-terminal (closed-loop round trip)",
)

# POC (plan 0009 s9.11): ONE request-thread pool per worker process, shared by every
# queue handler. The wave of any in-flight bundle draws its threads from this common
# budget, so a slow tail in one wave frees capacity that immediately serves the other
# queues' waves, instead of idling inside a per-handler silo. Sized by the FIRST
# handler constructed (all handlers of a process share one worker config).
_shared_bundle_executor: Optional[ThreadPoolExecutor] = None
_shared_bundle_executor_lock = threading.Lock()


def get_shared_bundle_executor(budget: int) -> ThreadPoolExecutor:
    global _shared_bundle_executor  # pylint: disable=global-statement
    if _shared_bundle_executor is None:
        with _shared_bundle_executor_lock:
            if _shared_bundle_executor is None:
                _shared_bundle_executor = ThreadPoolExecutor(
                    max_workers=max(1, budget),
                    thread_name_prefix="bundle-shared",
                )
    return _shared_bundle_executor


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
    # POC (plan 0009 s9.11): wave (chunk) size DECOUPLED from the thread budget.
    # 0 = follow bundle_parallelism (compatibility with every pre-s9.11 run manifest).
    bundle_wave_width: int = 0
    # POC (plan 0009 s9.11): size of the process-wide shared request pool. 0 = derive
    # 4x the wave width (roughly today's aggregate capacity, but un-siloed).
    bundle_executor_budget: int = 0
    # Chunked ingest pools (s9.12.1 successor, kb note opencti-worker-chunked-ingest-pools).
    # ingest_pools > 0 switches the inline import to the pool path: the handler splits,
    # chunks (splitter order, chunks may span levels), routes ALL chunks of the bundle to
    # ONE pool, and blocks until bundle-terminal (ack semantics unchanged, decision Q1-B).
    # 0 = OFF (s9.11 wave path, no pool threads created).
    ingest_pools: int = 0
    # CS: objects per chunk AND request threads per pool (1 object per thread).
    ingest_chunk_size: int = 16
    # Bundle-to-pool pick at bundle start (decision Q3): least_full | round_robin.
    ingest_pick: str = "least_full"
    # Per-pool queue bound (chunks); 0 = unbounded. Backpressure insurance only:
    # ordering never depends on it (affinity + FIFO carry it).
    ingest_pool_queue_bound: int = 64
    # V2 pipelined admission (next chunk as request threads free up). Default V1 barrier.
    ingest_pipelined: bool = False
    # Dependency-aware admission under V2 (fix of ladder run 4's failure cascades):
    # an object is held while its in-bundle producers from EARLIER chunks are still
    # in flight. No effect on V1 (the barrier is stronger) nor on other bundles'
    # chunks (cross-bundle admission keeps the pool saturated).
    ingest_dep_admission: bool = True

    def __post_init__(self) -> None:
        self.api = OpenCTIApiClient(
            url=self.opencti_url,
            token=self.opencti_token,
            log_level=self.log_level,
            json_logging=self.json_logging,
            ssl_verify=self.ssl_verify,
            provider="worker/" + __version__,
        )
        # study 0011: the default 10-connection pool IS the per-process ceiling (env-gated)
        tune_session_pool(self.api.session, self.api.app_logger)
        # s9.11: the wave width is a pure shaping choice; the thread budget is a
        # process-wide resource shared across handlers (see get_shared_bundle_executor).
        self.wave_width = max(1, self.bundle_wave_width or self.bundle_parallelism)
        budget = self.bundle_executor_budget or self.wave_width * 4
        self.bundle_executor = get_shared_bundle_executor(budget)
        # Chunked ingest pools: created once per process by the first handler; no
        # pool threads exist at all when the knob is off.
        self.pools = (
            get_ingest_pools(
                self.ingest_pools,
                self.ingest_chunk_size,
                self.ingest_pool_queue_bound,
                self.ingest_pipelined,
                self.ingest_dep_admission,
                self.logger,
            )
            if self.ingest_pools > 0
            else None
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

    def collect_member_refs(self, node: Any, member_ids: set, acc: set) -> None:
        # Mirror of mark_member_refs' key rules, collecting instead of suffixing:
        # the object's declared in-bundle dependencies (run BEFORE marking, on
        # clean ref values). Feeds the V2 dependency-aware admission.
        if isinstance(node, dict):
            for key, value in node.items():
                is_ref_key = key.endswith("_ref") or key.endswith("_refs")
                if is_ref_key and isinstance(value, str):
                    if value in member_ids:
                        acc.add(value)
                elif is_ref_key and isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item in member_ids:
                            acc.add(item)
                elif isinstance(value, (dict, list)):
                    self.collect_member_refs(value, member_ids, acc)
        elif isinstance(node, list):
            for item in node:
                self.collect_member_refs(item, member_ids, acc)

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
            # choice (wave_width since s9.11, bundle_parallelism before), not a
            # property of the bundle's shape.
            size = self.wave_width
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
                # s9.11: prove the runtime shape, not just the config file
                "wave_width": self.wave_width,
                "executor_budget": self.bundle_executor._max_workers,  # pylint: disable=protected-access
            },
        )
        # Per-object isolation (s9.8.4): pycti reports and drops failed objects internally
        # (import_item), so a future raising here is an ESCAPED error (transport, bundle
        # format). It must never abort the remaining waves nor discard the bundle message:
        # log, report the expectation for that object, and continue.
        # s9.11: results collect per OBJECT as they land (as_completed), not in
        # submission order: each object frees its slot and memory the moment IT is done,
        # the wave barrier only blocks on the LAST one, and the shared pool's freed
        # threads immediately serve other bundles' waves.
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
            for future in as_completed(futures):
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

    def import_bundle_chunked(
        self,
        content: Dict[str, Any],
        data: Dict[str, Any],
        work_id: Any,
        types: Any,
    ) -> List[Any]:
        # Chunked ingest pools (kb note opencti-worker-chunked-ingest-pools): same split +
        # member-ref marking as the inline path, then fixed-size chunks in SPLITTER order
        # (chunks may span dependency levels, decision Q4) all routed to ONE pool
        # (bundle-to-pool affinity, decision Q3): pool FIFO + the V1 barrier keep producer
        # chunks strictly ahead of dependent chunks. This handler thread then blocks until
        # every chunk reported terminal, so the caller's "ack" stays bundle-terminal
        # (decision Q1-B: at-least-once preserved, crash = RabbitMQ redelivery).
        t_start = time.monotonic()
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
        member_ids = {obj["id"] for obj in content.get("objects", []) if "id" in obj}
        # per-object in-bundle deps, collected BEFORE marking (clean ref values)
        deps_per_bundle: List[set] = []
        for mini_bundle in bundles:
            deps: set = set()
            for obj in mini_bundle.get("objects", []):
                self.collect_member_refs(obj, member_ids, deps)
                deps.discard(obj.get("id"))
            deps_per_bundle.append(deps)
            for obj in mini_bundle.get("objects", []):
                self.mark_member_refs(obj, member_ids)
        size = max(1, self.ingest_chunk_size)
        # V2 dependency-aware admission metadata: an entry's blocking deps are its
        # in-bundle producers sitting in an EARLIER chunk (splitter order puts
        # producers first, so a dep is never in a later chunk); same-chunk deps fly
        # together and are ordered platform-side (V1-equivalent semantics).
        chunk_of: Dict[str, int] = {}
        for position, mini_bundle in enumerate(bundles):
            for obj in mini_bundle.get("objects", []):
                obj_id = obj.get("id")
                if obj_id is not None and obj_id not in chunk_of:
                    chunk_of[obj_id] = position // size
        chunks: List[List[ChunkEntry]] = []
        for position, mini_bundle in enumerate(bundles):
            chunk_index = position // size
            if chunk_index >= len(chunks):
                chunks.append([])
            objs = mini_bundle.get("objects", [])
            raw_id = objs[0].get("id") if objs else None
            object_id = raw_id.replace(self.MEMBER_REF_MARK, "") if isinstance(raw_id, str) else raw_id
            blocking = {
                dep
                for dep in deps_per_bundle[position]
                if chunk_of.get(dep, chunk_index) < chunk_index
            }
            chunks[chunk_index].append(
                ChunkEntry(mini_bundle=mini_bundle, object_id=object_id, blocking_deps=blocking)
            )
        bundle_terminal: set = set()
        t_split_done = time.monotonic()
        tracker_lock = threading.Lock()
        bundle_done = threading.Event()
        remaining = len(chunks)
        imported_items: List[Any] = []
        too_large_items_bundles: List[Any] = []

        # Runs on a request thread; closes over this handler's pycti client (one bundle
        # in flight per handler at prefetch=1: header state is stable). The request
        # thread owns the object's retry loop through pycti (decision Q2-A).
        def import_one(mini_bundle: Dict[str, Any]):
            return self.api.stix2.import_bundle_from_json(
                json.dumps(mini_bundle), update, types, work_id, self.objects_max_refs
            )

        def on_object_error(err: Exception) -> None:
            self.logger.error(
                "Chunk object import failed, continuing the bundle",
                {"error": str(err)},
            )
            if work_id is not None:
                try:
                    self.api.work.report_expectation(
                        work_id, {"error": str(err), "source": "chunked import"}
                    )
                except Exception:  # pylint: disable=broad-except
                    pass

        def on_chunk_done(items: List[Any], too_large: List[Any]) -> None:
            nonlocal remaining
            with tracker_lock:
                imported_items.extend(items)
                too_large_items_bundles.extend(too_large)
                remaining -= 1
                is_last = remaining == 0
            if is_last:
                bundle_done.set()

        jobs = [
            ChunkJob(
                entries=chunk_entries,
                bundle_terminal=bundle_terminal,
                import_one=import_one,
                on_object_error=on_object_error,
                on_chunk_done=on_chunk_done,
            )
            for chunk_entries in chunks
        ]
        # bundle-contiguous post under the pool's submit lock (depth re-checked
        # under lock for least_full: see submit_bundle_atomic)
        pool = submit_bundle_atomic(self.pools, self.ingest_pick, jobs)
        t_posted = time.monotonic()
        self.logger.info(
            "Chunked bundle import",
            {
                "objects": expectations,
                "chunks": len(chunks),
                "chunk_size": size,
                "pool": pool.index,
                "pool_depth": pool.depth(),
                "pick": self.ingest_pick,
                "pipelined": self.ingest_pipelined,
                "dep_admission": self.ingest_dep_admission,
                "split_ms": round((t_split_done - t_start) * 1000, 1),
                "post_ms": round((t_posted - t_split_done) * 1000, 1),
            },
        )
        bundle_done.wait()
        chunked_split_seconds.record(t_split_done - t_start)
        chunked_post_seconds.record(t_posted - t_split_done)
        chunked_bundle_seconds.record(time.monotonic() - t_start)
        # dead-letter forwarding after completion, from the handler thread (one connection)
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
                    if self.pools is not None:
                        imported_items = self.import_bundle_chunked(
                            content, data, work_id, types
                        )
                    else:
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
