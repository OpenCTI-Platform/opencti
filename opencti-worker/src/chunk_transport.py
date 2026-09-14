"""Chunk-queue direct intake, worker side (kb note opencti-chunk-queue-direct-intake-design).

On this path the queue_thread keeps doing what it does today for an inline bundle
(split, mark in-bundle refs with ||M||) but instead of importing the objects over HTTP
through a thread pool it CAPTURES the GraphQL mutation pycti would have sent for each
object and publishes ONE RabbitMQ message per chunk of captured operations to the
platform chunk queue, consumed in process by the chunk intake manager. No ingest pool and
no HTTP leg for the objects themselves; HTTP stays for reads (pycti's one
getVocabCategories at client start) and for the work expectations.

Env-gated: WORKER_CHUNK_QUEUE=true (default off).
"""

import json
import threading
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

import pika
from pika.exceptions import AMQPError, NackError, UnroutableError

CHUNK_ROUTING_SUFFIX = "chunk_intake_routing"
ECHO_PREFIX = "echo--"


class ChunkQueueUnavailable(Exception):
    """No queue is bound on the chunk routing key: the platform manager is not enabled."""


def collect_echo_refs(value: Any, acc: set) -> None:
    """Collect every echo id referenced anywhere inside a variables tree."""
    if isinstance(value, str):
        if value.startswith(ECHO_PREFIX):
            acc.add(value)
    elif isinstance(value, dict):
        for item in value.values():
            collect_echo_refs(item, acc)
    elif isinstance(value, list):
        for item in value:
            collect_echo_refs(item, acc)


def build_chunks(
    operations: List[Dict[str, Any]], size: int
) -> List[List[Dict[str, Any]]]:
    """Group captured operations into chunks of `size` OBJECTS, in capture order.

    Producers (sub-object creates carrying an echo_id) do not count toward the size, and
    every chunk carries the producers its operations reference, even when pycti captured
    them in an earlier chunk (its bundle pre-pass creates all labels / external references
    / kill chain phases up front): those creates are idempotent upserts, so repeating one
    across chunks is safe, while a dangling echo id would fail the object platform-side.
    """
    producers = {op["echo_id"]: op for op in operations if op.get("echo_id")}
    chunks: List[List[Dict[str, Any]]] = []
    current: List[Dict[str, Any]] = []
    current_echo: set = set()
    objects_in_current = 0

    def close_current() -> None:
        nonlocal current, current_echo, objects_in_current
        if current:
            chunks.append(current)
        current, current_echo, objects_in_current = [], set(), 0

    for op in operations:
        if op.get("echo_id"):
            if op["echo_id"] not in current_echo:
                current.append(op)
                current_echo.add(op["echo_id"])
            continue
        if objects_in_current >= size:
            close_current()
        refs: set = set()
        collect_echo_refs(op.get("variables"), refs)
        for echo_id in refs:
            producer = producers.get(echo_id)
            if producer is not None and echo_id not in current_echo:
                current.append(producer)
                current_echo.add(echo_id)
        current.append(op)
        objects_in_current += 1
    close_current()
    return chunks


class _EchoData(dict):
    """GraphQL `data` object whose every root field resolves to the echo payload."""

    def __init__(self, echo: Dict[str, Any]) -> None:
        super().__init__()
        self._echo = echo

    def __missing__(self, _key: str) -> Dict[str, Any]:
        return self._echo


class ChunkCapture:
    """Capture transport on ONE pycti client (instance-level override of `query`).

    While a capture is open on the current thread, mutations are recorded and answered
    with an echo instead of being POSTed; reads, and every call outside a capture (work
    expectations, the writer lookup), go to the real API. Other clients are untouched.

    The echo carries the object's own STIX id as its id: pycti caches create responses
    (stix id -> internal id) and reuses them for later refs, so echoing the STIX id keeps
    every ref a STIX id, which is what the platform resolves anyway (with the ||M|| mark).
    """

    def __init__(self, api: Any) -> None:
        self._api = api
        self._real_query = api.query
        self._local = threading.local()
        api.query = self._query

    def _purge_echo_cache(self) -> None:
        # pycti caches the ids it gets back from sub-object creates (labels by value, kill
        # chain phases, external references) for the CLIENT's lifetime and reuses them
        # across bundles. An echo id is only meaningful inside the capture window that
        # produced it (its producer travels in that bundle's chunks), so drop every cached
        # echo entry when the window closes: the next bundle re-creates its sub-objects
        # (idempotent upserts, in process) with producers of its own.
        stix2 = getattr(self._api, "stix2", None)
        cache = getattr(stix2, "mapping_cache", None)
        if cache is None:
            return
        stale = [
            key
            for key, value in list(cache.items())
            if isinstance(value, dict)
            and str(value.get("id", "")).startswith(ECHO_PREFIX)
        ]
        for key in stale:
            try:
                del cache[key]
            except KeyError:
                pass

    def _query(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
        disable_impersonate: bool = False,
    ) -> Any:
        buffer = getattr(self._local, "buffer", None)
        if buffer is None or not query.lstrip().startswith("mutation"):
            return self._real_query(query, variables, disable_impersonate)
        variables = variables or {}
        # most pycti creates nest their fields under `input`; observables pass them at the
        # top level (stixCyberObservableAdd): look in both places for the STIX id
        payload = (
            variables.get("input")
            if isinstance(variables.get("input"), dict)
            else variables
        )
        stix_id = payload.get("stix_id") or variables.get("stix_id")
        # A create WITHOUT a STIX id is one of pycti's pre-created sub-objects (label,
        # external reference, kill chain phase): pycti reuses the id the platform returns
        # inside the owning object's input. Hand it a unique echo id and mark the operation
        # as its PRODUCER: the platform manager executes producers first and substitutes
        # the real ids before the objects run (worker-side there is no platform to ask).
        echo_id = None if stix_id else f"{ECHO_PREFIX}{uuid.uuid4()}"
        captured = {
            # whitespace-normalized: same document string every time, so the platform's
            # per-document parse cache hits and the message stays small
            "query": " ".join(query.split()),
            "variables": variables,
            "object_id": stix_id,
        }
        if echo_id:
            captured["echo_id"] = echo_id
        buffer.append(captured)
        # The echo carries the SCALAR input fields back on top of the ids: pycti reads some
        # of them after a create (vocabularies: `name`). Lists and objects are NOT echoed:
        # for relationship inputs (objectLabel, objectMarking, killChainPhases...) pycti
        # post-processes the API's response shape (lists of dicts), and the input's lists
        # of ids crash that post-processing (gate 11: 210 TypeErrors).
        echo = {
            **{
                k: v
                for k, v in payload.items()
                if isinstance(k, str) and isinstance(v, (str, int, float, bool))
            },
            "id": stix_id or echo_id,
            "standard_id": stix_id or echo_id,
            "entity_type": payload.get("type", "Unknown"),
            "parent_types": [],
            "observables": [],
        }
        return {"data": _EchoData(echo)}

    @contextmanager
    def capture(self) -> Iterator[List[Dict[str, Any]]]:
        buffer: List[Dict[str, Any]] = []
        self._local.buffer = buffer
        try:
            yield buffer
        finally:
            self._local.buffer = None
            self._purge_echo_cache()


class ChunkPublisher:
    """One persistent, confirmed pika channel per handler (a handler serves one queue thread).

    `mandatory=True` publishing: a chunk that no queue is bound to receive is refused by
    the broker instead of being dropped, which is how the worker learns the platform
    manager is not enabled and falls back to the HTTP path for that bundle.
    """

    def __init__(
        self,
        pika_parameters: pika.ConnectionParameters,
        exchange: str,
        routing_key: str,
        logger: Any,
    ) -> None:
        self.pika_parameters = pika_parameters
        self.exchange = exchange
        self.routing_key = routing_key
        self.logger = logger
        self.published_chunks = 0
        self._lock = threading.Lock()
        self._connection: Optional[pika.BlockingConnection] = None
        self._channel: Any = None

    def _channel_or_connect(self) -> Any:
        if (
            self._channel is None
            or self._channel.is_closed
            or self._connection is None
            or not self._connection.is_open
        ):
            self._connection = pika.BlockingConnection(self.pika_parameters)
            self._channel = self._connection.channel()
            self._channel.confirm_delivery()
        return self._channel

    def _reset(self) -> None:
        try:
            if self._connection is not None and self._connection.is_open:
                self._connection.close()
        except Exception:  # pylint: disable=broad-except
            pass
        self._connection = None
        self._channel = None

    def publish(self, message: Dict[str, Any]) -> None:
        body = json.dumps(message)
        last_error: Optional[Exception] = None
        with self._lock:
            for _attempt in range(3):
                try:
                    channel = self._channel_or_connect()
                    channel.basic_publish(
                        exchange=self.exchange,
                        routing_key=self.routing_key,
                        body=body,
                        properties=pika.BasicProperties(
                            delivery_mode=2, content_encoding="utf-8"
                        ),
                        mandatory=True,
                    )
                    self.published_chunks += 1
                    if self.published_chunks == 1:
                        # traceable proof that the chunk path actually RAN (gate assertion)
                        self.logger.info(
                            "First chunk published to the platform chunk queue",
                            {
                                "exchange": self.exchange,
                                "routing_key": self.routing_key,
                                "operations": len(message.get("operations", [])),
                            },
                        )
                    return
                except UnroutableError as err:
                    raise ChunkQueueUnavailable(
                        f"no queue bound on {self.routing_key}"
                    ) from err
                except (NackError, AMQPError) as err:
                    last_error = err
                    self._reset()
        raise (
            last_error
            if last_error is not None
            else RuntimeError("chunk publish failed")
        )
