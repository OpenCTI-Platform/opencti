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


class ChunkQueueUnavailable(Exception):
    """No queue is bound on the chunk routing key: the platform manager is not enabled."""


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
        self._real_query = api.query
        self._local = threading.local()
        api.query = self._query

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
        buffer.append(
            {
                # whitespace-normalized: same document string every time, so the platform's
                # per-document parse cache hits and the message stays small
                "query": " ".join(query.split()),
                "variables": variables,
                "object_id": stix_id,
            }
        )
        echo = {
            "id": stix_id or f"echo--{uuid.uuid4()}",
            "standard_id": stix_id or "echo--unknown",
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
