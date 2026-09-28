"""POC ingestion sequencer, study 0011 option 2 (kb plan 0011, note
opencti-graphql-request-pipeline-cost-map): batch outbound GraphQL calls into
Apollo HTTP batches (one POST carrying a JSON ARRAY of operations; Apollo builds
ONE context per POST and runs the operations concurrently, so unlike aliased
root fields nothing is serialized). Platform side requires
APP__GRAPHQL__HTTP_BATCHING=true (allowBatchedHttpRequests).

Transport-level micro-batcher: pycti keeps owning the STIX -> mutation mapping
and the per-object retry loops; only OpenCTIApiClient.query is wrapped. Calls
landing on the same client within a short linger window are flushed as one
array POST; per-item "errors" are re-raised as the same ValueError shape
pycti's query() raises, so callers cannot tell the transport changed.

Correctness guards:
- a batch shares ONE set of HTTP headers (one Apollo context): only calls whose
  captured header snapshot is identical are grouped (applicant-id, retry-number
  and work-id headers mutate on the client between calls);
- multipart (file upload) queries bypass the batcher (spec: no batching+upload);
- a single-item flush is sent as a plain object POST, byte-identical to stock.

Env-gated: WORKER_GQL_BATCH=<max batch size> (unset/0 = off),
WORKER_GQL_BATCH_LINGER_MS=<window, default 3>.
"""

import os
import threading
from concurrent.futures import Future
from typing import Any, Dict, List, Tuple

from opentelemetry import metrics as otel_metrics

# Batch size distribution, scraped by the bench Prometheus (worker job): mean =
# rate(_sum)/rate(_count), spread via histogram_quantile on the buckets. Same
# module-level OTel pattern as push_handler's chunked_* instruments.
gql_batch_meter = otel_metrics.get_meter(__name__)
gql_batch_size = gql_batch_meter.create_histogram(
    name="opencti_worker_gql_batch_size",
    description="Operations per outbound GraphQL HTTP batch (1 = unbatched POST)",
    unit="1",
)


class GraphQLBatcher:
    def __init__(self, api_client: Any, max_size: int, linger_ms: float, logger: Any) -> None:
        self.client = api_client
        self.max_size = max(2, max_size)
        self.linger_s = max(0.0, linger_ms) / 1000.0
        self.logger = logger
        self._orig_query = api_client.query
        self._lock = threading.Condition()
        # (headers_key, headers, payload, future)
        self._buffer: List[Tuple[Any, Dict, Dict, Future]] = []
        self._batches = 0
        self._batched_items = 0
        self._max_size_seen = 0
        self._multi_seen = False
        self._flusher = threading.Thread(
            target=self._run, name="gql-batch-flusher", daemon=True
        )
        self._flusher.start()
        api_client.query = self._query

    # -- caller side (request threads) ---------------------------------------

    def _query(self, query: str, variables: Any = None, disable_impersonate: bool = False) -> Any:
        variables = variables or {}
        # multipart uploads keep the stock path (no batching per the spec)
        _, files_vars = self.client._extract_files(variables)  # pylint: disable=protected-access
        if files_vars:
            return self._orig_query(query, variables, disable_impersonate)
        headers = self.client.request_headers.copy()
        if disable_impersonate and "opencti-applicant-id" in headers:
            del headers["opencti-applicant-id"]
        headers_key = tuple(sorted(headers.items()))
        future: Future = Future()
        with self._lock:
            self._buffer.append((headers_key, headers, {"query": query, "variables": variables}, future))
            self._lock.notify()
        return future.result()  # re-raises the flusher's per-item exception

    # -- flusher side ----------------------------------------------------------

    def _run(self) -> None:
        while True:
            with self._lock:
                while not self._buffer:
                    self._lock.wait()
            # linger: let concurrent request threads of the same bundle pile up
            if self.linger_s:
                threading.Event().wait(self.linger_s)
            with self._lock:
                drained, self._buffer = self._buffer, []
            groups: Dict[Any, List[Tuple[Dict, Dict, Future]]] = {}
            for headers_key, headers, payload, future in drained:
                groups.setdefault(headers_key, []).append((headers, payload, future))
            for items in groups.values():
                for start in range(0, len(items), self.max_size):
                    self._flush(items[start:start + self.max_size])

    def _flush(self, items: List[Tuple[Dict, Dict, Future]]) -> None:
        headers = items[0][0]
        payloads = [payload for _, payload, _ in items]
        futures = [future for _, _, future in items]
        try:
            client = self.client
            response = client.session.post(
                client.api_url,
                json=payloads if len(payloads) > 1 else payloads[0],
                headers=headers,
                verify=client.ssl_verify,
                cert=client.cert,
                proxies=client.proxies,
                timeout=client.session_requests_timeout,
            )
            if response.status_code != 200:
                raise ValueError(response.text)
            results = response.json()
            if len(payloads) == 1:
                results = [results]
            if not isinstance(results, list) or len(results) != len(payloads):
                raise ValueError(
                    "GraphQL batch response shape mismatch (is "
                    "APP__GRAPHQL__HTTP_BATCHING enabled platform-side?)"
                )
        except Exception as err:  # pylint: disable=broad-except
            for future in futures:
                future.set_exception(err if isinstance(err, ValueError) else ValueError(str(err)))
            return
        gql_batch_size.record(len(payloads))
        with self._lock:
            self._batches += 1
            self._batched_items += len(payloads)
            self._max_size_seen = max(self._max_size_seen, len(payloads))
            if len(payloads) > 1 and not self._multi_seen:
                # first multi-item batch: the smoke gate greps this line to prove
                # the batched path actually engaged (not a silent per-item fallback)
                self._multi_seen = True
                self.logger.info("GraphQL batch transport first multi-item batch", {"size": len(payloads)})
            if self._batches % 500 == 0:
                self.logger.info(
                    "GraphQL batch transport stats",
                    {
                        "batches": self._batches,
                        "mean_size": round(self._batched_items / self._batches, 2),
                        "max_size": self._max_size_seen,
                    },
                )
        for payload, future in zip(results, futures):
            # same per-item contract as pycti query(): errors -> ValueError
            if "errors" in payload:
                main_error = payload["errors"][0]
                error_name = main_error.get("name", main_error.get("message"))
                meta_data = dict(main_error.get("data") or {})
                meta_data.pop("input", None)
                future.set_exception(
                    ValueError({"name": error_name, "error_message": main_error.get("message"), **meta_data})
                )
            else:
                future.set_result(payload)


def install_graphql_batcher(api_client: Any, logger: Any) -> None:
    size_raw = os.getenv("WORKER_GQL_BATCH", "")
    if not size_raw or int(size_raw) <= 0:
        return
    linger_ms = float(os.getenv("WORKER_GQL_BATCH_LINGER_MS", "3"))
    GraphQLBatcher(api_client, int(size_raw), linger_ms, logger)
    logger.info(
        "GraphQL batch transport enabled",
        {"max_size": int(size_raw), "linger_ms": linger_ms},
    )
