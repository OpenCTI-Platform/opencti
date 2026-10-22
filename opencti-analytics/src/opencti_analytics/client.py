"""GraphQL access to the platform graph analytics contract, with retries."""

import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, Optional, Protocol, Sequence

from opencti_analytics.graph import EdgeRecord

EDGES_PAGE_SIZE = 5000  # platform maximum for graphAnalyticsEdges

# Errors a retry cannot fix: wrong token or capabilities, rejected input, or a
# platform that does not expose the graph analytics contract.
NON_RETRYABLE_ERRORS = frozenset(
    {
        "AUTH_FAILURE",
        "AUTH_REQUIRED",
        "FORBIDDEN_ACCESS",
        "FUNCTIONAL_ERROR",
        "UNSUPPORTED_ERROR",
        "VALIDATION_ERROR",
        "GRAPHQL_VALIDATION_FAILED",
        "BAD_USER_INPUT",
    }
)

EDGES_QUERY = """
    query GraphAnalyticsEdges(
        $relationshipTypes: [String!]!
        $includeInferred: Boolean
        $first: Int
        $after: ID
    ) {
        graphAnalyticsEdges(
            relationshipTypes: $relationshipTypes
            includeInferred: $includeInferred
            first: $first
            after: $after
        ) {
            pageInfo {
                endCursor
                hasNextPage
                globalCount
            }
            edges {
                node {
                    id
                    relationship_type
                    from_id
                    from_type
                    to_id
                    to_type
                }
            }
        }
    }
"""

STATUS_QUERY = """
    query GraphAnalyticsStatus {
        graphAnalyticsStatus {
            manager_enabled
            pending_entities
            similarity_documents
            clusters_count
            analytics_process_active
            analytics_process_last_run_at
            analytics_process_last_run_id
            analytics_process_version
        }
    }
"""

UPSERT_MUTATION = """
    mutation GraphAnalyticsUpsertMetrics($input: GraphAnalyticsUpsertMetricsInput!) {
        graphAnalyticsUpsertMetrics(input: $input) {
            run_id
            updated_entities
            skipped_entities
            upserted_clusters
            removed_clusters
        }
    }
"""


class ApiClient(Protocol):  # pylint: disable=too-few-public-methods
    def query(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Any:
        """pycti OpenCTIApiClient.query"""


class Logger(Protocol):
    def debug(self, message: str, meta: Optional[Dict[str, Any]] = None) -> None:
        """Debug log."""

    def info(self, message: str, meta: Optional[Dict[str, Any]] = None) -> None:
        """Info log."""

    def warning(self, message: str, meta: Optional[Dict[str, Any]] = None) -> None:
        """Warning log."""

    def error(self, message: str, meta: Optional[Dict[str, Any]] = None) -> None:
        """Error log."""


class RunCancelled(Exception):
    """A shutdown was requested while the run was in progress."""


class EdgesPaginationError(Exception):
    """The edges export announced more pages but its cursor did not move."""


@dataclass(frozen=True)
class RetryPolicy:
    attempts: int = 5
    initial_delay: float = 2.0
    max_delay: float = 60.0


def error_name(error: Exception) -> Optional[str]:
    # pycti raises ValueError({"name": ..., "error_message": ...}) on API errors
    if error.args and isinstance(error.args[0], dict):
        name = error.args[0].get("name")
        return str(name) if name is not None else None
    return None


class AnalyticsClient:
    def __init__(
        self,
        api: ApiClient,
        logger: Logger,
        retry: RetryPolicy = RetryPolicy(),
        stop_event: Optional[threading.Event] = None,
        wait: Optional[Callable[[float], bool]] = None,
    ) -> None:
        self.api = api
        self.logger = logger
        self.retry = retry
        self.stop_event = stop_event or threading.Event()
        # returns True when the wait was interrupted by a shutdown request
        self._wait = wait or self.stop_event.wait

    def _query(self, operation: str, query: str, variables: Dict[str, Any]) -> Any:
        delay = self.retry.initial_delay
        attempt = 1
        while True:
            if self.stop_event.is_set():
                raise RunCancelled(operation)
            try:
                result = self.api.query(query, variables)
                data = result.get("data") if isinstance(result, dict) else None
                if data is None:
                    raise ValueError(f"Empty response for {operation}")
                return data
            except Exception as e:  # pylint: disable=broad-except
                name = error_name(e)
                if name in NON_RETRYABLE_ERRORS or attempt >= self.retry.attempts:
                    raise
                self.logger.warning(
                    "Graph analytics API call failed, retrying",
                    {
                        "operation": operation,
                        "attempt": attempt,
                        "retry_in_seconds": delay,
                        "error": name or type(e).__name__,
                        "reason": str(e),
                    },
                )
                if self._wait(delay):
                    raise RunCancelled(operation) from e
                delay = min(delay * 2, self.retry.max_delay)
                attempt += 1

    def status(self) -> Dict[str, Any]:
        data = self._query("graphAnalyticsStatus", STATUS_QUERY, {})
        return dict(data.get("graphAnalyticsStatus") or {})

    def count_edges(
        self, relationship_types: Sequence[str], include_inferred: bool
    ) -> Dict[str, int]:
        """globalCount of each relationship type, read from a one-edge page."""
        counts: Dict[str, int] = {}
        for relationship_type in relationship_types:
            data = self._query(
                "graphAnalyticsEdges",
                EDGES_QUERY,
                {
                    "relationshipTypes": [relationship_type],
                    "includeInferred": include_inferred,
                    "first": 1,
                    "after": None,
                },
            )
            connection = data.get("graphAnalyticsEdges") or {}
            page_info = connection.get("pageInfo") or {}
            counts[relationship_type] = int(page_info.get("globalCount") or 0)
        return counts

    def iter_edges(
        self,
        relationship_type: str,
        include_inferred: bool,
        page_size: int = EDGES_PAGE_SIZE,
    ) -> Iterator[EdgeRecord]:
        """All the edges of one relationship type, following the cursors."""
        after: Optional[str] = None
        while True:
            data = self._query(
                "graphAnalyticsEdges",
                EDGES_QUERY,
                {
                    "relationshipTypes": [relationship_type],
                    "includeInferred": include_inferred,
                    "first": page_size,
                    "after": after,
                },
            )
            connection = data.get("graphAnalyticsEdges") or {}
            edges = connection.get("edges") or []
            for edge in edges:
                node = edge.get("node") or {}
                yield EdgeRecord(
                    id=str(node.get("id", "")),
                    relationship_type=str(node.get("relationship_type", "")),
                    from_id=str(node.get("from_id", "")),
                    from_type=str(node.get("from_type", "")),
                    to_id=str(node.get("to_id", "")),
                    to_type=str(node.get("to_type", "")),
                )
            page_info = connection.get("pageInfo") or {}
            next_cursor = page_info.get("endCursor")
            if not page_info.get("hasNextPage"):
                return
            # A page can be empty when the account cannot read the endpoints
            # of its relationships: only the cursor tells the progress
            if not next_cursor or next_cursor == after:
                # A partial export must never complete a run: it would
                # detach every omitted entity
                raise EdgesPaginationError(
                    f"Edges pagination made no progress for {relationship_type}"
                    f" after cursor {after}"
                )
            after = next_cursor

    def upsert_metrics(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        data = self._query(
            "graphAnalyticsUpsertMetrics", UPSERT_MUTATION, {"input": payload}
        )
        return dict(data.get("graphAnalyticsUpsertMetrics") or {})
