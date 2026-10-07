"""Test helpers: readable node ids and small graphs, no network."""

import uuid
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from opencti_analytics.config import Settings
from opencti_analytics.engines import GraphEngine, NetworkxEngine, igraph_available
from opencti_analytics.graph import AnalysisGraph, EdgeRecord, GraphBuilder

NodeSpec = Tuple[str, str]  # (id, entity type)


def node_id(name: str) -> str:
    """Stable UUID per readable name, so ids sort like real internal ids."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, name))


def edge(
    source: NodeSpec,
    target: NodeSpec,
    relationship_type: str = "related-to",
) -> EdgeRecord:
    return EdgeRecord(
        id=node_id(f"{source[0]}|{relationship_type}|{target[0]}"),
        relationship_type=relationship_type,
        from_id=node_id(source[0]),
        from_type=source[1],
        to_id=node_id(target[0]),
        to_type=target[1],
    )


def build_graph(
    edges: Iterable[EdgeRecord], max_container_size: int = 500
) -> AnalysisGraph:
    builder = GraphBuilder(max_container_size)
    for record in edges:
        builder.add(record)
    return builder.build()


def index_of(graph: AnalysisGraph, name: str) -> int:
    return graph.ids.index(node_id(name))


def settings(**overrides: Any) -> Settings:
    values: Dict[str, Any] = {
        "opencti_url": "http://localhost:8080",
        "opencti_token": "token",
        "min_edges": 0,
    }
    values.update(overrides)
    return Settings(**values)


def engines() -> List[GraphEngine]:
    result: List[GraphEngine] = [NetworkxEngine()]
    if igraph_available():
        from opencti_analytics.engines import IgraphEngine

        result.append(IgraphEngine())
    return result


def engine_ids() -> List[str]:
    return [engine.name for engine in engines()]


def clique(prefix: str, size: int, entity_type: str) -> List[EdgeRecord]:
    nodes = [(f"{prefix}-{i}", entity_type) for i in range(size)]
    return [edge(nodes[i], nodes[j]) for i in range(size) for j in range(i + 1, size)]


class FakeApi:
    """pycti OpenCTIApiClient stand-in: replays responses, records calls."""

    def __init__(self, responses: Optional[Sequence[Any]] = None) -> None:
        self.responses = list(responses or [])
        self.calls: List[Tuple[str, Dict[str, Any]]] = []

    def query(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Any:
        self.calls.append((query, variables or {}))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response
