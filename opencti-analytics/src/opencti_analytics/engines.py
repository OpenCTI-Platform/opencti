"""Graph engines: python-igraph (preferred, C core) and networkx (fallback).

Both engines work on the same index space (nodes 0..n-1, sorted by internal id)
and return normalized structures (sorted members, groups ordered by their
smallest member), so the pipeline never depends on engine-specific ordering.
"""

import importlib
import random
from abc import ABC, abstractmethod
from collections import deque
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import networkx as nx

Edges = Sequence[Tuple[int, int]]


def normalize_groups(groups: Iterable[Iterable[int]]) -> List[List[int]]:
    result = [sorted(group) for group in groups]
    result = [group for group in result if group]
    result.sort(key=lambda group: group[0])
    return result


class GraphEngine(ABC):
    name = "abstract"

    @abstractmethod
    def build(self, node_count: int, edges: Edges) -> Any:
        """Build the engine-specific graph handle."""

    @abstractmethod
    def connected_components(self, handle: Any) -> List[List[int]]:
        """Connected components, normalized."""

    @abstractmethod
    def label_propagation(self, handle: Any, seed: int) -> List[List[int]]:
        """Label propagation communities, normalized and seeded."""

    @abstractmethod
    def betweenness(
        self, handle: Any, sources: Optional[List[int]], cutoff: Optional[int]
    ) -> List[float]:
        """Unnormalized undirected betweenness restricted to shortest paths
        starting from `sources` (all nodes when None) and no longer than
        `cutoff` (unbounded when None). Each source contributes half of its pair
        dependencies, so `sources=None` gives the exact betweenness."""


class IgraphEngine(GraphEngine):
    name = "igraph"

    def __init__(self) -> None:
        self._igraph = importlib.import_module("igraph")

    def build(self, node_count: int, edges: Edges) -> Any:
        return self._igraph.Graph(n=node_count, edges=list(edges), directed=False)

    def connected_components(self, handle: Any) -> List[List[int]]:
        return normalize_groups(handle.connected_components(mode="weak"))

    def label_propagation(self, handle: Any, seed: int) -> List[List[int]]:
        # igraph draws its random numbers from a pluggable generator (the global
        # `random` module by default): a dedicated seeded one makes runs repeatable.
        self._igraph.set_random_number_generator(random.Random(seed))
        try:
            clustering = handle.community_label_propagation()
        finally:
            self._igraph.set_random_number_generator(random)
        return normalize_groups(clustering)

    def betweenness(
        self, handle: Any, sources: Optional[List[int]], cutoff: Optional[int]
    ) -> List[float]:
        node_count = handle.vcount()
        if cutoff is not None:
            if sources is not None:
                raise ValueError("igraph cannot combine source sampling and cutoff")
            return [float(v) for v in handle.betweenness(directed=False, cutoff=cutoff)]
        if sources is not None and len(sources) == 0:
            return [0.0] * node_count
        if sources is None or len(sources) == node_count:
            return [float(v) for v in handle.betweenness(directed=False)]
        return [
            float(v) for v in handle.betweenness(directed=False, sources=list(sources))
        ]


def accumulate_dependencies(
    adjacency: Sequence[Sequence[int]],
    source: int,
    cutoff: Optional[int],
    scores: List[float],
) -> None:
    """Brandes single-source accumulation, shortest paths up to `cutoff` hops."""
    stack: List[int] = []
    predecessors: Dict[int, List[int]] = {source: []}
    sigma: Dict[int, float] = {source: 1.0}
    distance: Dict[int, int] = {source: 0}
    queue = deque([source])
    while queue:
        v = queue.popleft()
        stack.append(v)
        next_distance = distance[v] + 1
        if cutoff is not None and next_distance > cutoff:
            continue
        for w in adjacency[v]:
            if w not in distance:
                distance[w] = next_distance
                sigma[w] = 0.0
                predecessors[w] = []
                queue.append(w)
            if distance[w] == next_distance:
                sigma[w] += sigma[v]
                predecessors[w].append(v)
    delta: Dict[int, float] = dict.fromkeys(stack, 0.0)
    while stack:
        w = stack.pop()
        coefficient = (1.0 + delta[w]) / sigma[w]
        for v in predecessors[w]:
            delta[v] += sigma[v] * coefficient
        if w != source:
            scores[w] += delta[w]


class NetworkxEngine(GraphEngine):
    name = "networkx"

    def build(self, node_count: int, edges: Edges) -> Any:
        graph = nx.Graph()
        graph.add_nodes_from(range(node_count))
        graph.add_edges_from(edges)
        return graph

    def connected_components(self, handle: Any) -> List[List[int]]:
        return normalize_groups(nx.connected_components(handle))

    def label_propagation(self, handle: Any, seed: int) -> List[List[int]]:
        return normalize_groups(nx.community.asyn_lpa_communities(handle, seed=seed))

    def betweenness(
        self, handle: Any, sources: Optional[List[int]], cutoff: Optional[int]
    ) -> List[float]:
        # networkx has no cutoff nor explicit source list for betweenness: the
        # Brandes accumulation is run directly on its adjacency, which keeps the
        # exact same semantics as igraph (validated against
        # networkx.betweenness_centrality in the tests).
        node_count = handle.number_of_nodes()
        adjacency = [list(handle.adj[v]) for v in range(node_count)]
        scores = [0.0] * node_count
        for source in range(node_count) if sources is None else sources:
            accumulate_dependencies(adjacency, source, cutoff, scores)
        return [score / 2.0 for score in scores]


def igraph_available() -> bool:
    try:
        importlib.import_module("igraph")
    except ImportError:
        return False
    return True


def select_engine(name: str) -> GraphEngine:
    """`auto` prefers igraph and falls back to networkx when it is not installed."""
    if name == "networkx":
        return NetworkxEngine()
    if name == "igraph":
        return IgraphEngine()
    if igraph_available():
        return IgraphEngine()
    return NetworkxEngine()
