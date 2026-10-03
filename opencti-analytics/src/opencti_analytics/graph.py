"""Undirected simple graph built from the platform edges export.

Nodes are indexed in ascending order of their internal id, edges are stored once
as sorted (low, high) index pairs: the same input always gives the same graph,
whatever the order in which the platform returned the edges.
"""

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

CONTAINMENT_RELATIONSHIP = "object"

CONTAINER_TYPES: FrozenSet[str] = frozenset(
    {
        "Report",
        "Grouping",
        "Note",
        "Opinion",
        "Observed-Data",
        "Case-Incident",
        "Case-Rfi",
        "Case-Rft",
        "Feedback",
        "Task",
    }
)

_EDGE_KEY_SHIFT = 32


@dataclass(frozen=True)
class EdgeRecord:
    id: str
    relationship_type: str
    from_id: str
    from_type: str
    to_id: str
    to_type: str


@dataclass
class BuildStats:
    received_edges: int = 0
    self_loops: int = 0
    relationship_refs: int = 0
    containment_edges: int = 0
    oversized_containers: int = 0
    dropped_containment_edges: int = 0


def is_relationship_type(entity_type: str) -> bool:
    # Entity types are capitalized (Intrusion-Set, IPv4-Addr, Url), relationship
    # types are not (uses, stix-sighting-relationship): containers can reference
    # relationships, which are not nodes of the analyzed graph.
    return not entity_type[:1].isupper()


@dataclass
class AnalysisGraph:
    ids: List[str]
    types: List[str]
    edges: List[Tuple[int, int]]
    is_container: List[bool]
    stats: BuildStats = field(default_factory=BuildStats)
    _adjacency: Optional[List[List[int]]] = field(default=None, repr=False)

    @property
    def node_count(self) -> int:
        return len(self.ids)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def adjacency(self) -> List[List[int]]:
        if self._adjacency is None:
            adjacency: List[List[int]] = [[] for _ in range(self.node_count)]
            for low, high in self.edges:
                adjacency[low].append(high)
                adjacency[high].append(low)
            for neighbors in adjacency:
                neighbors.sort()
            self._adjacency = adjacency
        return self._adjacency

    def degrees(self) -> List[int]:
        return [len(neighbors) for neighbors in self.adjacency()]


class GraphBuilder:
    """Accumulates platform edges, then builds the deterministic analysis graph.

    `object` edges (container -> contained object) are kept apart until `build`:
    containers referencing more than `max_container_size` entities are dropped
    from the containment layer, they would otherwise turn into giant hubs linking
    unrelated knowledge.
    """

    def __init__(self, max_container_size: int) -> None:
        self.max_container_size = max_container_size
        self.stats = BuildStats()
        self._index: Dict[str, int] = {}
        self._ids: List[str] = []
        self._types: List[str] = []
        self._edges: Set[int] = set()
        self._containment: Dict[int, Set[int]] = {}

    def _node(self, node_id: str, node_type: str) -> int:
        index = self._index.get(node_id)
        if index is None:
            index = len(self._ids)
            self._index[node_id] = index
            self._ids.append(node_id)
            self._types.append(node_type)
        return index

    @staticmethod
    def _key(a: int, b: int) -> int:
        low, high = (a, b) if a < b else (b, a)
        return (low << _EDGE_KEY_SHIFT) | high

    def add(self, edge: EdgeRecord) -> None:
        self.stats.received_edges += 1
        if is_relationship_type(edge.from_type) or is_relationship_type(edge.to_type):
            self.stats.relationship_refs += 1
            return
        if edge.from_id == edge.to_id:
            self.stats.self_loops += 1
            return
        source = self._node(edge.from_id, edge.from_type)
        target = self._node(edge.to_id, edge.to_type)
        if edge.relationship_type == CONTAINMENT_RELATIONSHIP:
            self.stats.containment_edges += 1
            self._containment.setdefault(source, set()).add(target)
        else:
            self._edges.add(self._key(source, target))

    def build(self) -> AnalysisGraph:
        self.stats.oversized_containers = 0
        self.stats.dropped_containment_edges = 0
        edge_keys = set(self._edges)
        containers: Set[int] = set()
        for container, objects in self._containment.items():
            if len(objects) > self.max_container_size:
                self.stats.oversized_containers += 1
                self.stats.dropped_containment_edges += len(objects)
                continue
            containers.add(container)
            for target in objects:
                edge_keys.add(self._key(container, target))
        mask = (1 << _EDGE_KEY_SHIFT) - 1
        used: Set[int] = set()
        for key in edge_keys:
            used.add(key >> _EDGE_KEY_SHIFT)
            used.add(key & mask)
        ordered = sorted(used, key=lambda old: self._ids[old])
        remap = {old: new for new, old in enumerate(ordered)}
        edges: List[Tuple[int, int]] = []
        for key in edge_keys:
            a = remap[key >> _EDGE_KEY_SHIFT]
            b = remap[key & mask]
            edges.append((a, b) if a < b else (b, a))
        edges.sort()
        types = [self._types[old] for old in ordered]
        is_container = [
            old in containers or self._types[old] in CONTAINER_TYPES for old in ordered
        ]
        return AnalysisGraph(
            ids=[self._ids[old] for old in ordered],
            types=types,
            edges=edges,
            is_container=is_container,
            stats=self.stats,
        )
