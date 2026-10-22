"""Analysis pipeline: components, communities, clusters and betweenness."""

import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from opencti_analytics.classification import Cluster, ClusteringStats, build_clusters
from opencti_analytics.config import Settings
from opencti_analytics.engines import GraphEngine
from opencti_analytics.graph import AnalysisGraph

# Below 3 nodes no shortest path goes through a node: betweenness is exactly 0.
MIN_BETWEENNESS_COMPONENT_SIZE = 3


@dataclass
class AnalysisResult:  # pylint: disable=too-many-instance-attributes
    clusters: List[Cluster]
    cluster_of: Dict[int, Cluster]
    betweenness: Optional[List[float]]
    components: int
    largest_component: int
    hubs: int
    clustering: ClusteringStats
    betweenness_sources: int
    durations: Dict[str, float] = field(default_factory=dict)


def find_hubs(graph: AnalysisGraph, max_node_degree: int) -> List[bool]:
    return [degree > max_node_degree for degree in graph.degrees()]


def community_edges(
    graph: AnalysisGraph, hubs: Sequence[bool]
) -> List[Tuple[int, int]]:
    """Edges of the community detection graph: hubs are isolated, so they end up
    in singleton communities and never join a cluster."""
    return [(a, b) for a, b in graph.edges if not hubs[a] and not hubs[b]]


def sample_sources(
    graph: AnalysisGraph,
    components: Sequence[Sequence[int]],
    sample_size: int,
    seed: int,
) -> Tuple[List[int], Dict[int, int]]:
    """Shortest-path sources of every component, and the number of sources per
    component (keyed by its smallest node).

    Components up to `sample_size` nodes use every node (exact betweenness),
    larger ones a seeded sample of `sample_size` nodes. The generator of a
    component is seeded with its smallest id, so its sample does not change when
    another part of the graph changes.
    """
    sources: List[int] = []
    counts: Dict[int, int] = {}
    for component in components:
        if len(component) < MIN_BETWEENNESS_COMPONENT_SIZE:
            continue
        if len(component) <= sample_size:
            picked = list(component)
        else:
            rng = random.Random(f"{seed}:{graph.ids[component[0]]}")
            picked = sorted(rng.sample(list(component), sample_size))
        counts[component[0]] = len(picked)
        sources.extend(picked)
    sources.sort()
    return sources, counts


def normalize_betweenness(
    raw: Sequence[float],
    components: Sequence[Sequence[int]],
    sources_per_component: Dict[int, int],
) -> List[float]:
    """Scale to [0, 1] within each connected component.

    `raw` holds half the summed pair dependencies of the sampled sources; it is
    extrapolated to all the component's sources (size / sampled) and divided by
    the number of pairs a node can sit between ((n - 1)(n - 2) / 2).
    """
    result = [0.0] * len(raw)
    for component in components:
        size = len(component)
        sampled = sources_per_component.get(component[0], 0)
        if size < MIN_BETWEENNESS_COMPONENT_SIZE or sampled == 0:
            continue
        scale = 2.0 * (size / sampled) / ((size - 1) * (size - 2))
        for node in component:
            result[node] = min(1.0, max(0.0, raw[node] * scale))
    return result


def compute_betweenness(
    engine: GraphEngine,
    handle: Any,
    graph: AnalysisGraph,
    components: Sequence[Sequence[int]],
    settings: Settings,
) -> Tuple[Optional[List[float]], int]:
    """Approximate betweenness of every node, None when disabled.

    Without cutoff, shortest paths are counted from a sample of sources per
    component (Brandes-style estimation). With a cutoff, every node is a source
    but paths are limited to `betweenness_cutoff` hops (igraph cannot combine
    both, and neither does this process).
    """
    if settings.betweenness_sample_size <= 0:
        return None, 0
    if settings.betweenness_cutoff is not None:
        counts = {
            component[0]: len(component)
            for component in components
            if len(component) >= MIN_BETWEENNESS_COMPONENT_SIZE
        }
        raw = engine.betweenness(handle, None, settings.betweenness_cutoff)
        return normalize_betweenness(raw, components, counts), graph.node_count
    sources, counts = sample_sources(
        graph, components, settings.betweenness_sample_size, settings.seed
    )
    if not sources:
        return [0.0] * graph.node_count, 0
    raw = engine.betweenness(handle, sources, None)
    return normalize_betweenness(raw, components, counts), len(sources)


def analyze(
    graph: AnalysisGraph, engine: GraphEngine, settings: Settings
) -> AnalysisResult:
    durations: Dict[str, float] = {}
    if graph.node_count == 0:
        return AnalysisResult(
            clusters=[],
            cluster_of={},
            betweenness=None if settings.betweenness_sample_size <= 0 else [],
            components=0,
            largest_component=0,
            hubs=0,
            clustering=ClusteringStats(),
            betweenness_sources=0,
            durations=durations,
        )

    started = time.monotonic()
    handle = engine.build(graph.node_count, graph.edges)
    components = engine.connected_components(handle)
    durations["components"] = time.monotonic() - started

    started = time.monotonic()
    hubs = find_hubs(graph, settings.max_node_degree)
    community_handle = engine.build(graph.node_count, community_edges(graph, hubs))
    communities = engine.label_propagation(community_handle, settings.seed)
    del community_handle
    clusters, clustering = build_clusters(
        graph, communities, settings.min_cluster_size, settings.max_cluster_size
    )
    durations["communities"] = time.monotonic() - started

    started = time.monotonic()
    betweenness, sources = compute_betweenness(
        engine, handle, graph, components, settings
    )
    durations["betweenness"] = time.monotonic() - started

    cluster_of: Dict[int, Cluster] = {}
    for cluster in clusters:
        for member in cluster.members:
            cluster_of[member] = cluster
    return AnalysisResult(
        clusters=clusters,
        cluster_of=cluster_of,
        betweenness=betweenness,
        components=len(components),
        largest_component=max((len(c) for c in components), default=0),
        hubs=sum(1 for hub in hubs if hub),
        clustering=clustering,
        betweenness_sources=sources,
        durations=durations,
    )
