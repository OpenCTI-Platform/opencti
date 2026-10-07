"""Cluster identity, kind classification, representatives and shared features."""

import hashlib
import uuid
from collections import Counter
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from opencti_analytics.graph import AnalysisGraph

# Shared with the platform (graphAnalytics-clustering.ts): never change it, cluster
# ids would no longer match between the platform manager and this process.
# These ids are provisional: when a run is published, the platform gives a cluster
# the id of the previous cluster most of whose members it holds.
CLUSTER_NAMESPACE = uuid.UUID("b639ff3b-00eb-42ed-aa36-a8dd6f8fb4cf")

KIND_INFRASTRUCTURE = "infrastructure"
KIND_TOOLING = "tooling"
KIND_CAMPAIGN = "campaign"
# Tie-break of the majority vote: the most specific kind wins, campaign is the
# catch-all kind.
KIND_PRIORITY: Tuple[str, ...] = (KIND_INFRASTRUCTURE, KIND_TOOLING, KIND_CAMPAIGN)

INFRASTRUCTURE_TYPES: FrozenSet[str] = frozenset(
    {
        "Infrastructure",
        "IPv4-Addr",
        "IPv6-Addr",
        "Domain-Name",
        "Hostname",
        "Url",
        "X509-Certificate",
        "Autonomous-System",
        "Mac-Addr",
    }
)
TOOLING_TYPES: FrozenSet[str] = frozenset({"Malware", "Tool", "Attack-Pattern"})

FEATURE_FAMILY_BY_TYPE: Dict[str, str] = {
    "X509-Certificate": "certificates",
    "Autonomous-System": "asn",
    "Organization": "registrar",
    "Individual": "registrar",
    "Domain-Name": "nameservers",
    "Hostname": "nameservers",
    "IPv4-Addr": "hosting",
    "IPv6-Addr": "hosting",
    "Report": "reports",
    "Attack-Pattern": "techniques",
    "Tool": "tools",
    "Malware": "malware",
    "Infrastructure": "infrastructure",
    "Sector": "victims",
    "Country": "victims",
    "Region": "victims",
    "City": "victims",
    "Administrative-Area": "victims",
}

MAX_REPRESENTATIVES = 5
MAX_FEATURE_IDS = 50
MIN_FEATURE_LINKS = 2


def build_cluster_id(kind: str, anchor: str) -> str:
    """uuid5(CLUSTER_NAMESPACE, f"graph-cluster:{kind}:{anchor}")."""
    # Same bytes as uuid.uuid5, with an explicit non-security SHA-1 so the
    # identifier can be computed by FIPS-enabled Python builds.
    name = f"graph-cluster:{kind}:{anchor}".encode("utf-8")
    digest = hashlib.sha1(CLUSTER_NAMESPACE.bytes + name, usedforsecurity=False)
    return str(uuid.UUID(bytes=digest.digest()[:16], version=5))


def entity_kind(entity_type: str) -> str:
    if entity_type in INFRASTRUCTURE_TYPES:
        return KIND_INFRASTRUCTURE
    if entity_type in TOOLING_TYPES:
        return KIND_TOOLING
    return KIND_CAMPAIGN


def classify_kind(entity_types: Iterable[str]) -> str:
    counts = Counter(entity_kind(entity_type) for entity_type in entity_types)
    return max(
        KIND_PRIORITY,
        key=lambda kind: (counts[kind], -KIND_PRIORITY.index(kind)),
    )


@dataclass(frozen=True)
class ClusterFeature:
    family: str
    ids: Tuple[str, ...]


@dataclass(frozen=True)
class Cluster:
    cluster_id: str
    kind: str
    anchor: str
    members: Tuple[int, ...]
    representative_ids: Tuple[str, ...]
    features: Tuple[ClusterFeature, ...]

    @property
    def members_count(self) -> int:
        return len(self.members)


@dataclass
class ClusteringStats:
    communities: int = 0
    too_small: int = 0
    too_large: int = 0
    clusters: int = 0


def select_representatives(
    graph: AnalysisGraph, community: Sequence[int], members: Sequence[int]
) -> Tuple[str, ...]:
    """Top members by degree inside the community, ties by id."""
    adjacency = graph.adjacency()
    inside = set(community)
    ranked = sorted(
        members,
        key=lambda m: (-sum(1 for n in adjacency[m] if n in inside), graph.ids[m]),
    )
    return tuple(graph.ids[m] for m in ranked[:MAX_REPRESENTATIVES])


def extract_features(
    graph: AnalysisGraph, members: Sequence[int]
) -> Tuple[ClusterFeature, ...]:
    """Neighbors shared by at least two members, grouped by family, most linked
    first (ties by id), at most MAX_FEATURE_IDS per family."""
    adjacency = graph.adjacency()
    links: Counter[int] = Counter()
    for member in members:
        links.update(adjacency[member])
    by_family: Dict[str, List[Tuple[int, str]]] = {}
    for neighbor, count in links.items():
        if count < MIN_FEATURE_LINKS:
            continue
        family = FEATURE_FAMILY_BY_TYPE.get(graph.types[neighbor])
        if family is None:
            continue
        by_family.setdefault(family, []).append((-count, graph.ids[neighbor]))
    features: List[ClusterFeature] = []
    for family in sorted(by_family):
        ranked = sorted(by_family[family])[:MAX_FEATURE_IDS]
        features.append(ClusterFeature(family, tuple(i for _, i in ranked)))
    return tuple(features)


def build_cluster(
    graph: AnalysisGraph, community: Sequence[int], min_size: int, max_size: int
) -> Tuple[Optional[Cluster], str]:
    """Cluster of a community, or None with the reason (too_small, too_large).

    Containers link members but are never members themselves: they show up as
    `reports` features instead.
    """
    members = sorted(m for m in community if not graph.is_container[m])
    if len(members) < min_size:
        return None, "too_small"
    if len(members) > max_size:
        return None, "too_large"
    kind = classify_kind(graph.types[m] for m in members)
    # node indexes follow the id order: the first member has the smallest id
    anchor = graph.ids[members[0]]
    return (
        Cluster(
            cluster_id=build_cluster_id(kind, anchor),
            kind=kind,
            anchor=anchor,
            members=tuple(members),
            representative_ids=select_representatives(graph, community, members),
            features=extract_features(graph, members),
        ),
        "",
    )


def build_clusters(
    graph: AnalysisGraph,
    communities: Sequence[Sequence[int]],
    min_size: int,
    max_size: int,
) -> Tuple[List[Cluster], ClusteringStats]:
    stats = ClusteringStats(communities=len(communities))
    clusters: List[Cluster] = []
    for community in communities:
        # cheap pre-filter, containers never count as members
        if len(community) < min_size:
            stats.too_small += 1
            continue
        cluster, reason = build_cluster(graph, community, min_size, max_size)
        if cluster is None:
            if reason == "too_large":
                stats.too_large += 1
            else:
                stats.too_small += 1
            continue
        clusters.append(cluster)
    clusters.sort(key=lambda c: (-c.members_count, c.anchor))
    stats.clusters = len(clusters)
    return clusters, stats
