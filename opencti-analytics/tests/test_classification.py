import uuid

import pytest
from factories import build_graph, edge, index_of, node_id

from opencti_analytics.classification import (
    CLUSTER_NAMESPACE,
    build_cluster,
    build_cluster_id,
    build_clusters,
    classify_kind,
    extract_features,
    select_representatives,
)
from opencti_analytics.graph import AnalysisGraph


class TestClusterId:
    @pytest.mark.parametrize(
        "kind, anchor, expected",
        [
            (
                "infrastructure",
                "0a6f0f2e-4b4e-4f5e-9c3a-1d2e3f4a5b6c",
                "495765b1-3336-546c-9008-64acd11a1449",
            ),
            (
                "campaign",
                "11111111-2222-4333-8444-555555555555",
                "155deb88-fd53-5237-b6fa-05f09a5983af",
            ),
        ],
    )
    def test_platform_vectors(self, kind: str, anchor: str, expected: str) -> None:
        assert build_cluster_id(kind, anchor) == expected

    def test_matches_uuid5(self) -> None:
        anchor = node_id("anchor")
        expected = uuid.uuid5(CLUSTER_NAMESPACE, f"graph-cluster:tooling:{anchor}")
        assert build_cluster_id("tooling", anchor) == str(expected)

    def test_anchor_is_smallest_member_id(self) -> None:
        names = ["ip-a", "ip-b", "ip-c"]
        hub = ("domain", "Domain-Name")
        graph = build_graph(edge(hub, (n, "IPv4-Addr")) for n in names)
        cluster, _ = build_cluster(graph, list(range(graph.node_count)), 3, 10)
        assert cluster is not None
        smallest = min(node_id(n) for n in names + ["domain"])
        assert cluster.anchor == smallest
        assert cluster.cluster_id == build_cluster_id("infrastructure", smallest)


class TestKind:
    def test_majority(self) -> None:
        assert classify_kind(["IPv4-Addr", "Domain-Name", "Malware"]) == (
            "infrastructure"
        )
        assert classify_kind(["Malware", "Tool", "Intrusion-Set"]) == "tooling"
        assert classify_kind(["Intrusion-Set", "Campaign", "Url"]) == "campaign"
        assert classify_kind(["Sector", "Country", "Report"]) == "campaign"

    def test_tie_prefers_the_most_specific_kind(self) -> None:
        assert classify_kind(["IPv4-Addr", "Malware"]) == "infrastructure"
        assert classify_kind(["Malware", "Intrusion-Set"]) == "tooling"
        assert classify_kind(["Url", "Intrusion-Set"]) == "infrastructure"


def report_cluster_graph() -> AnalysisGraph:
    """Three domains in a report, sharing an ASN and a certificate.

    domain-a also resolves to a lone IP (shared by nobody else).
    """
    report = ("report", "Report")
    asn = ("asn", "Autonomous-System")
    cert = ("cert", "X509-Certificate")
    domains = [(f"domain-{c}", "Domain-Name") for c in "abc"]
    edges = [edge(report, d, "object") for d in domains]
    edges += [edge(d, asn) for d in domains]
    edges += [edge(d, cert) for d in domains[:2]]
    edges.append(edge(domains[0], ("ip", "IPv4-Addr"), "resolves-to"))
    return build_graph(edges)


class TestFeaturesAndRepresentatives:
    def test_containers_are_not_members(self) -> None:
        graph = report_cluster_graph()
        community = list(range(graph.node_count))
        cluster, _ = build_cluster(graph, community, 3, 10)
        assert cluster is not None
        member_ids = {graph.ids[m] for m in cluster.members}
        assert node_id("report") not in member_ids
        assert cluster.members_count == 6

    def test_shared_neighbors_by_family(self) -> None:
        graph = report_cluster_graph()
        members = [index_of(graph, f"domain-{c}") for c in "abc"]
        features = {f.family: f.ids for f in extract_features(graph, members)}
        assert features == {
            "asn": (node_id("asn"),),
            "certificates": (node_id("cert"),),
            "reports": (node_id("report"),),
        }

    def test_features_sorted_by_links_then_id(self) -> None:
        members = [(f"m-{i}", "Intrusion-Set") for i in range(4)]
        techniques = [(f"t-{i}", "Attack-Pattern") for i in range(3)]
        edges = [edge(m, techniques[0], "uses") for m in members]
        edges += [edge(m, techniques[1], "uses") for m in members[:2]]
        edges += [edge(m, techniques[2], "uses") for m in members[:2]]
        graph = build_graph(edges)
        indexes = [index_of(graph, m[0]) for m in members]
        (feature,) = extract_features(graph, indexes)
        tied = sorted([node_id("t-1"), node_id("t-2")])
        assert feature.family == "techniques"
        assert feature.ids == (node_id("t-0"), *tied)

    def test_feature_ids_capped(self) -> None:
        members = [("m-0", "Intrusion-Set"), ("m-1", "Intrusion-Set")]
        edges = [
            edge(m, (f"t-{i}", "Attack-Pattern"), "uses")
            for m in members
            for i in range(60)
        ]
        graph = build_graph(edges)
        indexes = [index_of(graph, m[0]) for m in members]
        (feature,) = extract_features(graph, indexes)
        assert len(feature.ids) == 50

    def test_representatives_by_internal_degree_then_id(self) -> None:
        center = ("center", "Infrastructure")
        leaves = [(f"leaf-{i}", "IPv4-Addr") for i in range(7)]
        edges = [edge(center, leaf) for leaf in leaves]
        edges.append(edge(leaves[3], leaves[4]))
        graph = build_graph(edges)
        community = list(range(graph.node_count))
        representatives = select_representatives(graph, community, community)
        tied = sorted(node_id(f"leaf-{i}") for i in (0, 1, 2, 5, 6))
        assert representatives[0] == node_id("center")
        assert set(representatives[1:3]) == {node_id("leaf-3"), node_id("leaf-4")}
        assert list(representatives[3:]) == tied[:2]
        assert len(representatives) == 5


class TestClusterSizes:
    def test_too_small_and_too_large(self) -> None:
        graph = report_cluster_graph()
        community = list(range(graph.node_count))
        assert build_cluster(graph, community, 7, 10) == (None, "too_small")
        assert build_cluster(graph, community, 2, 5) == (None, "too_large")

    def test_clusters_ordered_by_size_then_anchor(self) -> None:
        graph = report_cluster_graph()
        ids = graph.ids
        domains = sorted(index_of(graph, f"domain-{c}") for c in "abc")
        others = [i for i in range(graph.node_count) if i not in domains]
        clusters, stats = build_clusters(graph, [domains, others, [0]], 2, 10)
        assert [c.members_count for c in clusters] == [3, 3]
        assert clusters[0].anchor < clusters[1].anchor
        assert stats.communities == 3
        assert stats.too_small == 1
        assert all(c.anchor in ids for c in clusters)
