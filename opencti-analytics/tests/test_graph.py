import random

from factories import build_graph, edge, index_of, node_id

from opencti_analytics.graph import EdgeRecord, GraphBuilder, is_relationship_type

DOMAIN = ("domain", "Domain-Name")
IP = ("ip", "IPv4-Addr")
ASN = ("asn", "Autonomous-System")


class TestGraphBuilder:
    def test_parallel_and_reverse_edges_are_merged(self) -> None:
        graph = build_graph(
            [
                edge(DOMAIN, IP, "resolves-to"),
                edge(DOMAIN, IP, "related-to"),
                edge(IP, DOMAIN, "related-to"),
                edge(IP, ASN, "related-to"),
            ]
        )
        assert graph.node_count == 3
        assert graph.edge_count == 2
        assert graph.stats.received_edges == 4

    def test_nodes_sorted_by_id_and_typed(self) -> None:
        records = [edge(DOMAIN, IP), edge(IP, ASN), edge(ASN, DOMAIN)]
        graph = build_graph(records)
        assert graph.ids == sorted(graph.ids)
        assert graph.types[index_of(graph, "asn")] == "Autonomous-System"
        assert all(a < b for a, b in graph.edges)
        assert graph.edges == sorted(graph.edges)

    def test_input_order_does_not_matter(self) -> None:
        records = [edge((f"n-{i}", "Url"), (f"n-{i + 1}", "Url")) for i in range(30)]
        shuffled = list(records)
        random.Random(3).shuffle(shuffled)
        first = build_graph(records)
        second = build_graph(shuffled)
        assert first.ids == second.ids
        assert first.edges == second.edges

    def test_self_loops_and_relationship_refs_are_ignored(self) -> None:
        report = ("report", "Report")
        relationship = ("rel", "uses")
        graph = build_graph(
            [
                edge(DOMAIN, DOMAIN),
                edge(report, relationship, "object"),
                edge(report, DOMAIN, "object"),
            ]
        )
        assert graph.node_count == 2
        assert node_id("rel") not in graph.ids
        assert graph.stats.self_loops == 1
        assert graph.stats.relationship_refs == 1

    def test_adjacency_and_degrees(self) -> None:
        graph = build_graph([edge(DOMAIN, IP), edge(DOMAIN, ASN)])
        domain = index_of(graph, "domain")
        assert graph.degrees()[domain] == 2
        assert graph.adjacency()[domain] == sorted(graph.adjacency()[domain])


class TestContainers:
    def test_container_flag(self) -> None:
        report = ("report", "Report")
        grouping = ("grouping", "Grouping")
        graph = build_graph(
            [edge(report, DOMAIN, "object"), edge(grouping, IP), edge(DOMAIN, IP)]
        )
        assert graph.is_container[index_of(graph, "report")]
        assert graph.is_container[index_of(graph, "grouping")]
        assert not graph.is_container[index_of(graph, "domain")]

    def test_oversized_container_is_dropped(self) -> None:
        big = ("big-report", "Report")
        small = ("small-report", "Report")
        objects = [(f"obj-{i}", "Url") for i in range(4)]
        records = [edge(big, o, "object") for o in objects]
        records += [edge(small, o, "object") for o in objects[:2]]
        graph = build_graph(records, max_container_size=3)
        assert node_id("big-report") not in graph.ids
        assert node_id("obj-3") not in graph.ids
        assert graph.node_count == 3
        assert graph.stats.oversized_containers == 1
        assert graph.stats.dropped_containment_edges == 4

    def test_container_size_counts_distinct_objects(self) -> None:
        report = ("report", "Report")
        records = [edge(report, DOMAIN, "object")] * 5
        graph = build_graph(records, max_container_size=1)
        assert graph.node_count == 2
        assert graph.stats.oversized_containers == 0

    def test_oversized_container_keeps_its_other_relationships(self) -> None:
        big = ("big-report", "Report")
        records = [edge(big, (f"obj-{i}", "Url"), "object") for i in range(3)]
        records.append(edge(big, DOMAIN, "related-to"))
        graph = build_graph(records, max_container_size=2)
        assert sorted(graph.ids) == sorted([node_id("big-report"), node_id("domain")])
        assert graph.is_container[index_of(graph, "big-report")]

    def test_build_is_repeatable(self) -> None:
        builder = GraphBuilder(1)
        builder.add(
            EdgeRecord("r1", "object", node_id("c"), "Report", node_id("a"), "Url")
        )
        builder.add(
            EdgeRecord("r2", "object", node_id("c"), "Report", node_id("b"), "Url")
        )
        first = builder.build()
        second = builder.build()
        assert first.ids == second.ids == []
        assert second.stats.oversized_containers == 1


def test_is_relationship_type() -> None:
    assert is_relationship_type("uses")
    assert is_relationship_type("stix-sighting-relationship")
    assert is_relationship_type("")
    assert not is_relationship_type("IPv4-Addr")
    assert not is_relationship_type("Intrusion-Set")
