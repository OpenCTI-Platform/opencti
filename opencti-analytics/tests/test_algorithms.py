import random

import pytest
from factories import build_graph, clique, edge, engine_ids, engines, index_of, settings

from opencti_analytics.algorithms import (
    analyze,
    community_edges,
    find_hubs,
    normalize_betweenness,
    sample_sources,
)
from opencti_analytics.engines import GraphEngine
from opencti_analytics.graph import AnalysisGraph


def campaign_and_infrastructure() -> AnalysisGraph:
    """An intrusion set cluster and an infrastructure cluster bridged by a hub."""
    records = clique("is", 5, "Intrusion-Set")
    records += clique("ip", 6, "IPv4-Addr")
    hub = ("sector", "Sector")
    records += [edge((f"is-{i}", "Intrusion-Set"), hub, "targets") for i in range(5)]
    records += [edge((f"ip-{i}", "IPv4-Addr"), hub) for i in range(6)]
    records.append(edge(("lonely-a", "Url"), ("lonely-b", "Url")))
    return build_graph(records)


@pytest.mark.parametrize("engine", engines(), ids=engine_ids())
class TestAnalyze:
    def test_clusters_and_hub_exclusion(self, engine: GraphEngine) -> None:
        graph = campaign_and_infrastructure()
        result = analyze(graph, engine, settings(max_node_degree=8))
        assert result.hubs == 1
        kinds = sorted((c.kind, c.members_count) for c in result.clusters)
        assert kinds == [("campaign", 5), ("infrastructure", 6)]
        hub = index_of(graph, "sector")
        assert hub not in result.cluster_of
        assert result.betweenness is not None
        # the hub keeps its centrality: it is the only bridge between the groups
        assert result.betweenness[hub] == max(result.betweenness)
        lonely = index_of(graph, "lonely-a")
        assert lonely not in result.cluster_of
        assert result.betweenness[lonely] == 0.0

    def test_hub_shows_up_as_victims_feature(self, engine: GraphEngine) -> None:
        graph = campaign_and_infrastructure()
        result = analyze(graph, engine, settings(max_node_degree=8))
        campaign = next(c for c in result.clusters if c.kind == "campaign")
        assert [(f.family, f.ids) for f in campaign.features] == [
            ("victims", (graph.ids[index_of(graph, "sector")],))
        ]

    def test_deterministic(self, engine: GraphEngine) -> None:
        records = clique("a", 6, "Malware") + clique("b", 7, "Domain-Name")
        records.append(edge(("a-0", "Malware"), ("b-0", "Domain-Name")))
        shuffled = list(records)
        random.Random(9).shuffle(shuffled)
        first = analyze(build_graph(records), engine, settings())
        second = analyze(build_graph(shuffled), engine, settings())
        assert first.clusters == second.clusters
        assert first.betweenness == second.betweenness

    def test_betweenness_is_normalized(self, engine: GraphEngine) -> None:
        records = [
            edge((f"n-{i}", "Url"), (f"n-{(i * 7 + 3) % 40}", "Url")) for i in range(40)
        ]
        records += [edge(("star", "Url"), (f"leaf-{i}", "Url")) for i in range(20)]
        graph = build_graph(records)
        for sample_size in (5, 500):
            result = analyze(
                graph, engine, settings(betweenness_sample_size=sample_size)
            )
            assert result.betweenness is not None
            assert all(0.0 <= value <= 1.0 for value in result.betweenness)
        star = index_of(graph, "star")
        assert result.betweenness[star] == pytest.approx(1.0)

    def test_cutoff_mode(self, engine: GraphEngine) -> None:
        path = [edge((f"p-{i}", "Url"), (f"p-{i + 1}", "Url")) for i in range(6)]
        graph = build_graph(path)
        result = analyze(graph, engine, settings(betweenness_cutoff=2))
        assert result.betweenness is not None
        assert result.betweenness_sources == graph.node_count
        assert all(0.0 <= value <= 1.0 for value in result.betweenness)

    def test_betweenness_disabled(self, engine: GraphEngine) -> None:
        graph = campaign_and_infrastructure()
        result = analyze(graph, engine, settings(betweenness_sample_size=0))
        assert result.betweenness is None

    def test_component_below_min_size_is_ignored(self, engine: GraphEngine) -> None:
        graph = build_graph([edge(("a", "Url"), ("b", "Url"))])
        result = analyze(graph, engine, settings(min_cluster_size=3))
        assert result.clusters == []

    def test_oversized_community_is_ignored(self, engine: GraphEngine) -> None:
        graph = build_graph(clique("c", 8, "Malware"))
        result = analyze(graph, engine, settings(max_cluster_size=5))
        assert result.clusters == []
        assert result.clustering.too_large == 1

    def test_whole_small_component_is_the_cluster(self, engine: GraphEngine) -> None:
        graph = build_graph(clique("c", 4, "Tool"))
        result = analyze(graph, engine, settings())
        assert len(result.clusters) == 1
        assert result.clusters[0].members_count == 4
        assert result.clusters[0].kind == "tooling"


class TestHelpers:
    def test_find_hubs_and_community_edges(self) -> None:
        graph = campaign_and_infrastructure()
        hubs = find_hubs(graph, 8)
        hub = index_of(graph, "sector")
        assert [i for i, is_hub in enumerate(hubs) if is_hub] == [hub]
        assert all(hub not in pair for pair in community_edges(graph, hubs))

    def test_sample_sources_per_component(self) -> None:
        records = [edge(("big", "Url"), (f"leaf-{i}", "Url")) for i in range(30)]
        records += [edge(("x", "Url"), ("y", "Url")), edge(("y", "Url"), ("z", "Url"))]
        records.append(edge(("pair-a", "Url"), ("pair-b", "Url")))
        graph = build_graph(records)
        big = sorted(
            index_of(graph, n) for n in ["big"] + [f"leaf-{i}" for i in range(30)]
        )
        small = sorted(index_of(graph, n) for n in ["x", "y", "z"])
        pair = sorted(index_of(graph, n) for n in ["pair-a", "pair-b"])
        components = sorted([big, small, pair], key=lambda c: c[0])
        sources, counts = sample_sources(graph, components, 10, 42)
        assert counts == {big[0]: 10, small[0]: 3}
        assert set(small) <= set(sources)
        assert not set(pair) & set(sources)
        assert sources == sorted(sources)
        again, _ = sample_sources(graph, components, 10, 42)
        assert again == sources

    def test_normalize_betweenness_clamps(self) -> None:
        values = normalize_betweenness([0.0, 50.0, -1.0], [[0, 1, 2]], {0: 1})
        assert values == [0.0, 1.0, 0.0]
