from typing import List, Tuple

import networkx as nx
import pytest
from factories import engine_ids, engines

from opencti_analytics.algorithms import normalize_betweenness
from opencti_analytics.engines import (
    GraphEngine,
    IgraphEngine,
    NetworkxEngine,
    igraph_available,
    normalize_groups,
    select_engine,
)

needs_igraph = pytest.mark.skipif(not igraph_available(), reason="igraph missing")


def karate() -> Tuple[int, List[Tuple[int, int]]]:
    graph = nx.karate_club_graph()
    edges = sorted((min(a, b), max(a, b)) for a, b in graph.edges())
    return graph.number_of_nodes(), edges


def two_cliques_with_bridge() -> Tuple[int, List[Tuple[int, int]]]:
    edges = []
    for offset in (0, 6):
        edges += [(offset + i, offset + j) for i in range(6) for j in range(i + 1, 6)]
    edges.append((5, 6))
    return 12, edges


@pytest.mark.parametrize("engine", engines(), ids=engine_ids())
class TestEngine:
    def test_connected_components(self, engine: GraphEngine) -> None:
        handle = engine.build(7, [(0, 1), (1, 2), (3, 4), (5, 6), (4, 5)])
        assert engine.connected_components(handle) == [[0, 1, 2], [3, 4, 5, 6]]

    def test_label_propagation_is_deterministic(self, engine: GraphEngine) -> None:
        n, edges = karate()
        first = engine.label_propagation(engine.build(n, edges), 42)
        second = engine.label_propagation(engine.build(n, edges), 42)
        assert first == second
        assert sorted(node for group in first for node in group) == list(range(n))

    def test_label_propagation_finds_dense_groups(self, engine: GraphEngine) -> None:
        n, edges = two_cliques_with_bridge()
        communities = engine.label_propagation(engine.build(n, edges), 42)
        assert communities == [list(range(6)), list(range(6, 12))]

    def test_isolated_nodes_are_singletons(self, engine: GraphEngine) -> None:
        communities = engine.label_propagation(engine.build(5, [(0, 1), (1, 2)]), 1)
        assert [3] in communities and [4] in communities

    def test_exact_betweenness_matches_networkx(self, engine: GraphEngine) -> None:
        n, edges = karate()
        raw = engine.betweenness(engine.build(n, edges), None, None)
        normalized = normalize_betweenness(raw, [list(range(n))], {0: n})
        expected = nx.betweenness_centrality(nx.karate_club_graph(), normalized=True)
        for node in range(n):
            assert normalized[node] == pytest.approx(expected[node], abs=1e-9)

    def test_all_sources_equals_exact(self, engine: GraphEngine) -> None:
        n, edges = karate()
        handle = engine.build(n, edges)
        exact = engine.betweenness(handle, None, None)
        explicit = engine.betweenness(handle, list(range(n)), None)
        assert explicit == pytest.approx(exact)

    def test_no_sources_gives_zeros(self, engine: GraphEngine) -> None:
        n, edges = karate()
        assert engine.betweenness(engine.build(n, edges), [], None) == [0.0] * n


@needs_igraph
class TestEngineParity:
    def test_sampled_betweenness(self) -> None:
        n, edges = karate()
        sources = [0, 3, 7, 12, 20, 33]
        ig = IgraphEngine()
        nx_engine = NetworkxEngine()
        expected = ig.betweenness(ig.build(n, edges), sources, None)
        actual = nx_engine.betweenness(nx_engine.build(n, edges), sources, None)
        assert actual == pytest.approx(expected)

    @pytest.mark.parametrize("cutoff", [1, 2, 3])
    def test_cutoff_betweenness(self, cutoff: int) -> None:
        n, edges = karate()
        ig = IgraphEngine()
        nx_engine = NetworkxEngine()
        expected = ig.betweenness(ig.build(n, edges), None, cutoff)
        actual = nx_engine.betweenness(nx_engine.build(n, edges), None, cutoff)
        assert actual == pytest.approx(expected)

    def test_igraph_rejects_sampling_with_cutoff(self) -> None:
        ig = IgraphEngine()
        with pytest.raises(ValueError):
            ig.betweenness(ig.build(3, [(0, 1), (1, 2)]), [0], 2)

    def test_auto_prefers_igraph(self) -> None:
        assert select_engine("auto").name == "igraph"
        assert select_engine("igraph").name == "igraph"


def test_forced_networkx() -> None:
    assert select_engine("networkx").name == "networkx"


def test_auto_falls_back_to_networkx(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("opencti_analytics.engines.igraph_available", lambda: False)
    assert select_engine("auto").name == "networkx"


def test_normalize_groups() -> None:
    assert normalize_groups([{5, 4}, set(), [3, 1], (2,)]) == [[1, 3], [2], [4, 5]]
