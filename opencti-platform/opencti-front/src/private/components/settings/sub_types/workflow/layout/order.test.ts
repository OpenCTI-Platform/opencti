import { describe, it, expect } from 'vitest';
import { buildGraph, rankGraph } from './rank';
import { orderLayers } from './order';
import { buildElements, randomWorkflow, SAMPLES } from './layoutFixtures';

const order = (fixture: Parameters<typeof buildElements>[0]) => {
  const { nodes, edges } = buildElements(fixture);
  const graph = buildGraph(nodes, edges);
  const ranked = rankGraph(graph);
  return { ranked, ordering: orderLayers(graph, ranked) };
};

describe('orderLayers', () => {
  it('finds a crossing-free ordering for Report review and Incident response', () => {
    expect(order(SAMPLES.review).ordering.crossings).toBe(0);
    expect(order(SAMPLES.incident).ordering.crossings).toBe(0);
  });

  it('keeps every layered node exactly once, in the row of its rank', () => {
    const { ranked, ordering } = order(SAMPLES.case);
    const all = ordering.layers.flat();
    expect(new Set(all).size).toBe(ranked.layered.size);
    ordering.layers.forEach((layer, r) => layer.forEach((id) => expect(ranked.layered.get(id)!.rank).toBe(r)));
  });

  it('is deterministic', () => {
    const a = order(randomWorkflow(11)).ordering.layers;
    const b = order(randomWorkflow(11)).ordering.layers;
    expect(a).toEqual(b);
  });
});
