import { describe, it, expect } from 'vitest';
import { buildGraph, rankGraph } from './rank';
import { orderLayers } from './order';
import { pava, placeX } from './place';
import { buildElements, randomWorkflow, SAMPLES, transitionId } from './layoutFixtures';
import type { WorkflowFixture } from './layoutFixtures';

const place = (fixture: WorkflowFixture) => {
  const { nodes, edges } = buildElements(fixture);
  const graph = buildGraph(nodes, edges);
  const ranked = rankGraph(graph);
  const ordering = orderLayers(graph, ranked);
  return { ranked, ordering, x: placeX(ranked, ordering, 50) };
};

describe('pava', () => {
  it('returns the input when it is already non-decreasing', () => {
    expect(pava([1, 2, 3], [1, 1, 1])).toEqual([1, 2, 3]);
  });

  it('pools violators to their weighted mean', () => {
    expect(pava([3, 1], [1, 3])).toEqual([1.5, 1.5]);
  });
});

describe('placeX', () => {
  it('keeps the minimum gap between neighbours in every row (300 random workflows)', () => {
    for (let seed = 1; seed <= 300; seed += 1) {
      const { ranked, ordering, x } = place(randomWorkflow(seed));
      ordering.layers.forEach((layer) => {
        for (let i = 1; i < layer.length; i += 1) {
          const a = ranked.layered.get(layer[i - 1])!;
          const b = ranked.layered.get(layer[i])!;
          const gap = a.dummy || b.dummy ? 20 : 50;
          expect(x.get(b.id)! - x.get(a.id)!).toBeGreaterThanOrEqual(a.w / 2 + b.w / 2 + gap - 1);
        }
      });
    }
  });

  it('draws the happy path as one vertical line', () => {
    const review = place(SAMPLES.review).x;
    expect(new Set(['NEW', transitionId(['NEW'], 'submit', 'IN_REVIEW'), 'IN_REVIEW', 'ANALYZED', 'CLOSED'].map((id) => review.get(id))).size).toBe(1);
    const rfi = place(SAMPLES.rfi).x;
    expect(new Set(['DRAFT', 'PENDING', 'IN_PROGRESS', 'BLOCKED'].map((id) => rfi.get(id))).size).toBe(1);
  });

  it('returns whole pixels', () => {
    place(SAMPLES.case).x.forEach((v) => expect(Number.isInteger(v)).toBe(true));
  });
});
