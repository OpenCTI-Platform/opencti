import { describe, it, expect } from 'vitest';
import { buildGraph, rankGraph } from './rank';
import { orderLayers } from './order';
import { placeX } from './place';
import { placeLanes } from './lanes';
import { boxesOverlap, buildElements, randomWorkflow, SAMPLES, transitionId } from './layoutFixtures';
import type { WorkflowFixture } from './layoutFixtures';

const lanes = (fixture: WorkflowFixture) => {
  const { nodes, edges } = buildElements(fixture);
  const graph = buildGraph(nodes, edges);
  const ranked = rankGraph(graph);
  const x = placeX(ranked, orderLayers(graph, ranked), 50);
  return { ranked, ...placeLanes(graph, ranked, x, 50, 100) };
};

describe('placeLanes', () => {
  it('places every real node, lane nodes included', () => {
    const { nodes } = buildElements(SAMPLES.case);
    expect(lanes(SAMPLES.case).place.size).toBe(nodes.length);
  });

  it('puts a backward transition one row above the status it leaves from', () => {
    const { place } = lanes(SAMPLES.review);
    expect(place.get(transitionId(['IN_REVIEW'], 'reject', 'NEW'))!.rank).toBe(place.get('IN_REVIEW')!.rank - 1);
  });

  it('puts a self-loop on the row of its status, beside it', () => {
    const { place } = lanes(SAMPLES.rfi);
    const loop = place.get(transitionId(['IN_PROGRESS'], 'add_note', 'IN_PROGRESS'))!;
    const status = place.get('IN_PROGRESS')!;
    expect(loop.rank).toBe(status.rank);
    expect(Math.abs(loop.cx - status.cx)).toBeGreaterThanOrEqual(160 + 50);
  });

  it('nests overlapping loops on the same side: the shorter span is closer to the graph', () => {
    const { items } = lanes(SAMPLES.case);
    let checked = 0;
    const right = items.filter((i) => i.side === 'right');
    const left = items.filter((i) => i.side === 'left');
    [right, left].forEach((side) => {
      for (let i = 1; i < side.length; i += 1) {
        const inner = side[i - 1];
        const outer = side[i];
        if (inner.r0 <= outer.r1 && outer.r0 <= inner.r1) {
          expect(outer.sign * (outer.lx - inner.lx)).toBeGreaterThan(0);
          expect(outer.r1 - outer.r0).toBeGreaterThanOrEqual(inner.r1 - inner.r0);
          checked += 1;
        }
      }
    });
    expect(checked).toBeGreaterThan(0);
  });

  it('keeps a lane node on a finite row when none of its sources is placed', () => {
    const { nodes, edges } = buildElements(SAMPLES.review);
    const graph = buildGraph(nodes, edges);
    const ranked = rankGraph(graph);
    const x = placeX(ranked, orderLayers(graph, ranked), 50);
    const reject = transitionId(['IN_REVIEW'], 'reject', 'NEW');
    graph.inE.set(reject, []); // simulate a backward transition whose sources were all removed
    const { place } = placeLanes(graph, ranked, x, 50, 100);
    expect(Number.isFinite(place.get(reject)!.cy)).toBe(true);
  });

  it('never overlaps two nodes (300 random workflows)', () => {
    for (let seed = 1; seed <= 300; seed += 1) {
      const boxes = [...lanes(randomWorkflow(seed)).place.entries()].map(([id, p]) => ({ id, x: p.cx - p.w / 2, y: p.rank * 100 - p.h / 2, w: p.w, h: p.h }));
      for (let i = 0; i < boxes.length; i += 1) {
        for (let j = i + 1; j < boxes.length; j += 1) expect(boxesOverlap(boxes[i], boxes[j])).toBe(false);
      }
    }
  });
});
