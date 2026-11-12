import { describe, it, expect } from 'vitest';
import { layoutWorkflow } from './layoutWorkflow';
import { getRoutePath } from './route';
import { boxesOverlap, buildElements, countBends, isAxisAligned, isOnHexagonOutline, randomWorkflow, SAMPLES, segmentHitsBox, transitionId } from './layoutFixtures';
import type { Box, WorkflowFixture } from './layoutFixtures';

const OPTIONS = { spacing: [50, 50] as [number, number] };

const run = (fixture: WorkflowFixture, initialStatusId?: string) => {
  const { nodes, edges } = buildElements(fixture);
  const result = layoutWorkflow(nodes, edges, { ...OPTIONS, initialStatusId });
  const boxes: Box[] = nodes.map((n) => ({ id: n.id, ...result.positions.get(n.id)!, w: n.width ?? 160, h: n.height ?? 50 }));
  return { nodes, edges, result, boxes };
};

const fixtures: WorkflowFixture[] = [...Object.values(SAMPLES), ...Array.from({ length: 300 }, (_, i) => randomWorkflow(i + 1))];
// Each fixture again with its last status as the saved initial one, usually not a root. Laid out
// once for all the invariants below, which collect offenders and assert once: an expect per
// segment and box made the suite slow enough to time out on CI.
const runs = fixtures.flatMap((f) => [undefined, f.statuses.at(-1)].map((initial) => ({
  name: initial ? `${f.name} from ${initial}` : f.name,
  ...run(f, initial),
})));

describe('layoutWorkflow – invariants (4 samples + 300 random workflows, from the default root and from the last status)', () => {
  it('positions every node and routes every edge', () => {
    const offenders = runs.flatMap(({ name, nodes, edges, result }) => [
      ...nodes.filter((n) => !result.positions.has(n.id)).map((n) => `${name}: ${n.id}`),
      ...edges.filter((e) => (result.routes.get(e.id)?.length ?? 0) < 2).map((e) => `${name}: ${e.id}`),
    ]);
    expect(offenders).toEqual([]);
  });

  it('never overlaps nodes', () => {
    const offenders = runs.flatMap(({ name, boxes }) => boxes.flatMap((a, i) => boxes.slice(i + 1)
      .filter((b) => boxesOverlap(a, b))
      .map((b) => `${name}: ${a.id} / ${b.id}`)));
    expect(offenders).toEqual([]);
  });

  it('draws only horizontal and vertical segments', () => {
    const offenders = runs.flatMap(({ name, result }) => [...result.routes]
      .filter(([, points]) => !isAxisAligned(points))
      .map(([id]) => `${name}: ${id}`));
    expect(offenders).toEqual([]);
  });

  it('never draws an edge through a node other than its endpoints', () => {
    const offenders = runs.flatMap(({ name, edges, result, boxes }) => edges.flatMap((e) => {
      const points = result.routes.get(e.id)!;
      return boxes
        .filter((b) => b.id !== e.source && b.id !== e.target && points.slice(1).some((q, i) => segmentHitsBox(points[i], q, b)))
        .map((b) => `${name}: ${e.id} through ${b.id}`);
    }));
    expect(offenders).toEqual([]);
  });

  it('starts and ends edges on the outline of the transition hexagon', () => {
    const offenders = runs.flatMap(({ name, nodes, edges, result, boxes }) => {
      const transitionIds = new Set(nodes.filter((n) => n.type === 'transition').map((n) => n.id));
      const transitions = new Map(boxes.filter((b) => transitionIds.has(b.id)).map((b) => [b.id, b]));
      return edges.filter((e) => {
        const points = result.routes.get(e.id)!;
        const source = transitions.get(e.source);
        const target = transitions.get(e.target);
        return (source && !isOnHexagonOutline(points[0], source)) || (target && !isOnHexagonOutline(points[points.length - 1], target));
      }).map((e) => `${name}: ${e.id}`);
    });
    expect(offenders).toEqual([]);
  });

  it('is deterministic', () => {
    const { nodes, edges } = buildElements(SAMPLES.case);
    const a = layoutWorkflow(nodes, edges, OPTIONS);
    const b = layoutWorkflow(nodes, edges, OPTIONS);
    expect([...a.positions]).toEqual([...b.positions]);
    expect([...a.routes]).toEqual([...b.routes]);
  });

  it('keeps the total bend count under the measured baseline', () => {
    // Measured 11430 bends on these 300 seeds (self-loops and widths 120-240px included); fail on a clear regression.
    const bends = fixtures.slice(4).reduce((sum, fixture) => sum + countBends(run(fixture).result.routes), 0);
    expect(bends).toBeLessThanOrEqual(11800);
  });
});

describe('layoutWorkflow – hints and edge cases', () => {
  it('returns empty maps for an empty graph', () => {
    const result = layoutWorkflow([], [], OPTIONS);
    expect(result.positions.size + result.nodeHints.size + result.routes.size).toBe(0);
  });

  it('lays out a single status with its placeholder below', () => {
    const { result } = run({ name: 'single', statuses: ['NEW'], transitions: [] });
    expect(result.positions.get('placeholder-NEW')!.y).toBeGreaterThan(result.positions.get('NEW')!.y);
  });

  it('flags backward transitions and their lane', () => {
    const { result } = run(SAMPLES.review);
    const reject = result.nodeHints.get(transitionId(['IN_REVIEW'], 'reject', 'NEW'))!;
    expect(reject.backward).toBe(true);
    expect(['left', 'right']).toContain(reject.lane);
    expect(result.nodeHints.get(transitionId(['NEW'], 'submit', 'IN_REVIEW'))).toEqual({ backward: false, lane: null, rank: 1 });
  });

  it('places an unlinked transition on the row below its source', () => {
    const { result } = run(SAMPLES.rfi);
    const archive = result.nodeHints.get(transitionId(['DONE'], 'archive', null))!;
    expect(archive.rank).toBe(result.nodeHints.get('DONE')!.rank + 1);
  });

  it('uses NODE_SIZE when React Flow has not measured a node yet', () => {
    const result = layoutWorkflow([{ id: 'A', type: 'status' }], [], OPTIONS);
    expect(result.positions.get('A')).toEqual({ x: -80, y: -25 });
  });

  it('lays out a 1500-status chain without overflowing the stack', () => {
    const statuses = Array.from({ length: 1500 }, (_, i) => `S${i}`);
    const transitions = statuses.slice(1).map((s, i): WorkflowFixture['transitions'][number] => [[statuses[i]], 'next', s]);
    const { result } = run({ name: 'chain', statuses, transitions });
    expect(result.nodeHints.get('S1499')!.rank).toBe(2 * 1499);
  });

  it('keeps a transition with a forward and a backward target in the flow and routes both edges', () => {
    const nodes = ['A', 'B', 'C'].map((id) => ({ id, type: 'status' })).concat(['t1', 't'].map((id) => ({ id, type: 'transition' })));
    const edges = [
      { id: 'a', source: 'A', target: 't1' },
      { id: 'b', source: 't1', target: 'B' },
      { id: 'c', source: 'B', target: 't' },
      { id: 'd', source: 't', target: 'C' },
      { id: 'e', source: 't', target: 'A' },
    ];
    const result = layoutWorkflow(nodes, edges, OPTIONS);
    edges.forEach((e) => expect(result.routes.get(e.id)?.length).toBeGreaterThanOrEqual(2));
    expect(result.nodeHints.get('t')!.backward).toBe(false);
    expect(result.nodeHints.get('C')!.rank).toBeGreaterThan(result.nodeHints.get('t')!.rank);
    const back = result.routes.get('e')!;
    expect(back[back.length - 1].y).toBeCloseTo(result.positions.get('A')!.y);
    expect(isOnHexagonOutline(back[0], { id: 't', ...result.positions.get('t')!, w: 160, h: 50 })).toBe(true);
  });

  it('routes every target of a backward transition that goes back to several statuses', () => {
    const nodes = ['A', 'B', 'C'].map((id) => ({ id, type: 'status' })).concat(['t1', 't2', 't'].map((id) => ({ id, type: 'transition' })));
    const edges = [
      { id: 'a', source: 'A', target: 't1' },
      { id: 'b', source: 't1', target: 'B' },
      { id: 'c', source: 'B', target: 't2' },
      { id: 'd', source: 't2', target: 'C' },
      { id: 'e', source: 'C', target: 't' },
      { id: 'f', source: 't', target: 'A' },
      { id: 'g', source: 't', target: 'B' },
    ];
    const result = layoutWorkflow(nodes, edges, OPTIONS);
    expect(result.nodeHints.get('t')!.backward).toBe(true);
    edges.forEach((e) => expect(result.routes.get(e.id)?.length).toBeGreaterThanOrEqual(2));
    ['f', 'g'].forEach((id) => {
      const route = result.routes.get(id)!;
      expect(isAxisAligned(route)).toBe(true);
      expect(route[0].y).toBeCloseTo(result.positions.get('t')!.y);
    });
  });

  it('ignores an edge that points to a missing node', () => {
    const result = layoutWorkflow([{ id: 'A', type: 'status' }], [{ id: 'ghost', source: 'A', target: 'gone' }], OPTIONS);
    expect(result.routes.has('ghost')).toBe(false);
  });
});

describe('getRoutePath', () => {
  it('rounds corners and puts the badge on the longest segment', () => {
    const [d, x, y] = getRoutePath([{ x: 0, y: 0 }, { x: 0, y: 20 }, { x: 100, y: 20 }, { x: 100, y: 40 }]);
    expect(d).toBe('M0,0 L0,12 Q0,20 8,20 L92,20 Q100,20 100,28 L100,40');
    expect([x, y]).toEqual([50, 20]);
  });

  it('draws a straight line for two points', () => {
    expect(getRoutePath([{ x: 0, y: 0 }, { x: 0, y: 50 }])).toEqual(['M0,0 L0,50', 0, 25]);
  });
});
