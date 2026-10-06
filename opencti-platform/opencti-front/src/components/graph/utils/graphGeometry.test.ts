import { describe, expect, it } from 'vitest';
import {
  boundsOf,
  type Box,
  boxesOverlap,
  computeLinkCurvatures,
  computeObstacleBends,
  createBoxIndex,
  createPathBuffer,
  fitText,
  linkEndsKey,
  linkPath,
  linkPathInto,
  type LinkPath,
  type PathBuffer,
  pointAt,
  subPath,
  tangentAt,
  tangentInto,
  trimToNodes,
  trimToNodesInto,
} from './graphGeometry';

// The points a path holds, whatever its kind, to compare a path and a buffer
const pointsOf = (path: LinkPath | PathBuffer) => {
  if (path.kind === 'line') return [path.start, path.end];
  if (path.kind === 'quadratic') return [path.start, path.control, path.end];
  return [path.start, path.c1, path.c2, path.end];
};

describe('link geometry written in place', () => {
  const cases: [string, { x: number; y: number }, { x: number; y: number }, number, number][] = [
    ['a straight link', { x: 0, y: 0 }, { x: 100, y: 40 }, 0, 0],
    ['a curved link', { x: 10, y: -20 }, { x: -80, y: 60 }, 0.3, 0],
    ['a self-loop', { x: 5, y: 5 }, { x: 5, y: 5 }, 1, 45],
  ];
  it.each(cases)('gives the same path, trimmed path and tangent as the functions it replaces for %s', (_, start, end, curvature, rotation) => {
    const path = linkPath(start, end, curvature, rotation);
    const buffer = linkPathInto(createPathBuffer(), start, end, curvature, rotation);
    expect(buffer.kind).toBe(path.kind);
    pointsOf(buffer).forEach((point, i) => {
      expect(point.x).toBeCloseTo(pointsOf(path)[i].x, 9);
      expect(point.y).toBeCloseTo(pointsOf(path)[i].y, 9);
    });
    const trimmed = trimToNodes(path, 8, 8) as LinkPath;
    const trimmedBuffer = createPathBuffer();
    expect(trimToNodesInto(trimmedBuffer, buffer, 8, 8)).toBe(true);
    expect(trimmedBuffer.kind).toBe(trimmed.kind);
    pointsOf(trimmedBuffer).forEach((point, i) => {
      expect(point.x).toBeCloseTo(pointsOf(trimmed)[i].x, 6);
      expect(point.y).toBeCloseTo(pointsOf(trimmed)[i].y, 6);
    });
    const tangent = tangentAt(trimmed, 1);
    const tangentBuffer = tangentInto({ x: 0, y: 0 }, trimmedBuffer, 1);
    expect(tangentBuffer.x).toBeCloseTo(tangent.x, 6);
    expect(tangentBuffer.y).toBeCloseTo(tangent.y, 6);
  });

  it('reports a link hidden by the rings of its nodes like the function it replaces', () => {
    const start = { x: 0, y: 0 };
    const end = { x: 10, y: 0 };
    expect(trimToNodes(linkPath(start, end, 0), 8, 8)).toBeNull();
    expect(trimToNodesInto(createPathBuffer(), linkPathInto(createPathBuffer(), start, end, 0), 8, 8)).toBe(false);
  });
});

const distance = (a: { x: number; y: number }, b: { x: number; y: number }) => Math.hypot(a.x - b.x, a.y - b.y);
const key = (id: string, sourceId: string, targetId: string) => linkEndsKey({ id, sourceId, targetId });

describe('linkPath', () => {
  it('is a straight line without curvature', () => {
    expect(linkPath({ x: 0, y: 0 }, { x: 10, y: 0 }, 0)).toEqual({ kind: 'line', start: { x: 0, y: 0 }, end: { x: 10, y: 0 } });
  });

  it('places the control point like the rendering library, perpendicular to the link', () => {
    const path = linkPath({ x: 0, y: 0 }, { x: 10, y: 0 }, 0.5);
    expect(path.kind).toBe('quadratic');
    if (path.kind !== 'quadratic') return;
    // Midpoint (5, 0) moved by length x curvature = 5 along angle - 90 degrees.
    expect(path.control.x).toBeCloseTo(5);
    expect(path.control.y).toBeCloseTo(-5);
  });

  it('draws a loop when both ends are the same node', () => {
    const path = linkPath({ x: 3, y: 4 }, { x: 3, y: 4 }, 1);
    expect(path.kind).toBe('cubic');
    if (path.kind !== 'cubic') return;
    expect(path.c1.x).toBeCloseTo(3);
    expect(path.c1.y).toBeCloseTo(4 - 70);
    expect(path.c2.x).toBeCloseTo(73);
    expect(path.c2.y).toBeCloseTo(4);
  });
});

describe('pointAt / tangentAt / subPath', () => {
  const curve = linkPath({ x: 0, y: 0 }, { x: 100, y: 0 }, 0.3);

  it('starts and ends on the given points', () => {
    expect(pointAt(curve, 0)).toEqual({ x: 0, y: 0 });
    expect(pointAt(curve, 1)).toEqual({ x: 100, y: 0 });
  });

  it('gives unit tangents', () => {
    const tangent = tangentAt(curve, 0.5);
    expect(Math.hypot(tangent.x, tangent.y)).toBeCloseTo(1);
    // Halfway along a symmetric arc the curve runs parallel to the chord.
    expect(tangent.y).toBeCloseTo(0);
  });

  it('cuts a sub-path that follows the original curve', () => {
    const part = subPath(curve, 0.25, 0.75);
    expect(distance(pointAt(part, 0), pointAt(curve, 0.25))).toBeLessThan(1e-9);
    expect(distance(pointAt(part, 1), pointAt(curve, 0.75))).toBeLessThan(1e-9);
    expect(distance(pointAt(part, 0.5), pointAt(curve, 0.5))).toBeLessThan(1e-9);
  });

  it('cuts cubic loops too', () => {
    const loop = linkPath({ x: 0, y: 0 }, { x: 0, y: 0 }, 1);
    const part = subPath(loop, 0.2, 0.6);
    expect(distance(pointAt(part, 0), pointAt(loop, 0.2))).toBeLessThan(1e-9);
    expect(distance(pointAt(part, 1), pointAt(loop, 0.6))).toBeLessThan(1e-9);
  });
});

describe('trimToNodes', () => {
  it('stops a straight link on both rings', () => {
    const trimmed = trimToNodes(linkPath({ x: 0, y: 0 }, { x: 100, y: 0 }, 0), 10, 20);
    expect(trimmed?.start.x).toBeCloseTo(10, 3);
    expect(trimmed?.end.x).toBeCloseTo(80, 3);
  });

  it('stops a curved link on both rings', () => {
    const trimmed = trimToNodes(linkPath({ x: 0, y: 0 }, { x: 100, y: 0 }, 0.4), 8, 8);
    expect(trimmed).not.toBeNull();
    expect(distance(trimmed?.start ?? { x: 0, y: 0 }, { x: 0, y: 0 })).toBeCloseTo(8, 2);
    expect(distance(trimmed?.end ?? { x: 0, y: 0 }, { x: 100, y: 0 })).toBeCloseTo(8, 2);
  });

  it('gives nothing when the rings overlap', () => {
    expect(trimToNodes(linkPath({ x: 0, y: 0 }, { x: 10, y: 0 }, 0), 6, 6)).toBeNull();
  });

  it('cuts both ends of a loop against its node ring', () => {
    const trimmed = trimToNodes(linkPath({ x: 0, y: 0 }, { x: 0, y: 0 }, 1), 6, 6);
    expect(trimmed).not.toBeNull();
    expect(distance(trimmed?.start ?? { x: 0, y: 0 }, { x: 0, y: 0 })).toBeCloseTo(6, 1);
    expect(distance(trimmed?.end ?? { x: 0, y: 0 }, { x: 0, y: 0 })).toBeCloseTo(6, 1);
  });
});

describe('computeLinkCurvatures', () => {
  it('keeps a single link straight', () => {
    expect(computeLinkCurvatures([{ id: 'l1', sourceId: 'a', targetId: 'b' }]).get(key('l1', 'a', 'b'))).toEqual({ curvature: 0, rotation: 0 });
  });

  it('tells apart the two connectors of a nested relationship, which share its id', () => {
    const curvatures = computeLinkCurvatures([
      { id: 'nested', sourceId: 'a', targetId: 'n' },
      { id: 'nested', sourceId: 'n', targetId: 'b' },
      { id: 'other', sourceId: 'n', targetId: 'b' },
    ]);
    expect(curvatures.get(key('nested', 'a', 'n'))).toEqual({ curvature: 0, rotation: 0 });
    expect(curvatures.get(key('nested', 'n', 'b'))?.curvature).not.toBe(0);
    expect(curvatures.get(key('nested', 'n', 'b'))?.curvature).toBeCloseTo(-(curvatures.get(key('other', 'n', 'b'))?.curvature ?? 0));
  });

  it('fans parallel links out symmetrically', () => {
    const curvatures = computeLinkCurvatures([
      { id: 'l1', sourceId: 'a', targetId: 'b' },
      { id: 'l2', sourceId: 'a', targetId: 'b' },
    ]);
    const first = curvatures.get(key('l1', 'a', 'b'))?.curvature ?? 0;
    const second = curvatures.get(key('l2', 'a', 'b'))?.curvature ?? 0;
    expect(first).toBeCloseTo(-second);
    expect(first).not.toBe(0);
  });

  it('puts links of opposite directions on opposite sides', () => {
    const curvatures = computeLinkCurvatures([
      { id: 'l1', sourceId: 'a', targetId: 'b' },
      { id: 'l2', sourceId: 'b', targetId: 'a' },
    ]);
    const a = { x: 0, y: 0 };
    const b = { x: 100, y: 0 };
    const forward = linkPath(a, b, curvatures.get(key('l1', 'a', 'b'))?.curvature ?? 0);
    const backward = linkPath(b, a, curvatures.get(key('l2', 'b', 'a'))?.curvature ?? 0);
    const sideOf = (path: ReturnType<typeof linkPath>) => Math.sign(pointAt(path, 0.5).y);
    expect(sideOf(forward)).not.toBe(sideOf(backward));
  });

  it('spreads the loops of a node over the two quadrants above it, then nests them, whatever the input order', () => {
    const links = ['l3', 'l2', 'l4', 'l1'].map((id) => ({ id, sourceId: 'a', targetId: 'a' }));
    const curvatures = computeLinkCurvatures(links);
    const of = (id: string) => curvatures.get(key(id, 'a', 'a'));
    expect([of('l1'), of('l2'), of('l3'), of('l4')]).toEqual([
      { curvature: 0.5, rotation: 0 },
      { curvature: 0.5, rotation: -90 },
      { curvature: 0.8, rotation: 0 },
      { curvature: 0.8, rotation: -90 },
    ]);
    expect(computeLinkCurvatures([...links].reverse())).toEqual(curvatures);
    // Every loop stays above its node, clear of the name drawn under it.
    [of('l1'), of('l2')].forEach((curve) => {
      const loop = linkPath({ x: 0, y: 0 }, { x: 0, y: 0 }, curve?.curvature ?? 0, curve?.rotation ?? 0);
      expect(pointAt(loop, 0.5).y).toBeLessThan(0);
    });
    // The two first loops lean to opposite sides, so their labels, at mid-loop, never meet.
    const middle = (curve?: { curvature: number; rotation: number }) => pointAt(linkPath({ x: 0, y: 0 }, { x: 0, y: 0 }, curve?.curvature ?? 0, curve?.rotation ?? 0), 0.5);
    expect(Math.sign(middle(of('l1')).x)).toBe(1);
    expect(Math.sign(middle(of('l2')).x)).toBe(-1);
  });
});

describe('computeObstacleBends', () => {
  const clearance = 11;
  const row = new Map([['a', { x: 0, y: 0 }], ['b', { x: 60, y: 0 }], ['c', { x: 120, y: 0 }]]);
  const ends = (id: string, sourceId: string, targetId: string) => ({ id, sourceId, targetId });
  /** Closest distance between a node and the drawn curve of a link. */
  const gap = (start: { x: number; y: number }, end: { x: number; y: number }, curvature: number, node: { x: number; y: number }) => {
    const path = linkPath(start, end, curvature);
    return Math.min(...Array.from({ length: 201 }, (_, i) => distance(pointAt(path, i / 200), node)));
  };

  it('bends a link running through a node of the same row, and only that one', () => {
    const bends = computeObstacleBends([ends('ab', 'a', 'b'), ends('bc', 'b', 'c'), ends('ac', 'a', 'c')], row, clearance);
    expect([...bends.keys()]).toEqual([key('ac', 'a', 'c')]);
    expect(gap(row.get('a')!, row.get('c')!, bends.get(key('ac', 'a', 'c'))!, row.get('b')!)).toBeGreaterThanOrEqual(clearance - 0.01);
  });

  it('bends away from an obstacle off the line, and is deterministic', () => {
    const above = new Map(row);
    above.set('b', { x: 60, y: -4 });
    const links = [ends('ac', 'a', 'c')];
    const bend = computeObstacleBends(links, above, clearance).get(key('ac', 'a', 'c'))!;
    expect(gap(above.get('a')!, above.get('c')!, bend, above.get('b')!)).toBeGreaterThanOrEqual(clearance - 0.01);
    // The curve passes below the obstacle (positive y here), the shorter way round.
    const middle = pointAt(linkPath(above.get('a')!, above.get('c')!, bend), 0.5);
    expect(middle.y).toBeGreaterThan(0);
    expect(computeObstacleBends(links, above, clearance).get(key('ac', 'a', 'c'))).toBe(bend);
  });

  it('leaves alone parallel links, loops, links too short to bend and clear links', () => {
    const fanned = new Map([[key('ac', 'a', 'c'), { curvature: 0.24 }]]);
    expect(computeObstacleBends([ends('ac', 'a', 'c')], row, clearance, fanned).size).toBe(0);
    expect(computeObstacleBends([ends('aa', 'a', 'a')], row, clearance).size).toBe(0);
    const far = new Map([['a', { x: 0, y: 0 }], ['b', { x: 60, y: 40 }], ['c', { x: 120, y: 0 }]]);
    expect(computeObstacleBends([ends('ac', 'a', 'c')], far, clearance).size).toBe(0);
    const close = new Map([['a', { x: 0, y: 0 }], ['c', { x: 15, y: 0 }]]);
    expect(computeObstacleBends([ends('ac', 'a', 'c')], close, clearance).size).toBe(0);
  });

  it('stays fast on 2,000 nodes in rows and 4,000 links', () => {
    const positions = new Map<string, { x: number; y: number }>();
    for (let i = 0; i < 2000; i += 1) positions.set(`n${i}`, { x: (i % 50) * 40, y: Math.floor(i / 50) * 60 });
    const links = Array.from({ length: 4000 }, (_, i) => ends(`l${i}`, `n${(i * 7) % 2000}`, `n${(i * 13 + 5) % 2000}`));
    const started = performance.now();
    computeObstacleBends(links, positions, clearance);
    expect(performance.now() - started).toBeLessThan(1500);
  });
});

describe('createBoxIndex', () => {
  it('finds an overlap with any box added, across cells, and none with separate boxes', () => {
    const index = createBoxIndex(10);
    index.add({ x: 0, y: 0, halfWidth: 5, halfHeight: 5 });
    index.add({ x: 100, y: 100, halfWidth: 30, halfHeight: 2 });
    expect(index.overlaps({ x: 4, y: 0, halfWidth: 5, halfHeight: 5 })).toBe(true);
    expect(index.overlaps({ x: 125, y: 101, halfWidth: 1, halfHeight: 1 })).toBe(true);
    expect(index.overlaps({ x: 20, y: 0, halfWidth: 5, halfHeight: 5 })).toBe(false);
    expect(index.overlaps({ x: 100, y: 110, halfWidth: 40, halfHeight: 2 })).toBe(false);
  });
});

describe('boxesOverlap', () => {
  // A label 20 long and 4 thick drawn at `angle` around (x, y), as the link labels are measured.
  const label = (x: number, y: number, angle: number): Box => {
    const cos = Math.abs(Math.cos(angle));
    const sin = Math.abs(Math.sin(angle));
    return { x, y, halfWidth: (20 * cos + 4 * sin) / 2, halfHeight: (20 * sin + 4 * cos) / 2, rotated: { angle, halfLength: 10, halfThickness: 2 } };
  };

  it('compares rotated boxes by the rectangles they cover, not by their extents', () => {
    const diagonal = Math.PI / 4;
    // Side by side along two parallel links, 6 apart across the text: the extents overlap, the labels do not.
    const first = label(0, 0, diagonal);
    const second = label(6 / Math.SQRT2, -6 / Math.SQRT2, diagonal);
    expect(Math.abs(first.x - second.x) < first.halfWidth + second.halfWidth).toBe(true);
    expect(boxesOverlap(first, second)).toBe(false);
    // Crossing, or 3 apart across the text (less than their thickness): they overlap.
    expect(boxesOverlap(first, label(0, 0, -diagonal))).toBe(true);
    expect(boxesOverlap(first, label(3 / Math.SQRT2, -3 / Math.SQRT2, diagonal))).toBe(true);
  });

  it('compares a rotated box with an axis-aligned one, in both orders', () => {
    const node = { x: 0, y: 0, halfWidth: 5, halfHeight: 5 };
    // The corner of its extent covers the node, the label passes beside it.
    const beside = label(8, -8, Math.PI / 4);
    expect(boxesOverlap(node, beside)).toBe(false);
    expect(boxesOverlap(beside, node)).toBe(false);
    expect(boxesOverlap(node, label(6, 0, Math.PI / 4))).toBe(true);
    expect(boxesOverlap(node, { x: 9, y: 0, halfWidth: 5, halfHeight: 5 })).toBe(true);
  });
});

describe('fitText', () => {
  const measure = (text: string) => text.length;

  it('keeps a text that fits', () => {
    expect(fitText(measure, 'Emotet', 10)).toBe('Emotet');
  });

  it('cuts a long text with an ellipsis within the width', () => {
    const fitted = fitText(measure, 'A very long intrusion set name', 10);
    expect(fitted.endsWith('\u2026')).toBe(true);
    expect(measure(fitted)).toBeLessThanOrEqual(10);
  });
});

describe('boundsOf', () => {
  it('surrounds every point', () => {
    expect(boundsOf([{ x: 1, y: -2 }, { x: -3, y: 4 }])).toEqual({ minX: -3, minY: -2, maxX: 1, maxY: 4 });
    expect(boundsOf([])).toBeNull();
  });
});
