import { describe, expect, it } from 'vitest';
import { boundsOf, computeLinkCurvatures, fitText, keepNonOverlapping, linkPath, pointAt, subPath, tangentAt, trimToNodes } from './graphGeometry';

const distance = (a: { x: number; y: number }, b: { x: number; y: number }) => Math.hypot(a.x - b.x, a.y - b.y);

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
    expect(computeLinkCurvatures([{ id: 'l1', sourceId: 'a', targetId: 'b' }]).get('l1')).toEqual({ curvature: 0, rotation: 0 });
  });

  it('fans parallel links out symmetrically', () => {
    const curvatures = computeLinkCurvatures([
      { id: 'l1', sourceId: 'a', targetId: 'b' },
      { id: 'l2', sourceId: 'a', targetId: 'b' },
    ]);
    const first = curvatures.get('l1')?.curvature ?? 0;
    const second = curvatures.get('l2')?.curvature ?? 0;
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
    const forward = linkPath(a, b, curvatures.get('l1')?.curvature ?? 0);
    const backward = linkPath(b, a, curvatures.get('l2')?.curvature ?? 0);
    const sideOf = (path: ReturnType<typeof linkPath>) => Math.sign(pointAt(path, 0.5).y);
    expect(sideOf(forward)).not.toBe(sideOf(backward));
  });

  it('nests loops on the same node and is independent of the input order', () => {
    const links = [
      { id: 'l2', sourceId: 'a', targetId: 'a' },
      { id: 'l1', sourceId: 'a', targetId: 'a' },
    ];
    const curvatures = computeLinkCurvatures(links);
    expect(curvatures.get('l1')?.curvature).toBeLessThan(curvatures.get('l2')?.curvature ?? 0);
    expect(computeLinkCurvatures([...links].reverse())).toEqual(curvatures);
  });
});

describe('keepNonOverlapping', () => {
  it('keeps the first of two overlapping boxes and every separate one', () => {
    const kept = keepNonOverlapping([
      { id: 1, box: { x: 0, y: 0, halfWidth: 5, halfHeight: 5 } },
      { id: 2, box: { x: 4, y: 0, halfWidth: 5, halfHeight: 5 } },
      { id: 3, box: { x: 20, y: 0, halfWidth: 5, halfHeight: 5 } },
    ]);
    expect(kept.map(({ id }) => id)).toEqual([1, 3]);
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
