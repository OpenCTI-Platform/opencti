export interface Point {
  x: number;
  y: number;
}

/**
 * The path of a link, in graph units. Quadratic for a curved link between two nodes and cubic for
 * a loop on one node: the same shapes the rendering library hit-tests on its pointer canvas, so a
 * click on the drawn line always lands on the link.
 */
export type LinkPath
  = | { kind: 'line'; start: Point; end: Point }
    | { kind: 'quadratic'; start: Point; control: Point; end: Point }
    | { kind: 'cubic'; start: Point; c1: Point; c2: Point; end: Point };

/** A box centred on a point, in the units of the context it is measured in. */
export interface Box extends Point {
  halfWidth: number;
  halfHeight: number;
}

/** Self-loops have no length to scale a curvature by, so the library sizes them with this factor. */
const SELF_LOOP_SIZE = 70;
/** Two links between the same nodes fan out by this curvature step, enough for both labels to read. */
const PARALLEL_CURVATURE_STEP = 0.24;
const TRIM_ITERATIONS = 18;

const lerp = (a: Point, b: Point, t: number): Point => ({ x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t });

const unit = (x: number, y: number): Point => {
  const length = Math.hypot(x, y);
  return length === 0 ? { x: 1, y: 0 } : { x: x / length, y: y / length };
};

/**
 * The path the library draws for a link, from its two end positions, its curvature and, for a
 * loop, its rotation in degrees (`linkCurvature` and `linkSelfCurveRotation` of the library).
 */
export const linkPath = (start: Point, end: Point, curvature: number, selfRotationDegrees = 0): LinkPath => {
  const length = Math.hypot(end.x - start.x, end.y - start.y);
  if (length === 0) {
    const d = (curvature || 1) * SELF_LOOP_SIZE;
    const angle = (selfRotationDegrees * Math.PI) / 180;
    const outAngle = angle - Math.PI / 2;
    return {
      kind: 'cubic',
      start,
      c1: { x: end.x + d * Math.cos(outAngle), y: end.y + d * Math.sin(outAngle) },
      c2: { x: end.x + d * Math.cos(angle), y: end.y + d * Math.sin(angle) },
      end,
    };
  }
  if (!curvature) return { kind: 'line', start, end };
  const angle = Math.atan2(end.y - start.y, end.x - start.x);
  const d = length * curvature;
  return {
    kind: 'quadratic',
    start,
    control: {
      x: (start.x + end.x) / 2 + d * Math.cos(angle - Math.PI / 2),
      y: (start.y + end.y) / 2 + d * Math.sin(angle - Math.PI / 2),
    },
    end,
  };
};

export const pointAt = (path: LinkPath, t: number): Point => {
  if (path.kind === 'line') return lerp(path.start, path.end, t);
  if (path.kind === 'quadratic') {
    return lerp(lerp(path.start, path.control, t), lerp(path.control, path.end, t), t);
  }
  const a = lerp(path.start, path.c1, t);
  const b = lerp(path.c1, path.c2, t);
  const c = lerp(path.c2, path.end, t);
  return lerp(lerp(a, b, t), lerp(b, c, t), t);
};

/** The unit direction of travel along the path at `t`. */
export const tangentAt = (path: LinkPath, t: number): Point => {
  if (path.kind === 'line') return unit(path.end.x - path.start.x, path.end.y - path.start.y);
  if (path.kind === 'quadratic') {
    const u = 1 - t;
    return unit(
      2 * u * (path.control.x - path.start.x) + 2 * t * (path.end.x - path.control.x),
      2 * u * (path.control.y - path.start.y) + 2 * t * (path.end.y - path.control.y),
    );
  }
  const u = 1 - t;
  return unit(
    3 * u * u * (path.c1.x - path.start.x) + 6 * u * t * (path.c2.x - path.c1.x) + 3 * t * t * (path.end.x - path.c2.x),
    3 * u * u * (path.c1.y - path.start.y) + 6 * u * t * (path.c2.y - path.c1.y) + 3 * t * t * (path.end.y - path.c2.y),
  );
};

/**
 * The parameter where the path leaves a circle of `radius` around `centre`, searched from the
 * end given. The path is assumed to start inside the circle and leave it once, which holds for
 * a link leaving a node.
 */
const exitParameter = (path: LinkPath, centre: Point, radius: number, fromEnd: boolean): number => {
  let inside = fromEnd ? 1 : 0;
  let outside = fromEnd ? 0 : 1;
  if (Math.hypot(pointAt(path, outside).x - centre.x, pointAt(path, outside).y - centre.y) <= radius) return outside;
  for (let iteration = 0; iteration < TRIM_ITERATIONS; iteration += 1) {
    const middle = (inside + outside) / 2;
    const point = pointAt(path, middle);
    if (Math.hypot(point.x - centre.x, point.y - centre.y) <= radius) inside = middle;
    else outside = middle;
  }
  return (inside + outside) / 2;
};

/** The part of a path between two parameters, as a path of the same kind (de Casteljau split). */
export const subPath = (path: LinkPath, from: number, to: number): LinkPath => {
  if (path.kind === 'line') return { kind: 'line', start: pointAt(path, from), end: pointAt(path, to) };
  if (path.kind === 'quadratic') {
    // Split at `to`, then the first part at `from / to`.
    const head = {
      start: path.start,
      control: lerp(path.start, path.control, to),
      end: pointAt(path, to),
    };
    const s = to === 0 ? 0 : from / to;
    return {
      kind: 'quadratic',
      start: lerp(lerp(head.start, head.control, s), lerp(head.control, head.end, s), s),
      control: lerp(head.control, head.end, s),
      end: head.end,
    };
  }
  const splitCubic = (p0: Point, p1: Point, p2: Point, p3: Point, t: number) => {
    const a = lerp(p0, p1, t);
    const b = lerp(p1, p2, t);
    const c = lerp(p2, p3, t);
    const d = lerp(a, b, t);
    const e = lerp(b, c, t);
    const f = lerp(d, e, t);
    return { left: [p0, a, d, f] as const, right: [f, e, c, p3] as const };
  };
  const { left } = splitCubic(path.start, path.c1, path.c2, path.end, to);
  const s = to === 0 ? 0 : from / to;
  const { right } = splitCubic(left[0], left[1], left[2], left[3], s);
  return { kind: 'cubic', start: right[0], c1: right[1], c2: right[2], end: right[3] };
};

/**
 * The path cut where it leaves the ring of each node, so a line never runs under a node and an
 * arrowhead drawn at its end touches the ring. `null` when the two rings overlap and nothing of
 * the link would show.
 */
export const trimToNodes = (path: LinkPath, startReach: number, endReach: number): LinkPath | null => {
  if (path.kind === 'cubic' && path.start.x === path.end.x && path.start.y === path.end.y) {
    // A loop leaves and enters the same node: cut both ends against the one ring.
    const from = exitParameter(subPath(path, 0, 0.5), path.start, startReach, false) / 2;
    const to = 0.5 + exitParameter(subPath(path, 0.5, 1), path.end, endReach, true) / 2;
    return subPath(path, from, to);
  }
  const length = Math.hypot(path.end.x - path.start.x, path.end.y - path.start.y);
  if (length <= startReach + endReach) return null;
  const from = exitParameter(path, path.start, startReach, false);
  const to = exitParameter(path, path.end, endReach, true);
  return to > from ? subPath(path, from, to) : null;
};

export interface LinkEnds {
  id: string;
  sourceId: string;
  targetId: string;
}

/**
 * Curvature and loop rotation of every link, so that several links between the same two nodes
 * fan out symmetrically instead of being drawn on top of each other. The curvature of a link is
 * read in its own direction, so links going opposite ways between the same nodes are mirrored
 * to land on distinct sides. Deterministic: links are ordered by id within a pair.
 */
export const computeLinkCurvatures = (links: readonly LinkEnds[]): Map<string, { curvature: number; rotation: number }> => {
  const groups = new Map<string, LinkEnds[]>();
  links.forEach((link) => {
    const key = link.sourceId < link.targetId ? `${link.sourceId}|${link.targetId}` : `${link.targetId}|${link.sourceId}`;
    const group = groups.get(key);
    if (group) group.push(link);
    else groups.set(key, [link]);
  });
  const result = new Map<string, { curvature: number; rotation: number }>();
  groups.forEach((group) => {
    const sorted = [...group].sort((a, b) => a.id.localeCompare(b.id));
    sorted.forEach((link, index) => {
      if (link.sourceId === link.targetId) {
        // Loops on one node nest, each one wider than the previous.
        result.set(link.id, { curvature: 0.5 + index * 0.3, rotation: 0 });
        return;
      }
      if (sorted.length === 1) {
        result.set(link.id, { curvature: 0, rotation: 0 });
        return;
      }
      const offset = (index - (sorted.length - 1) / 2) * PARALLEL_CURVATURE_STEP;
      // Expressed for the canonical direction, then flipped for a link going the other way.
      const canonical = link.sourceId < link.targetId;
      result.set(link.id, { curvature: canonical ? offset : -offset, rotation: 0 });
    });
  });
  return result;
};

const boxesOverlap = (first: Box, second: Box): boolean => Math.abs(first.x - second.x) < first.halfWidth + second.halfWidth
  && Math.abs(first.y - second.y) < first.halfHeight + second.halfHeight;

/** Kept in the order given, each one dropped when it would overlap one kept before it. */
export const keepNonOverlapping = <T extends { box: Box }>(items: readonly T[]): T[] => {
  const kept: T[] = [];
  items.forEach((item) => {
    if (!kept.some((other) => boxesOverlap(other.box, item.box))) kept.push(item);
  });
  return kept;
};

/**
 * The longest prefix of `text` that fits `maxWidth` once followed by an ellipsis, measured with
 * the context's current font. The full text is kept when it fits.
 */
export const fitText = (measure: (text: string) => number, text: string, maxWidth: number): string => {
  if (measure(text) <= maxWidth) return text;
  let low = 0;
  let high = text.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (measure(`${text.slice(0, middle)}\u2026`) <= maxWidth) low = middle;
    else high = middle - 1;
  }
  return low === 0 ? '\u2026' : `${text.slice(0, low).trimEnd()}\u2026`;
};

/** The smallest box holding every point, `null` when there is none. */
export const boundsOf = (points: readonly Point[]): { minX: number; minY: number; maxX: number; maxY: number } | null => {
  if (points.length === 0) return null;
  return points.reduce((acc, { x, y }) => ({
    minX: Math.min(acc.minX, x),
    minY: Math.min(acc.minY, y),
    maxX: Math.max(acc.maxX, x),
    maxY: Math.max(acc.maxY, y),
  }), { minX: Infinity, minY: Infinity, maxX: -Infinity, maxY: -Infinity });
};
