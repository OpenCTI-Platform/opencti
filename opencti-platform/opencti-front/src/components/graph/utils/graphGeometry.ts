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

/**
 * A box centred on a point, in the units of the context it is measured in. A rotated box (a label
 * drawn along its link) gives the rectangle it covers in `rotated`; `halfWidth` and `halfHeight`
 * are then the extents of the axis-aligned box holding it.
 */
export interface Box extends Point {
  halfWidth: number;
  halfHeight: number;
  rotated?: { angle: number; halfLength: number; halfThickness: number };
}

/** Self-loops have no length to scale a curvature by, so the library sizes them with this factor. */
const SELF_LOOP_SIZE = 70;
/** A loop rotated by 0 degrees spans the quadrant above and right of its node, by -90 the one above and left. */
const SELF_LOOP_ROTATIONS = [0, -90];
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

export const pointAt = (path: LinkPath | PathBuffer, t: number): Point => {
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
export const tangentAt = (path: LinkPath | PathBuffer, t: number): Point => {
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

// One coordinate of the point of the path at `t` (Bernstein form), without building the point: the trim search below
// evaluates it dozens of times per link at every frame
const coordinateAt = (path: LinkPath | PathBuffer, t: number, axis: 'x' | 'y'): number => {
  const u = 1 - t;
  if (path.kind === 'line') return path.start[axis] + (path.end[axis] - path.start[axis]) * t;
  if (path.kind === 'quadratic') return u * u * path.start[axis] + 2 * u * t * path.control[axis] + t * t * path.end[axis];
  return u * u * u * path.start[axis] + 3 * u * u * t * path.c1[axis] + 3 * u * t * t * path.c2[axis] + t * t * t * path.end[axis];
};

const distanceAt = (path: LinkPath | PathBuffer, t: number, centre: Point) => Math.hypot(coordinateAt(path, t, 'x') - centre.x, coordinateAt(path, t, 'y') - centre.y);

/**
 * The parameter where the path leaves a circle of `radius` around `centre`, searched from the
 * end given. The path is assumed to start inside the circle and leave it once, which holds for
 * a link leaving a node.
 */
const exitParameter = (path: LinkPath | PathBuffer, centre: Point, radius: number, fromEnd: boolean): number => {
  let inside = fromEnd ? 1 : 0;
  let outside = fromEnd ? 0 : 1;
  if (distanceAt(path, outside, centre) <= radius) return outside;
  for (let iteration = 0; iteration < TRIM_ITERATIONS; iteration += 1) {
    const middle = (inside + outside) / 2;
    if (distanceAt(path, middle, centre) <= radius) inside = middle;
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

/**
 * A path whose points are written in place. The link painter fills the same buffers for every link of every frame
 * with the values `linkPath`, `subPath`, `trimToNodes` and `tangentAt` return, so painting allocates nothing per link.
 */
export interface PathBuffer {
  kind: LinkPath['kind'];
  start: Point;
  control: Point;
  c1: Point;
  c2: Point;
  end: Point;
}

export const createPathBuffer = (): PathBuffer => ({
  kind: 'line',
  start: { x: 0, y: 0 },
  control: { x: 0, y: 0 },
  c1: { x: 0, y: 0 },
  c2: { x: 0, y: 0 },
  end: { x: 0, y: 0 },
});

const setPoint = (point: Point, x: number, y: number) => {
  point.x = x;
  point.y = y;
};

/** `linkPath`, written into `out`. */
export const linkPathInto = (out: PathBuffer, start: Point, end: Point, curvature: number, selfRotationDegrees = 0): PathBuffer => {
  setPoint(out.start, start.x, start.y);
  setPoint(out.end, end.x, end.y);
  const length = Math.hypot(end.x - start.x, end.y - start.y);
  if (length === 0) {
    const d = (curvature || 1) * SELF_LOOP_SIZE;
    const angle = (selfRotationDegrees * Math.PI) / 180;
    const outAngle = angle - Math.PI / 2;
    out.kind = 'cubic';
    setPoint(out.c1, end.x + d * Math.cos(outAngle), end.y + d * Math.sin(outAngle));
    setPoint(out.c2, end.x + d * Math.cos(angle), end.y + d * Math.sin(angle));
    return out;
  }
  if (!curvature) {
    out.kind = 'line';
    return out;
  }
  const angle = Math.atan2(end.y - start.y, end.x - start.x);
  const d = length * curvature;
  out.kind = 'quadratic';
  setPoint(out.control, (start.x + end.x) / 2 + d * Math.cos(angle - Math.PI / 2), (start.y + end.y) / 2 + d * Math.sin(angle - Math.PI / 2));
  return out;
};

// One axis of the de Casteljau split of a cubic at `to`, then of its first part at `s`: the part between them
const cubicPartAxis = (p0: number, p1: number, p2: number, p3: number, to: number, s: number) => {
  const a = p0 + (p1 - p0) * to;
  const b = p1 + (p2 - p1) * to;
  const c = p2 + (p3 - p2) * to;
  const d = a + (b - a) * to;
  const e = b + (c - b) * to;
  const f = d + (e - d) * to;
  const a2 = p0 + (a - p0) * s;
  const b2 = a + (d - a) * s;
  const c2 = d + (f - d) * s;
  const d2 = a2 + (b2 - a2) * s;
  const e2 = b2 + (c2 - b2) * s;
  return { start: d2 + (e2 - d2) * s, c1: e2, c2, end: f };
};

/** `subPath`, written into `out` (which may not be `path`). */
export const subPathInto = (out: PathBuffer, path: PathBuffer, from: number, to: number): PathBuffer => {
  out.kind = path.kind;
  if (path.kind === 'line') {
    setPoint(out.start, coordinateAt(path, from, 'x'), coordinateAt(path, from, 'y'));
    setPoint(out.end, coordinateAt(path, to, 'x'), coordinateAt(path, to, 'y'));
    return out;
  }
  const s = to === 0 ? 0 : from / to;
  if (path.kind === 'quadratic') {
    // Split at `to`, then the first part at `from / to`.
    const headControlX = path.start.x + (path.control.x - path.start.x) * to;
    const headControlY = path.start.y + (path.control.y - path.start.y) * to;
    const headEndX = coordinateAt(path, to, 'x');
    const headEndY = coordinateAt(path, to, 'y');
    const u = 1 - s;
    setPoint(out.start, u * u * path.start.x + 2 * u * s * headControlX + s * s * headEndX, u * u * path.start.y + 2 * u * s * headControlY + s * s * headEndY);
    setPoint(out.control, headControlX + (headEndX - headControlX) * s, headControlY + (headEndY - headControlY) * s);
    setPoint(out.end, headEndX, headEndY);
    return out;
  }
  const x = cubicPartAxis(path.start.x, path.c1.x, path.c2.x, path.end.x, to, s);
  const y = cubicPartAxis(path.start.y, path.c1.y, path.c2.y, path.end.y, to, s);
  setPoint(out.start, x.start, y.start);
  setPoint(out.c1, x.c1, y.c1);
  setPoint(out.c2, x.c2, y.c2);
  setPoint(out.end, x.end, y.end);
  return out;
};

const loopHalf = createPathBuffer();

/** `trimToNodes`, written into `out` (which may not be `path`); `false` instead of `null`. */
export const trimToNodesInto = (out: PathBuffer, path: PathBuffer, startReach: number, endReach: number): boolean => {
  if (path.kind === 'cubic' && path.start.x === path.end.x && path.start.y === path.end.y) {
    const from = exitParameter(subPathInto(loopHalf, path, 0, 0.5), path.start, startReach, false) / 2;
    const to = 0.5 + exitParameter(subPathInto(loopHalf, path, 0.5, 1), path.end, endReach, true) / 2;
    subPathInto(out, path, from, to);
    return true;
  }
  const length = Math.hypot(path.end.x - path.start.x, path.end.y - path.start.y);
  if (length <= startReach + endReach) return false;
  const from = exitParameter(path, path.start, startReach, false);
  const to = exitParameter(path, path.end, endReach, true);
  if (to <= from) return false;
  subPathInto(out, path, from, to);
  return true;
};

/** `tangentAt`, written into `out`. */
export const tangentInto = (out: Point, path: PathBuffer, t: number): Point => {
  const u = 1 - t;
  let x: number;
  let y: number;
  if (path.kind === 'line') {
    x = path.end.x - path.start.x;
    y = path.end.y - path.start.y;
  } else if (path.kind === 'quadratic') {
    x = 2 * u * (path.control.x - path.start.x) + 2 * t * (path.end.x - path.control.x);
    y = 2 * u * (path.control.y - path.start.y) + 2 * t * (path.end.y - path.control.y);
  } else {
    x = 3 * u * u * (path.c1.x - path.start.x) + 6 * u * t * (path.c2.x - path.c1.x) + 3 * t * t * (path.end.x - path.c2.x);
    y = 3 * u * u * (path.c1.y - path.start.y) + 6 * u * t * (path.c2.y - path.c1.y) + 3 * t * t * (path.end.y - path.c2.y);
  }
  const length = Math.hypot(x, y);
  if (length === 0) setPoint(out, 1, 0);
  else setPoint(out, x / length, y / length);
  return out;
};

export interface LinkEnds {
  id: string;
  sourceId: string;
  targetId: string;
}

/**
 * The key of a link in the curvature and bend maps: the two connector links of a nested
 * relationship share its id, so a link is told apart by its id and its two ends.
 */
export const linkEndsKey = (link: LinkEnds) => `${link.id}|${link.sourceId}|${link.targetId}`;

/**
 * Curvature and loop rotation of every link, keyed by `linkEndsKey`, so that several links between
 * the same two nodes fan out symmetrically instead of being drawn on top of each other. The
 * curvature of a link is read in its own direction, so links going opposite ways between the same
 * nodes are mirrored to land on distinct sides. Deterministic: links are ordered by id within a pair.
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
        // Loops on one node take the two quadrants above it in turn, clear of the name drawn under the
        // node, each pair wider than the previous one: no two labels share a spot.
        result.set(linkEndsKey(link), { curvature: 0.5 + Math.floor(index / 2) * 0.3, rotation: SELF_LOOP_ROTATIONS[index % 2] });
        return;
      }
      if (sorted.length === 1) {
        result.set(linkEndsKey(link), { curvature: 0, rotation: 0 });
        return;
      }
      const offset = (index - (sorted.length - 1) / 2) * PARALLEL_CURVATURE_STEP;
      // Expressed for the canonical direction, then flipped for a link going the other way.
      const canonical = link.sourceId < link.targetId;
      result.set(linkEndsKey(link), { curvature: canonical ? offset : -offset, rotation: 0 });
    });
  });
  return result;
};

/** A bend never exceeds this curvature: past it a link reads as a loop. */
const MAX_BEND = 0.6;
/** Obstacles this close to an end of the link are hidden by the end node itself. */
const END_ZONE = 0.08;

/**
 * Curvatures that make straight links bend around the nodes lying on their way, for layouts
 * that line nodes up (layers, tiers): a link from the first to the third node of a row would
 * otherwise run through the second one and read as two links. Only links drawn straight (no
 * parallel link) are bent, away from the obstacle closest to their line and just enough to clear
 * every obstacle on that side by `clearance`. Nodes are indexed in a grid so that long links
 * across large graphs stay cheap; deterministic. Bends and curvatures are keyed by `linkEndsKey`.
 */
export const computeObstacleBends = (
  links: readonly LinkEnds[],
  positions: ReadonlyMap<string, Point>,
  clearance: number,
  curvatures?: ReadonlyMap<string, { curvature: number }>,
): Map<string, number> => {
  const cell = clearance * 3;
  const grid = new Map<string, string[]>();
  const cellKey = (cx: number, cy: number) => `${cx}:${cy}`;
  positions.forEach((point, id) => {
    if (!Number.isFinite(point.x) || !Number.isFinite(point.y)) return;
    const key = cellKey(Math.floor(point.x / cell), Math.floor(point.y / cell));
    const members = grid.get(key);
    if (members) members.push(id);
    else grid.set(key, [id]);
  });
  const bends = new Map<string, number>();
  links.forEach((link) => {
    if (link.sourceId === link.targetId || (curvatures?.get(linkEndsKey(link))?.curvature ?? 0) !== 0) return;
    const start = positions.get(link.sourceId);
    const end = positions.get(link.targetId);
    if (!start || !end) return;
    const length = Math.hypot(end.x - start.x, end.y - start.y);
    if (length < clearance * 2) return;
    const u = { x: (end.x - start.x) / length, y: (end.y - start.y) / length };
    // Positive curvature moves the curve towards this side (see `linkPath`).
    const normal = { x: u.y, y: -u.x };
    const seen = new Set<string>([link.sourceId, link.targetId]);
    const obstacles: { t: number; offset: number }[] = [];
    const steps = Math.ceil(length / cell);
    for (let step = 0; step <= steps; step += 1) {
      const along = Math.min(length, step * cell);
      const cx = Math.floor((start.x + u.x * along) / cell);
      const cy = Math.floor((start.y + u.y * along) / cell);
      for (let dx = -1; dx <= 1; dx += 1) {
        for (let dy = -1; dy <= 1; dy += 1) {
          (grid.get(cellKey(cx + dx, cy + dy)) ?? []).forEach((id) => {
            if (seen.has(id)) return;
            seen.add(id);
            const point = positions.get(id) as Point;
            const t = ((point.x - start.x) * u.x + (point.y - start.y) * u.y) / length;
            const offset = (point.x - start.x) * normal.x + (point.y - start.y) * normal.y;
            if (t > END_ZONE && t < 1 - END_ZONE && Math.abs(offset) < clearance) obstacles.push({ t, offset });
          });
        }
      }
    }
    if (obstacles.length === 0) return;
    // A quadratic curve of curvature c rises 2 t (1 - t) c times the length at t. Bending away from
    // an obstacle clears it sooner than bending towards it, which must pass beyond it.
    const neededTowards = (side: number) => obstacles.reduce((most, obstacle) => {
      const height = obstacle.offset * side > 0 ? Math.abs(obstacle.offset) + clearance : clearance - Math.abs(obstacle.offset);
      return Math.max(most, height / (2 * obstacle.t * (1 - obstacle.t) * length));
    }, 0);
    const positive = neededTowards(1);
    const negative = neededTowards(-1);
    // An obstacle right on the line is passed on the positive side.
    bends.set(linkEndsKey(link), negative < positive ? -Math.min(MAX_BEND, negative) : Math.min(MAX_BEND, positive));
  });
  return bends;
};

const axesOf = (box: Box) => {
  const angle = box.rotated?.angle ?? 0;
  return { cos: Math.cos(angle), sin: Math.sin(angle), halfLength: box.rotated?.halfLength ?? box.halfWidth, halfThickness: box.rotated?.halfThickness ?? box.halfHeight };
};

// Half the extent of a rectangle projected on the unit axis (x, y).
const projectedRadius = (axes: ReturnType<typeof axesOf>, x: number, y: number) => axes.halfLength * Math.abs(axes.cos * x + axes.sin * y)
  + axes.halfThickness * Math.abs(-axes.sin * x + axes.cos * y);

/**
 * Whether two boxes overlap. Rotated boxes are compared by the rectangles they cover (separating
 * axes), not by their axis-aligned extents: two labels drawn side by side along parallel links do
 * not overlap although their extents do.
 */
export const boxesOverlap = (first: Box, second: Box): boolean => {
  const dx = second.x - first.x;
  const dy = second.y - first.y;
  if (Math.abs(dx) >= first.halfWidth + second.halfWidth || Math.abs(dy) >= first.halfHeight + second.halfHeight) return false;
  if (!first.rotated && !second.rotated) return true;
  const a = axesOf(first);
  const b = axesOf(second);
  return [a, b].every(({ cos, sin }) => [[cos, sin], [-sin, cos]].every(([x, y]) => Math.abs(dx * x + dy * y) < projectedRadius(a, x, y) + projectedRadius(b, x, y)));
};

export interface BoxIndex {
  add: (box: Box) => void;
  overlaps: (box: Box) => boolean;
}

/**
 * Boxes indexed in a grid of `cellSize`, so that checking a box against thousands of others only
 * looks at its neighbours: what a frame needs to place labels among every node it drew.
 */
export const createBoxIndex = (cellSize: number): BoxIndex => {
  const cells = new Map<string, Box[]>();
  const cellsOf = (box: Box, visit: (key: string) => void) => {
    const minX = Math.floor((box.x - box.halfWidth) / cellSize);
    const maxX = Math.floor((box.x + box.halfWidth) / cellSize);
    const minY = Math.floor((box.y - box.halfHeight) / cellSize);
    const maxY = Math.floor((box.y + box.halfHeight) / cellSize);
    for (let cx = minX; cx <= maxX; cx += 1) {
      for (let cy = minY; cy <= maxY; cy += 1) visit(`${cx}:${cy}`);
    }
  };
  return {
    add: (box) => cellsOf(box, (key) => {
      const members = cells.get(key);
      if (members) members.push(box);
      else cells.set(key, [box]);
    }),
    overlaps: (box) => {
      let found = false;
      cellsOf(box, (key) => {
        if (!found) found = (cells.get(key) ?? []).some((other) => boxesOverlap(other, box));
      });
      return found;
    },
  };
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
