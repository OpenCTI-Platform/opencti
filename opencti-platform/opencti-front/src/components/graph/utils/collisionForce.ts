interface CollidingNode {
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number;
  fy?: number;
}

export interface CollisionForce {
  (alpha: number): void;
  initialize: (nodes: CollidingNode[]) => void;
}

/**
 * A d3-compatible force keeping every two nodes at least `distance` apart, so neither the discs
 * nor the labels under them pile up. Neighbours are found through a grid of `distance`-wide
 * cells, which keeps a tick linear in the number of nodes. Fixed nodes (`fx` / `fy`) are never
 * moved, their neighbours move away from them instead.
 */
export const collisionForce = (distance: number, strength = 0.7): CollisionForce => {
  let nodes: CollidingNode[] = [];
  const force = ((alpha: number) => {
    const cells = new Map<string, number[]>();
    const keyOf = (cx: number, cy: number) => `${cx}|${cy}`;
    nodes.forEach((node, index) => {
      const key = keyOf(Math.floor((node.x ?? 0) / distance), Math.floor((node.y ?? 0) / distance));
      const cell = cells.get(key);
      if (cell) cell.push(index);
      else cells.set(key, [index]);
    });
    nodes.forEach((node, index) => {
      const x = node.x ?? 0;
      const y = node.y ?? 0;
      const cx = Math.floor(x / distance);
      const cy = Math.floor(y / distance);
      for (let dx = -1; dx <= 1; dx += 1) {
        for (let dy = -1; dy <= 1; dy += 1) {
          (cells.get(keyOf(cx + dx, cy + dy)) ?? []).forEach((otherIndex) => {
            if (otherIndex <= index) return;
            const other = nodes[otherIndex];
            let ox = (other.x ?? 0) - x;
            let oy = (other.y ?? 0) - y;
            let gap = Math.hypot(ox, oy);
            if (gap >= distance) return;
            if (gap === 0) {
              // Two nodes on the same spot: separate them along a direction of their own.
              ox = ((index * 7919 + otherIndex) % 13) - 6 || 1;
              oy = ((otherIndex * 104729 + index) % 11) - 5 || 1;
              gap = Math.hypot(ox, oy);
            }
            const push = ((distance - gap) / gap) * alpha * strength * 0.5;
            const firstFixed = node.fx !== undefined && node.fx !== null;
            const secondFixed = other.fx !== undefined && other.fx !== null;
            if (firstFixed && secondFixed) return;
            const share = firstFixed || secondFixed ? 2 : 1;
            if (!firstFixed) {
              node.vx = (node.vx ?? 0) - ox * push * share;
              node.vy = (node.vy ?? 0) - oy * push * share;
            }
            if (!secondFixed) {
              other.vx = (other.vx ?? 0) + ox * push * share;
              other.vy = (other.vy ?? 0) + oy * push * share;
            }
          });
        }
      }
    });
  }) as CollisionForce;
  force.initialize = (newNodes) => {
    nodes = newNodes;
  };
  return force;
};
