import { Position } from 'reactflow';

// Under this offset between the two ends of a link, across the flow, the link is one straight
// segment: React Flow measures handles in sub-pixels, and an orthogonal route between two ends a
// pixel or two apart draws a visible jog.
export const PLAYBOOK_STRAIGHT_TOLERANCE = 4;
// Radius of the rounded corners of a real bend, capped by the room the bend has.
export const PLAYBOOK_EDGE_RADIUS = 12;

export interface PlaybookEdgeEnds {
  sourceX: number;
  sourceY: number;
  targetX: number;
  targetY: number;
  sourcePosition: Position;
}

export interface PlaybookEdgePath {
  path: string;
  labelX: number;
  labelY: number;
  // Number of turns of the route: 0 for a straight link, 2 for a step.
  bends: number;
}

const snap = (value: number) => Math.round(value);

// The path of a link between two steps, on whole pixels: a straight segment when both ends are
// aligned within the tolerance, else an orthogonal step with rounded corners whose middle segment
// sits halfway between the two ends (so links leaving one card or joining one card share it).
export const playbookEdgePath = ({ sourceX, sourceY, targetX, targetY, sourcePosition }: PlaybookEdgeEnds): PlaybookEdgePath => {
  const horizontal = sourcePosition === Position.Left || sourcePosition === Position.Right;
  // Work along / across the flow, then map back to x / y.
  const along0 = snap(horizontal ? sourceX : sourceY);
  const along1 = snap(horizontal ? targetX : targetY);
  const across0 = snap(horizontal ? sourceY : sourceX);
  const across1 = snap(horizontal ? targetY : targetX);
  const point = (along: number, across: number) => (horizontal ? `${along},${across}` : `${across},${along}`);

  if (Math.abs(across1 - across0) <= PLAYBOOK_STRAIGHT_TOLERANCE) {
    // One straight segment, on the target's line: the arrowhead stays centred on the card.
    const middle = snap((along0 + along1) / 2);
    return {
      path: `M${point(along0, across1)} L${point(along1, across1)}`,
      labelX: horizontal ? middle : across1,
      labelY: horizontal ? across1 : middle,
      bends: 0,
    };
  }

  const mid = snap((along0 + along1) / 2);
  const direction = Math.sign(across1 - across0);
  const forward = Math.sign(along1 - along0) || 1;
  const radius = Math.max(0, Math.min(
    PLAYBOOK_EDGE_RADIUS,
    Math.abs(mid - along0),
    Math.abs(along1 - mid),
    Math.abs(across1 - across0) / 2,
  ));
  const corner = (alongAt: number, acrossAt: number, inAlong: boolean) => {
    // A quarter turn at (alongAt, acrossAt), entering along the flow (inAlong) or across it.
    if (inAlong) {
      return `L${point(alongAt - forward * radius, acrossAt)} Q${point(alongAt, acrossAt)} ${point(alongAt, acrossAt + direction * radius)}`;
    }
    return `L${point(alongAt, acrossAt - direction * radius)} Q${point(alongAt, acrossAt)} ${point(alongAt + forward * radius, acrossAt)}`;
  };
  const path = [
    `M${point(along0, across0)}`,
    corner(mid, across0, true),
    corner(mid, across1, false),
    `L${point(along1, across1)}`,
  ].join(' ');
  const centre = snap((across0 + across1) / 2);
  return {
    path,
    labelX: horizontal ? mid : centre,
    labelY: horizontal ? centre : mid,
    bends: 2,
  };
};
