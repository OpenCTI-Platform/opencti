import { type Node, Position } from 'reactflow';

interface Box {
  x: number;
  y: number;
  width: number;
  height: number;
}

const boxOf = (node: Node): Box | null => {
  const position = node.positionAbsolute ?? node.position;
  if (!node.width || !node.height) return null;
  return { x: position.x, y: position.y, width: node.width, height: node.height };
};

/** Where the line between both centers leaves the box. */
const borderPoint = (box: Box, toward: Box) => {
  const halfWidth = box.width / 2;
  const halfHeight = box.height / 2;
  const centerX = box.x + halfWidth;
  const centerY = box.y + halfHeight;
  const dx = toward.x + toward.width / 2 - centerX;
  const dy = toward.y + toward.height / 2 - centerY;
  if (dx === 0 && dy === 0) return { x: centerX, y: centerY };
  const scale = 1 / Math.max(Math.abs(dx) / halfWidth, Math.abs(dy) / halfHeight);
  return { x: centerX + dx * scale, y: centerY + dy * scale };
};

const sideOf = (box: Box, point: { x: number; y: number }): Position => {
  if (point.x <= box.x + 1) return Position.Left;
  if (point.x >= box.x + box.width - 1) return Position.Right;
  if (point.y <= box.y + 1) return Position.Top;
  return Position.Bottom;
};

/**
 * Endpoints on the facing borders of both nodes, so edges spread around a node instead of all
 * meeting on one handle. `offset` shifts the edge sideways to separate A→B from B→A.
 */
export const floatingEdgeParams = (source: Node, target: Node, offset = 0) => {
  const sourceBox = boxOf(source);
  const targetBox = boxOf(target);
  if (!sourceBox || !targetBox) return null;
  const start = borderPoint(sourceBox, targetBox);
  const end = borderPoint(targetBox, sourceBox);
  const length = Math.hypot(end.x - start.x, end.y - start.y) || 1;
  const normalX = (-(end.y - start.y) / length) * offset;
  const normalY = ((end.x - start.x) / length) * offset;
  return {
    sourceX: start.x + normalX,
    sourceY: start.y + normalY,
    targetX: end.x + normalX,
    targetY: end.y + normalY,
    sourcePosition: sideOf(sourceBox, start),
    targetPosition: sideOf(targetBox, end),
  };
};
