import { memo, useCallback } from 'react';
import { EdgeLabelRenderer, type EdgeProps, getBezierPath, type ReactFlowState, useStore } from 'reactflow';
import { clsx } from 'clsx';
import { useCompactMode } from '../hooks/useVisibleStats';
import { MARKER_IDS, type RelationEdgeData } from './edgeData';
import { floatingEdgeParams } from './floatingEdge';
import './edges.css';

const LOOP_SIZE = 70;
const PARALLEL_OFFSET = 7;

/** Relations from a type to itself (Malware controls Malware) loop around the node's side. */
const selfLoopPath = (sourceX: number, sourceY: number, targetX: number, targetY: number): [string, number, number] => {
  const horizontal = Math.abs(sourceY - targetY) < Math.abs(sourceX - targetX);
  if (horizontal) {
    const top = Math.min(sourceY, targetY) - LOOP_SIZE;
    return [`M ${sourceX} ${sourceY} C ${sourceX + LOOP_SIZE} ${sourceY}, ${sourceX + LOOP_SIZE} ${top}, ${(sourceX + targetX) / 2} ${top} S ${targetX - LOOP_SIZE} ${targetY}, ${targetX} ${targetY}`, (sourceX + targetX) / 2, top];
  }
  const side = Math.max(sourceX, targetX) + LOOP_SIZE + 60;
  return [`M ${sourceX} ${sourceY} C ${sourceX} ${sourceY + LOOP_SIZE}, ${side} ${sourceY + LOOP_SIZE}, ${side} ${(sourceY + targetY) / 2} S ${targetX} ${targetY - LOOP_SIZE}, ${targetX} ${targetY}`, side, (sourceY + targetY) / 2];
};

const RelationEdge = ({ id, source, target, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data }: EdgeProps<RelationEdgeData>) => {
  const compact = useCompactMode();
  const sourceNode = useStore(useCallback((state: ReactFlowState) => state.nodeInternals.get(source), [source]));
  const targetNode = useStore(useCallback((state: ReactFlowState) => state.nodeInternals.get(target), [target]));
  const floating = source !== target && sourceNode && targetNode
    ? floatingEdgeParams(sourceNode, targetNode, data?.parallel ? PARALLEL_OFFSET : 0)
    : null;
  const [path, labelX, labelY] = source === target
    ? selfLoopPath(sourceX, sourceY, targetX, targetY)
    : getBezierPath(floating ?? { sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  const emphasis = data?.emphasis ?? 'normal';
  const tone = data?.tone ?? 'relationship';
  const marker = emphasis === 'highlighted' ? MARKER_IDS.highlighted : MARKER_IDS[tone];

  return (
    <>
      <path id={id} d={path} fill="none" markerEnd={`url(#${marker})`} className={clsx('react-flow__edge-path', 'sv-edge-relation', `is-${tone}`, `is-${emphasis}`)} />
      {data && !compact && emphasis !== 'dimmed' && (
        <EdgeLabelRenderer>
          <div
            className={clsx('sv-edge-label', `is-${tone}`, `is-${emphasis}`)}
            style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}
            title={data.description}
          >
            {data.label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
};

export default memo(RelationEdge);
