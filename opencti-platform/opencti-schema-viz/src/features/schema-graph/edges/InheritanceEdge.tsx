import { memo } from 'react';
import { type EdgeProps, getSmoothStepPath } from 'reactflow';
import { clsx } from 'clsx';
import { type InheritanceEdgeData, MARKER_IDS } from './edgeData';
import './edges.css';

/** Parent → child, gray and dashed; the hollow arrowhead sits on the parent. */
const InheritanceEdge = ({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data }: EdgeProps<InheritanceEdgeData>) => {
  const [path] = getSmoothStepPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, borderRadius: 10 });
  return (
    <path
      id={id}
      d={path}
      fill="none"
      markerStart={`url(#${MARKER_IDS.inheritance})`}
      className={clsx('react-flow__edge-path', 'sv-edge-inheritance', data?.indirect && 'is-indirect', data && `is-${data.emphasis}`)}
    />
  );
};

export default memo(InheritanceEdge);
