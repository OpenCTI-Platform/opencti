import type { NodeTypes } from 'reactflow';
import EntityNode from './EntityNode';
import RelationshipNode from './RelationshipNode';
import TargetGroupNode from './TargetGroupNode';

/** Defined once at module level: React Flow warns and re-mounts nodes when this object changes. */
export const nodeTypes: NodeTypes = {
  entity: EntityNode,
  relationship: RelationshipNode,
  targetGroup: TargetGroupNode,
};
