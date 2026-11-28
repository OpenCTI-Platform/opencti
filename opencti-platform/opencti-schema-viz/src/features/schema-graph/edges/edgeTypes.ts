import type { EdgeTypes } from 'reactflow';
import InheritanceEdge from './InheritanceEdge';
import RelationEdge from './RelationEdge';

export const edgeTypes: EdgeTypes = {
  inheritance: InheritanceEdge,
  relation: RelationEdge,
};
