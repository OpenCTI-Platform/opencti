import type { SchemaType } from '../../../data/schemaTypes';
import type { GroupGraphNode, TypeRole } from '../buildVisibleGraph';
import type { LayoutDirection } from '../layout/LayoutEngine';

export interface TypeNodeData {
  type: SchemaType;
  role: TypeRole;
  direction: LayoutDirection;
  /** Relations that expanding the node would draw. */
  relationCount: number;
  /** Relationship types only: how many source → target pairs use this relationship. */
  usageCount: number;
  onToggleExpand: (typeId: string) => void;
}

export interface TargetGroupNodeData {
  group: GroupGraphNode;
  direction: LayoutDirection;
  onReveal: (typeIds: string[]) => void;
}
