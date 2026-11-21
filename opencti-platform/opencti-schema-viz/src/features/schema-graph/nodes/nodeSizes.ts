import type { GraphNode } from '../buildVisibleGraph';

export const ENTITY_NODE_SIZE = { width: 216, height: 60 };
export const RELATIONSHIP_NODE_SIZE = { width: 188, height: 44 };

export const GROUP_MAX_ITEMS = 6;
const GROUP_WIDTH = 224;
const GROUP_HEADER = 38;
const GROUP_ROW = 26;
const GROUP_PADDING = 10;

export const groupNodeSize = (itemCount: number) => {
  const rows = Math.min(itemCount, GROUP_MAX_ITEMS) + (itemCount > GROUP_MAX_ITEMS ? 1 : 0);
  return { width: GROUP_WIDTH, height: GROUP_HEADER + rows * GROUP_ROW + GROUP_PADDING };
};

/** Every node has a fixed size known before rendering, so the layout never waits for DOM measurement. */
export const nodeSize = (node: GraphNode, isRelationshipType: (typeId: string) => boolean) => {
  if (node.kind === 'group') return groupNodeSize(node.typeIds.length);
  return isRelationshipType(node.typeId) ? RELATIONSHIP_NODE_SIZE : ENTITY_NODE_SIZE;
};
