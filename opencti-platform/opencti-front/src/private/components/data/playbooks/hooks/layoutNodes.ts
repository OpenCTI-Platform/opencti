import { stratify, tree } from 'd3-hierarchy';
import type { Edge, Node } from 'reactflow';

const NODE_WIDTH = 250;
const NODE_HEIGHT = 175;

// Id of the root added when several nodes have no parent: d3 stratify accepts
// exactly one parentless node and throws "multiple roots" otherwise.
const VIRTUAL_ROOT_ID = '__playbook_layout_virtual_root__';

const layout = tree<Node>()
  .nodeSize([NODE_WIDTH, NODE_HEIGHT])
  .separation(() => 1);

/**
 * Positions of the playbook nodes as a tree, from the links between them.
 * A playbook whose definition holds several nodes without an incoming link
 * (a node added through the API and not linked yet) is still laid out: those
 * nodes are placed side by side on the first row, each with its own subtree.
 */
export const layoutNodes = (nodes: Node[], edges: Edge[]): Node[] => {
  if (nodes.length === 0) {
    return [];
  }
  const ids = new Set(nodes.map((n) => n.id));
  const parentOf = new Map<string, string>();
  edges.forEach((e) => {
    if (!parentOf.has(e.target) && ids.has(e.source) && e.source !== e.target) {
      parentOf.set(e.target, e.source);
    }
  });
  const rootCount = nodes.filter((n) => !parentOf.has(n.id)).length;
  const virtual = rootCount > 1;
  const data: Node[] = virtual
    ? [{ id: VIRTUAL_ROOT_ID, position: { x: 0, y: 0 }, data: {} }, ...nodes]
    : nodes;
  const hierarchy = stratify<Node>()
    .id((d) => d.id)
    .parentId((d) => {
      if (d.id === VIRTUAL_ROOT_ID) return undefined;
      return parentOf.get(d.id) ?? (virtual ? VIRTUAL_ROOT_ID : undefined);
    })(data);
  const root = layout(hierarchy);
  const offset = virtual ? NODE_HEIGHT : 0;
  return root
    .descendants()
    .filter((d) => d.data.id !== VIRTUAL_ROOT_ID)
    .map((d) => ({ ...d.data, position: { x: d.x, y: d.y - offset } }));
};

export default layoutNodes;
