import type { Edge, Node } from 'reactflow';
import { outPorts, portHasPill } from '../types/nodes/playbookNodeGeometry';

type Translate = (message: string, options?: { values?: Record<string, string> }) => string;

// What a screen reader reads for a link: its two steps by name and, when the source step names its
// ports, the port the link leaves from. React Flow would otherwise name it "Edge from <id> to <id>".
export const playbookEdgeAriaLabel = (edge: Edge, nodesById: Map<string, Node>, t: Translate): string => {
  const nameOf = (node: Node | undefined) => {
    if (!node) return '';
    if (node.type === 'placeholder') return t('Add component');
    return node.data?.name ? t(node.data.name) : '';
  };
  const source = nodesById.get(edge.source);
  const target = nodesById.get(edge.target);
  const ports = source?.data?.component
    ? outPorts(source.data.component.ports)
    : ((source?.data?.linkedPorts ?? []) as string[]).map((id) => ({ id, type: 'out' }));
  const port = edge.sourceHandle ?? 'out';
  const values = { source: nameOf(source), target: nameOf(target) };
  return portHasPill(port, ports.length)
    ? t('Link from {source} ({port}) to {target}', { values: { ...values, port: t(port) } })
    : t('Link from {source} to {target}', { values });
};

// The links whose name is missing or stale, renamed; the same array when every name holds.
export const nameEdges = (edges: Edge[], nodes: Node[], t: Translate): Edge[] => {
  const nodesById = new Map(nodes.map((node) => [node.id, node]));
  let changed = false;
  const named = edges.map((edge) => {
    const ariaLabel = playbookEdgeAriaLabel(edge, nodesById, t);
    if (edge.ariaLabel === ariaLabel) return edge;
    changed = true;
    return { ...edge, ariaLabel };
  });
  return changed ? named : edges;
};
