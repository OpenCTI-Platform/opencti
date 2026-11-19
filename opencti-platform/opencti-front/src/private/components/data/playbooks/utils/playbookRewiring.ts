import type { Connection, Edge, Node } from 'reactflow';
import type { PlaybookDefinitionEdge } from '../types/playbook-types';

// Rewiring a playbook on the canvas: a step attached under another out port by a drag between one of
// its points and that port, whichever end the drag starts from (playbookMoveNode). A step has one link
// in, so the end of a link is never dragged on its own (it would sit on the input and hide it).
// The plan is computed here, pure and testable; the server checks the same invariants again
// (one entry point, no cycle, every step reachable) and is the authority.

export type PlaybookRewire = { kind: 'move'; nodeId: string; parentNodeId: string; parentPortId: string };

const isStep = (node: Node | undefined): node is Node => Boolean(node && node.type !== 'placeholder');
const isEntryPoint = (node: Node | undefined) => Boolean(node?.data?.component?.is_entry_point);

// React Flow adds a connection drawn on the canvas to its own edges (defaultEdges) before it calls
// onConnect, under an id of its own: it is not a link of the playbook until the server answers.
const DRAWN_CONNECTION_PREFIX = 'reactflow__edge-';
export const isDrawnConnection = (edge: Edge) => edge.id.startsWith(DRAWN_CONNECTION_PREFIX);
export const withoutDrawnConnections = (edges: Edge[]) => edges.filter((e) => !isDrawnConnection(e));

// The links of the playbook: the edges between two steps, never the edges of the add buttons nor a
// connection React Flow drew before the server answered.
export const toDefinitionLinks = (nodes: Node[], edges: Edge[]): PlaybookDefinitionEdge[] => {
  const steps = new Set(nodes.filter(isStep).map((n) => n.id));
  return edges
    .filter((e) => e.type !== 'placeholder' && !isDrawnConnection(e) && steps.has(e.source) && steps.has(e.target))
    .map((e) => ({ id: e.id, from: { id: e.source, port: e.sourceHandle ?? 'out' }, to: { id: e.target } }));
};

// True when `to` can be reached from `from` by following the links.
export const reaches = (links: PlaybookDefinitionEdge[], from: string, to: string): boolean => {
  const children = new Map<string, string[]>();
  links.forEach((l) => {
    children.set(l.from.id, [...(children.get(l.from.id) ?? []), l.to.id]);
  });
  const seen = new Set<string>([from]);
  const queue = [from];
  while (queue.length > 0) {
    const current = queue.shift() as string;
    if (current === to) return true;
    (children.get(current) ?? []).forEach((child) => {
      if (!seen.has(child)) {
        seen.add(child);
        queue.push(child);
      }
    });
  }
  return false;
};

const endpoints = (nodes: Node[], connection: Connection) => {
  const source = nodes.find((n) => n.id === connection.source);
  const target = nodes.find((n) => n.id === connection.target);
  const port = connection.sourceHandle;
  if (!isStep(source) || !isStep(target) || !port || isEntryPoint(target) || source.id === target.id) {
    return null;
  }
  const isOutPort = (source.data?.component?.ports ?? []).some((p: { id: string; type: string }) => p.id === port && p.type === 'out');
  return isOutPort ? { source, target, port } : null;
};

// A connection drawn between an out port and a step (from either end: React Flow hands it over with the
// out port as its source): the step (and its branch) moves under that port.
export const planConnect = (nodes: Node[], edges: Edge[], connection: Connection): PlaybookRewire | null => {
  const ends = endpoints(nodes, connection);
  if (!ends) return null;
  const links = toDefinitionLinks(nodes, edges);
  const incoming = links.filter((l) => l.to.id === ends.target.id);
  if (incoming.length === 1 && incoming[0].from.id === ends.source.id && incoming[0].from.port === ends.port) {
    return null; // already its only parent
  }
  const remaining = links.filter((l) => l.to.id !== ends.target.id);
  if (reaches(remaining, ends.target.id, ends.source.id)) {
    return null; // the step would become its own ancestor
  }
  return { kind: 'move', nodeId: ends.target.id, parentNodeId: ends.source.id, parentPortId: ends.port };
};

// The links after the server accepted the move; newLinkId is the id the server answered.
export const applyRewire = (links: PlaybookDefinitionEdge[], rewire: PlaybookRewire, newLinkId: string): PlaybookDefinitionEdge[] => {
  return [
    ...links.filter((l) => l.to.id !== rewire.nodeId),
    { id: newLinkId, from: { id: rewire.parentNodeId, port: rewire.parentPortId }, to: { id: rewire.nodeId } },
  ];
};
