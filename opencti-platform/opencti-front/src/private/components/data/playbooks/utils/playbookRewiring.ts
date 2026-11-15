import type { Connection, Edge, Node } from 'reactflow';
import type { PlaybookDefinitionEdge } from '../types/playbook-types';

// Rewiring a playbook on the canvas: a link dragged to another step or port (playbookRelink),
// a step attached under another out port by drawing a connection to it (playbookMoveNode).
// The plan is computed here, pure and testable; the server checks the same invariants again
// (one entry point, no cycle, every step reachable) and is the authority.

type PlaybookRelink = { kind: 'relink'; linkId: string; toNodeId: string; fromNodeId?: string; fromPortId?: string };
type PlaybookMove = { kind: 'move'; nodeId: string; parentNodeId: string; parentPortId: string };
export type PlaybookRewire = PlaybookRelink | PlaybookMove;

const isStep = (node: Node | undefined): node is Node => Boolean(node && node.type !== 'placeholder');
const isEntryPoint = (node: Node | undefined) => Boolean(node?.data?.component?.is_entry_point);

// The links of the playbook: the edges between two steps, never the edges of the add buttons.
export const toDefinitionLinks = (nodes: Node[], edges: Edge[]): PlaybookDefinitionEdge[] => {
  const steps = new Set(nodes.filter(isStep).map((n) => n.id));
  return edges
    .filter((e) => e.type !== 'placeholder' && steps.has(e.source) && steps.has(e.target))
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

const endpoints = (nodes: Node[], connection: Connection | Edge) => {
  const source = nodes.find((n) => n.id === connection.source);
  const target = nodes.find((n) => n.id === connection.target);
  const port = connection.sourceHandle;
  if (!isStep(source) || !isStep(target) || !port || isEntryPoint(target) || source.id === target.id) {
    return null;
  }
  const isOutPort = (source.data?.component?.ports ?? []).some((p: { id: string; type: string }) => p.id === port && p.type === 'out');
  return isOutPort ? { source, target, port } : null;
};

// A new connection drawn from an out port to a step: the step (and its branch) moves under that port.
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

// An existing link whose end was dragged to another step, or whose start was dragged to another port.
export const planEdgeUpdate = (nodes: Node[], edges: Edge[], oldEdge: Edge, connection: Connection): PlaybookRewire | null => {
  if (oldEdge.type === 'placeholder') return null;
  const ends = endpoints(nodes, connection);
  if (!ends) return null;
  const sourceChanged = ends.source.id !== oldEdge.source || ends.port !== oldEdge.sourceHandle;
  const targetChanged = ends.target.id !== oldEdge.target;
  if (!sourceChanged && !targetChanged) return null;
  const links = toDefinitionLinks(nodes, edges);
  const others = links.filter((l) => l.id !== oldEdge.id);
  if (others.some((l) => l.from.id === ends.source.id && l.from.port === ends.port && l.to.id === ends.target.id)) {
    return null; // the same link already exists
  }
  if (targetChanged && !others.some((l) => l.to.id === oldEdge.target)) {
    return null; // the former target would be left without a parent
  }
  if (reaches(others, ends.target.id, ends.source.id)) {
    return null; // cycle
  }
  return {
    kind: 'relink',
    linkId: oldEdge.id,
    toNodeId: ends.target.id,
    ...(sourceChanged ? { fromNodeId: ends.source.id, fromPortId: ends.port } : {}),
  };
};

// The links after the server accepted the rewiring; newLinkId is the id the server answered.
export const applyRewire = (links: PlaybookDefinitionEdge[], rewire: PlaybookRewire, newLinkId: string): PlaybookDefinitionEdge[] => {
  if (rewire.kind === 'relink') {
    return links.map((l) => (l.id !== rewire.linkId ? l : {
      id: l.id,
      from: rewire.fromNodeId && rewire.fromPortId ? { id: rewire.fromNodeId, port: rewire.fromPortId } : l.from,
      to: { id: rewire.toNodeId },
    }));
  }
  return [
    ...links.filter((l) => l.to.id !== rewire.nodeId),
    { id: newLinkId, from: { id: rewire.parentNodeId, port: rewire.parentPortId }, to: { id: rewire.nodeId } },
  ];
};
