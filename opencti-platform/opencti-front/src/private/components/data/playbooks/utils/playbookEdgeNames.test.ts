import { describe, expect, it } from 'vitest';
import type { Edge, Node } from 'reactflow';
import { nameEdges, playbookEdgeAriaLabel } from './playbookEdgeNames';

// A translator that fills the ICU values, as react-intl does for these keys.
const t = (message: string, options?: { values?: Record<string, string> }) => Object.entries(options?.values ?? {})
  .reduce((text, [key, value]) => text.replace(`{${key}}`, value), message);

const step = (id: string, name: string, ports: string[]): Node => ({
  id,
  type: 'workflow',
  position: { x: 0, y: 0 },
  data: { name, component: { id: `c-${id}`, ports: ports.map((port) => ({ id: port, type: 'out' })) } },
});
const nodes: Node[] = [
  step('reduce', 'Keep reports only', ['out', 'unmatch']),
  step('log', 'Log non reports', ['out']),
  step('qualify', 'Qualify report', []),
  { id: 'ph', type: 'placeholder', position: { x: 0, y: 0 }, data: { name: '+' } },
];
const byId = new Map(nodes.map((node) => [node.id, node]));

describe('playbookEdgeAriaLabel', () => {
  it('names a link by its two steps, never by their ids', () => {
    const label = playbookEdgeAriaLabel({ id: 'e1', source: 'log', target: 'qualify', sourceHandle: 'out' }, byId, t);
    expect(label).toBe('Link from Log non reports to Qualify report');
  });

  it('names the port when the source step names its ports', () => {
    const label = playbookEdgeAriaLabel({ id: 'e2', source: 'reduce', target: 'log', sourceHandle: 'unmatch' }, byId, t);
    expect(label).toBe('Link from Keep reports only (unmatch) to Log non reports');
  });

  it('names the add button a free port leads to', () => {
    const label = playbookEdgeAriaLabel({ id: 'e3', source: 'reduce', target: 'ph', sourceHandle: 'out' }, byId, t);
    expect(label).toBe('Link from Keep reports only (out) to Add component');
  });
});

describe('nameEdges', () => {
  const edges: Edge[] = [{ id: 'e1', source: 'log', target: 'qualify', sourceHandle: 'out' }];

  it('sets the missing names', () => {
    const named = nameEdges(edges, nodes, t);
    expect(named).not.toBe(edges);
    expect(named[0].ariaLabel).toBe('Link from Log non reports to Qualify report');
  });

  it('returns the same array when every name holds, so the store is not written again', () => {
    const named = nameEdges(edges, nodes, t);
    expect(nameEdges(named, nodes, t)).toBe(named);
  });
});
