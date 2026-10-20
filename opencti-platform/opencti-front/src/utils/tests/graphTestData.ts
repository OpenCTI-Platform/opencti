import type { GraphLink, GraphNode } from '../../components/graph/graph.types';

/** A drawn node with sensible defaults, for the graph unit tests. */
export const graphNode = (overrides: Partial<GraphNode> = {}): GraphNode => ({
  id: 'node-1',
  name: 'Emotet\n2025-01-01',
  label: 'Emotet',
  disabled: false,
  defaultDate: new Date('2025-01-01T00:00:00.000Z'),
  entity_type: 'Malware',
  parent_types: ['Stix-Domain-Object', 'Stix-Core-Object'],
  relationship_type: '',
  isNestedInferred: false,
  createdBy: { id: 'author', name: 'Author' },
  markedBy: [],
  val: 1,
  color: '#f0b60a',
  x: 0,
  y: 0,
  z: 0,
  isObservable: false,
  rawImg: '',
  img: {} as HTMLImageElement,
  ...overrides,
});

/** A drawn link between two nodes, resolved to the node objects like the library does. */
export const graphLink = (source: GraphNode, target: GraphNode, overrides: Partial<GraphLink> = {}): GraphLink => ({
  id: `${source.id}-${target.id}`,
  name: 'uses',
  label: 'uses',
  disabled: false,
  defaultDate: new Date('2025-01-01T00:00:00.000Z'),
  entity_type: 'uses',
  parent_types: ['basic-relationship', 'stix-core-relationship'],
  relationship_type: 'uses',
  isNestedInferred: false,
  createdBy: { id: 'author', name: 'Author' },
  markedBy: [],
  source,
  source_id: source.id,
  target,
  target_id: target.id,
  inferred: false,
  ...overrides,
});

/** jsdom has no `Path2D`; the painters only need it to exist. */
export const installPath2DStub = () => {
  if (typeof (globalThis as { Path2D?: unknown }).Path2D === 'undefined') {
    (globalThis as { Path2D?: unknown }).Path2D = class {
      constructor(public d?: string) {}
    };
  }
};
