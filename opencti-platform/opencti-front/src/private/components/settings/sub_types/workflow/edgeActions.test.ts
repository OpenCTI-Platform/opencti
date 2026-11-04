import { describe, it, expect } from 'vitest';
import type { Edge, Node } from 'reactflow';
import { deleteConnection } from './edgeActions';
import { WorkflowNodeType } from './utils';

const node = (id: string, type: WorkflowNodeType): Node => ({ id, type, data: {}, position: { x: 0, y: 0 } });
const edge = (source: string, target: string): Edge => ({ id: `e-${source}->${target}`, source, target, type: WorkflowNodeType.transition });

// NEW -> submit -> DONE, and a second source OPEN -> submit
const nodes = [
  node('NEW', WorkflowNodeType.status),
  node('OPEN', WorkflowNodeType.status),
  node('DONE', WorkflowNodeType.status),
  node('submit', WorkflowNodeType.transition),
];
const edges = [edge('NEW', 'submit'), edge('OPEN', 'submit'), edge('submit', 'DONE')];

describe('deleteConnection', () => {
  it('unlinks the target of a transition and keeps the transition', () => {
    const result = deleteConnection(nodes, edges, 'e-submit->DONE');
    expect(result.nodes).toEqual(nodes);
    expect(result.edges.map((e) => e.id)).toEqual(['e-NEW->submit', 'e-OPEN->submit']);
  });

  it('removes one source of a transition that has others', () => {
    const result = deleteConnection(nodes, edges, 'e-NEW->submit');
    expect(result.nodes).toEqual(nodes);
    expect(result.edges.map((e) => e.id)).toEqual(['e-OPEN->submit', 'e-submit->DONE']);
  });

  it('removes the transition and its edges when its last source goes', () => {
    const once = deleteConnection(nodes, edges, 'e-NEW->submit');
    const result = deleteConnection(once.nodes, once.edges, 'e-OPEN->submit');
    expect(result.nodes.map((n) => n.id)).toEqual(['NEW', 'OPEN', 'DONE']);
    expect(result.edges).toEqual([]);
  });

  it('changes nothing for an unknown edge', () => {
    const result = deleteConnection(nodes, edges, 'gone');
    expect(result).toEqual({ nodes, edges });
  });
});
