import { describe, it, expect } from 'vitest';
import type { Edge, Node } from 'reactflow';
import { applyLayout } from './useWorkflowLayout';
import { transformToWorkflowDefinition } from '../utils';
import type { SubTypeWorkflowQuery$data } from '../../__generated__/SubTypeWorkflowQuery.graphql';

const nodes: Node[] = [
  { id: 'NEW', type: 'status', position: { x: 0, y: 0 }, width: 160, height: 50, data: { statusTemplate: { id: 'NEW', name: 'New', color: '#ff9800' } } },
  { id: 't', type: 'transition', position: { x: 0, y: 0 }, width: 160, height: 50, data: { event: 'submit' } },
  { id: 'DONE', type: 'status', position: { x: 0, y: 0 }, width: 160, height: 50, data: { statusTemplate: { id: 'DONE', name: 'Done', color: '#2e7d32' } } },
];
const edges: Edge[] = [
  { id: 'e1', source: 'NEW', target: 't', type: 'transition' },
  { id: 'e2', source: 't', target: 'DONE', type: 'transition', data: { kept: true } },
];
const options = { spacing: [50, 50] as [number, number] };

describe('applyLayout', () => {
  it('moves nodes into rows and keeps their data', () => {
    const result = applyLayout(nodes, edges, options);
    const byId = new Map(result.nodes.map((n) => [n.id, n]));
    expect(byId.get('NEW')!.position.y).toBeLessThan(byId.get('t')!.position.y);
    expect(byId.get('t')!.position.y).toBeLessThan(byId.get('DONE')!.position.y);
    expect(byId.get('NEW')!.data.statusTemplate).toEqual({ id: 'NEW', name: 'New', color: '#ff9800' });
    expect(byId.get('t')!.data.layout).toEqual({ backward: false, lane: null, rank: 1 });
    // No style is added: nothing hides nodes before the layout any more.
    expect(byId.get('NEW')!.style).toBeUndefined();
  });

  it('writes a route on every edge and keeps existing edge data', () => {
    const result = applyLayout(nodes, edges, options);
    result.edges.forEach((e) => expect(e.data.route.length).toBeGreaterThanOrEqual(2));
    expect(result.edges[1].data.kept).toBe(true);
  });

  it('leaves the saved workflow definition unchanged', () => {
    const definition = { id: '1', name: 'wf', initialState: 'NEW' } as SubTypeWorkflowQuery$data['workflowDefinition'];
    const before = JSON.stringify(transformToWorkflowDefinition(nodes, edges, definition));
    const result = applyLayout(nodes, edges, options);
    expect(JSON.stringify(transformToWorkflowDefinition(result.nodes, result.edges, definition))).toBe(before);
  });

  it('does not mutate its input', () => {
    applyLayout(nodes, edges, options);
    expect(nodes[0].position).toEqual({ x: 0, y: 0 });
    expect(edges[0].data).toBeUndefined();
  });
});
