import { renderHook, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Edge, Node } from 'reactflow';
import useDeleteKey from './useDeleteKey';
import { WorkflowNodeType } from '../utils';

const node = (id: string, type: WorkflowNodeType, selected = false): Node => ({ id, type, selected, data: {}, position: { x: 0, y: 0 } });
const edge = (source: string, target: string, selected = false): Edge => ({ id: `e-${source}->${target}`, source, target, selected, type: WorkflowNodeType.transition });
const element = (parent: HTMLElement, tag = 'div', attributes: Record<string, string> = {}) => {
  const el = parent.appendChild(document.createElement(tag));
  Object.entries(attributes).forEach(([name, value]) => el.setAttribute(name, value));
  return el;
};

let graph: { nodes: Node[]; edges: Edge[] };
const mockSetNodes = vi.fn();
const mockSetEdges = vi.fn();
const mockGetNodes = () => graph.nodes;
const mockGetEdges = () => graph.edges;
vi.mock('reactflow', () => ({
  useReactFlow: () => ({ getNodes: mockGetNodes, getEdges: mockGetEdges, setNodes: mockSetNodes, setEdges: mockSetEdges }),
}));

describe('useDeleteKey', () => {
  let canvas: HTMLElement;

  beforeEach(() => {
    vi.clearAllMocks();
    canvas = element(document.body, 'div', { class: 'react-flow' });
    // NEW -submit-> DONE, DONE has a placeholder.
    graph = {
      nodes: [node('NEW', WorkflowNodeType.status), node('DONE', WorkflowNodeType.status), node('submit', WorkflowNodeType.transition), node('placeholder-DONE', WorkflowNodeType.placeholder)],
      edges: [edge('NEW', 'submit'), edge('submit', 'DONE'), { ...edge('DONE', 'placeholder-DONE'), type: WorkflowNodeType.placeholder }],
    };
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('deletes a selected edge like the edge menu, even when nothing has focus', () => {
    graph.edges[0] = edge('NEW', 'submit', true);
    renderHook(() => useDeleteKey());

    fireEvent.keyDown(document.body, { key: 'Backspace' });

    // submit loses its last source, so it goes with its edges.
    expect(mockSetNodes).toHaveBeenCalledWith([graph.nodes[0], graph.nodes[1], graph.nodes[3]]);
    expect(mockSetEdges).toHaveBeenCalledWith([graph.edges[2]]);
  });

  it('deletes a selected status with its edges', () => {
    graph.nodes[1] = node('DONE', WorkflowNodeType.status, true);
    renderHook(() => useDeleteKey());

    fireEvent.keyDown(element(canvas), { key: 'Delete' });

    expect(mockSetNodes).toHaveBeenCalledWith([graph.nodes[0], graph.nodes[2], graph.nodes[3]]);
    expect(mockSetEdges).toHaveBeenCalledWith([graph.edges[0]]);
  });

  it('leaves placeholders, form fields, menus and keys from outside the canvas alone', () => {
    graph.edges[1] = edge('submit', 'DONE', true);
    renderHook(() => useDeleteKey());

    fireEvent.keyDown(element(canvas, 'input'), { key: 'Backspace' });
    fireEvent.keyDown(element(element(canvas, 'div', { role: 'menu' })), { key: 'Backspace' });
    fireEvent.keyDown(element(document.body, 'button'), { key: 'Backspace' }); // the drawer, a dialog
    graph.edges[1] = edge('submit', 'DONE');
    graph.nodes[3] = node('placeholder-DONE', WorkflowNodeType.placeholder, true);
    fireEvent.keyDown(document.body, { key: 'Backspace' });

    expect(mockSetNodes).not.toHaveBeenCalled();
    expect(mockSetEdges).not.toHaveBeenCalled();
  });
});
