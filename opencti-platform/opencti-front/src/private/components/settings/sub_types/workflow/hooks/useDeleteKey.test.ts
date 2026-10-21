import type { KeyboardEvent } from 'react';
import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Edge, Node } from 'reactflow';
import useDeleteKey from './useDeleteKey';
import { WorkflowNodeType } from '../utils';

const node = (id: string, type: WorkflowNodeType, selected = false): Node => ({ id, type, selected, data: {}, position: { x: 0, y: 0 } });
const edge = (source: string, target: string, selected = false): Edge => ({ id: `e-${source}->${target}`, source, target, selected, type: WorkflowNodeType.transition });
const press = (key: string, target: HTMLElement = document.createElement('div')) => ({ key, target }) as unknown as KeyboardEvent;

let graph: { nodes: Node[]; edges: Edge[] };
const mockSetNodes = vi.fn();
const mockSetEdges = vi.fn();
const mockGetNodes = () => graph.nodes;
const mockGetEdges = () => graph.edges;
vi.mock('reactflow', () => ({
  useReactFlow: () => ({ getNodes: mockGetNodes, getEdges: mockGetEdges, setNodes: mockSetNodes, setEdges: mockSetEdges }),
}));

describe('useDeleteKey', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // NEW -submit-> DONE, DONE has a placeholder.
    graph = {
      nodes: [node('NEW', WorkflowNodeType.status), node('DONE', WorkflowNodeType.status), node('submit', WorkflowNodeType.transition), node('placeholder-DONE', WorkflowNodeType.placeholder)],
      edges: [edge('NEW', 'submit'), edge('submit', 'DONE'), { ...edge('DONE', 'placeholder-DONE'), type: WorkflowNodeType.placeholder }],
    };
  });

  it('deletes a selected edge like the edge menu: the transition goes with its last source', () => {
    graph.edges[0] = edge('NEW', 'submit', true);
    const { result } = renderHook(() => useDeleteKey());

    act(() => result.current(press('Backspace')));

    expect(mockSetNodes).toHaveBeenCalledWith([graph.nodes[0], graph.nodes[1], graph.nodes[3]]);
    expect(mockSetEdges).toHaveBeenCalledWith([graph.edges[2]]);
  });

  it('deletes a selected status with its edges', () => {
    graph.nodes[1] = node('DONE', WorkflowNodeType.status, true);
    const { result } = renderHook(() => useDeleteKey());

    act(() => result.current(press('Delete')));

    expect(mockSetNodes).toHaveBeenCalledWith([graph.nodes[0], graph.nodes[2], graph.nodes[3]]);
    expect(mockSetEdges).toHaveBeenCalledWith([graph.edges[0]]);
  });

  it('leaves placeholders, form fields and open menus alone', () => {
    graph.nodes[3] = node('placeholder-DONE', WorkflowNodeType.placeholder, true);
    graph.edges[1] = edge('submit', 'DONE', true);
    const menu = document.createElement('div');
    menu.setAttribute('role', 'menu');
    const menuItem = menu.appendChild(document.createElement('div'));
    const { result } = renderHook(() => useDeleteKey());

    act(() => result.current(press('Backspace', document.createElement('input'))));
    act(() => result.current(press('Backspace', menuItem)));
    graph.edges[1] = edge('submit', 'DONE');
    act(() => result.current(press('Backspace')));

    expect(mockSetNodes).not.toHaveBeenCalled();
    expect(mockSetEdges).not.toHaveBeenCalled();
  });
});
