import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Node, Edge } from 'reactflow';
import { useWorkflowForm } from './useWorkflowForm'; // Adjust path
import { WorkflowNodeType, NEW_STATUS_NAME } from '../utils';
import { WorkflowEditionFormValues } from '../WorkflowEditionDrawer';

const mockSetNodes = vi.fn();
const mockAddStatus = vi.fn();
const mockDeleteElement = vi.fn();
const mockOnClose = vi.fn();

vi.mock('reactflow', () => ({
  useReactFlow: () => ({
    setNodes: mockSetNodes,
  }),
}));

vi.mock('./useAddStatus', () => ({
  default: () => mockAddStatus,
}));

vi.mock('./useDeleteElement', () => ({
  default: () => mockDeleteElement,
}));

vi.mock('../../../../../../components/i18n', () => ({
  useFormatter: () => ({
    t_i18n: (key: string) => key,
  }),
}));

describe('useWorkflowForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Initialization and State', () => {
    it('should identify a status node and return correct title', () => {
      const node: Node = { id: '1', type: WorkflowNodeType.status, position: { x: 0, y: 0 }, data: {} };
      const { result } = renderHook(() => useWorkflowForm(node, mockOnClose));

      expect(result.current.isStatus).toBe(true);
      expect(result.current.isNewStatus).toBe(false);
      expect(result.current.drawerTitle).toBe('Edit status');
    });

    it('should identify a placeholder as a new status', () => {
      const node: Node = { id: '1', type: WorkflowNodeType.placeholder, position: { x: 0, y: 0 }, data: {} };
      const { result } = renderHook(() => useWorkflowForm(node, mockOnClose));

      expect(result.current.isStatus).toBe(true);
      expect(result.current.isNewStatus).toBe(true);
      expect(result.current.drawerTitle).toBe('Add status');
    });

    it('should identify an edge as a transition', () => {
      const edge: Edge = { id: 'e1', source: '1', target: '2', type: WorkflowNodeType.transition };
      const { result } = renderHook(() => useWorkflowForm(edge, mockOnClose));

      expect(result.current.isStatus).toBe(false);
      expect(result.current.drawerTitle).toBe('Edit transition');
    });
  });

  describe('Handlers (onSubmit & onDelete)', () => {
    const formValues: WorkflowEditionFormValues = {
      statusTemplate: { id: NEW_STATUS_NAME, name: NEW_STATUS_NAME, color: '#a1b6d8' },
      event: '',
      onEnter: [],
      onExit: [],
    };

    it('should call addStatus on submit when it is a new status', () => {
      const node: Node = { id: '1', type: WorkflowNodeType.placeholder, position: { x: 0, y: 0 }, data: {} };
      const { result } = renderHook(() => useWorkflowForm(node, mockOnClose));

      act(() => {
        result.current.onSubmit(formValues);
      });

      expect(mockAddStatus).toHaveBeenCalledWith(formValues);
      expect(mockOnClose).toHaveBeenCalled();
    });

    it('should update nodes on submit when editing existing element', () => {
      const node: Node = { id: 'existing-id', type: WorkflowNodeType.status, position: { x: 0, y: 0 }, data: { old: 'data' } };
      const { result } = renderHook(() => useWorkflowForm(node, mockOnClose));

      act(() => {
        result.current.onSubmit(formValues);
      });

      expect(mockSetNodes).toHaveBeenCalled();
      const updater = mockSetNodes.mock.calls[0][0] as (nds: Node[]) => Node[];
      const resultNodes = updater([node]);

      expect(resultNodes[0].data).toEqual({ old: 'data', ...formValues });
      expect(mockOnClose).toHaveBeenCalled();
    });

    it('should call deleteElement and close on delete', () => {
      const node: Node = { id: 'to-delete', position: { x: 0, y: 0 }, data: {} };
      const { result } = renderHook(() => useWorkflowForm(node, mockOnClose));

      act(() => {
        result.current.onDelete();
      });

      expect(mockDeleteElement).toHaveBeenCalledWith('to-delete');
      expect(mockOnClose).toHaveBeenCalled();
    });
  });
});
