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

    describe('request access outcome', () => {
      const statusNode = (id: string, data: Record<string, unknown> = {}): Node => ({ id, type: WorkflowNodeType.status, position: { x: 0, y: 0 }, data });

      it('moves an outcome marker off the state that held it when editing a state', () => {
        const approved = statusNode('approved', { requestAccessOutcome: 'APPROVED' });
        const declined = statusNode('declined', { requestAccessOutcome: 'DECLINED' });
        const open = statusNode('open');
        const { result } = renderHook(() => useWorkflowForm(open, mockOnClose));

        act(() => {
          result.current.onSubmit({ ...formValues, requestAccessOutcome: 'APPROVED' });
        });

        const updater = mockSetNodes.mock.calls[0][0] as (nds: Node[]) => Node[];
        const [nextApproved, nextDeclined, nextOpen] = updater([approved, declined, open]);
        expect(nextOpen.data.requestAccessOutcome).toBe('APPROVED');
        expect(nextApproved.data.requestAccessOutcome).toBeUndefined();
        expect(nextDeclined.data.requestAccessOutcome).toBe('DECLINED');
      });

      it('moves an outcome marker off the state that held it when adding a state', () => {
        const approved = statusNode('approved', { requestAccessOutcome: 'APPROVED' });
        const placeholder: Node = { id: '1', type: WorkflowNodeType.placeholder, position: { x: 0, y: 0 }, data: {} };
        const { result } = renderHook(() => useWorkflowForm(placeholder, mockOnClose));
        const values = { ...formValues, statusTemplate: { id: 'new-approved', name: 'New approved', color: '#a1b6d8' }, requestAccessOutcome: 'APPROVED' as const };

        act(() => {
          result.current.onSubmit(values);
        });

        expect(mockAddStatus).toHaveBeenCalledWith(values);
        const updater = mockSetNodes.mock.calls[0][0] as (nds: Node[]) => Node[];
        const added = statusNode('new-approved', { requestAccessOutcome: 'APPROVED' });
        const [nextApproved, nextAdded] = updater([approved, added]);
        expect(nextApproved.data.requestAccessOutcome).toBeUndefined();
        expect(nextAdded.data.requestAccessOutcome).toBe('APPROVED');
      });

      it('leaves the other states alone when no outcome is set', () => {
        const approved = statusNode('approved', { requestAccessOutcome: 'APPROVED' });
        const open = statusNode('open');
        const { result } = renderHook(() => useWorkflowForm(open, mockOnClose));

        act(() => {
          result.current.onSubmit(formValues);
        });

        const updater = mockSetNodes.mock.calls[0][0] as (nds: Node[]) => Node[];
        expect(updater([approved, open])[0].data.requestAccessOutcome).toBe('APPROVED');
      });
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
