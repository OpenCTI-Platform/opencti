import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Node, Edge } from 'reactflow';
import { FormikHelpers } from 'formik';
import { useWorkflowForm } from './useWorkflowForm'; // Adjust path
import { WorkflowNodeType, WorkflowDataType, WorkflowActionType, Action, NEW_STATUS_NAME } from '../utils';
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

  // Helper to create a typed mock of FormikHelpers
  const createMockFormikHelpers = () => ({
    setFieldValue: vi.fn() as FormikHelpers<WorkflowEditionFormValues>['setFieldValue'],
  } as unknown as FormikHelpers<WorkflowEditionFormValues>);

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

  describe('onAddObject', () => {
    const mockValues: WorkflowEditionFormValues = {
      statusTemplate: { id: NEW_STATUS_NAME, name: NEW_STATUS_NAME, color: '#a1b6d8' },
      event: '',
      onEnter: [],
      onExit: [],
    };

    it('should add a new condition correctly', () => {
      const node: Node = { id: '1', position: { x: 0, y: 0 }, data: {} };
      const { result } = renderHook(() => useWorkflowForm(node, mockOnClose));
      const helpers = createMockFormikHelpers();

      act(() => {
        result.current.onAddObject(WorkflowDataType.conditions, '', helpers.setFieldValue, mockValues);
      });

      expect(helpers.setFieldValue).toHaveBeenCalledWith(
        WorkflowDataType.conditions,
        expect.objectContaining({
          filterGroups: [],
          filters: [],
          mode: 'and',
        }),
      );
    });

    it('should add a member update action with params', () => {
      const node: Node = { id: '1', position: { x: 0, y: 0 }, data: {} };
      const { result } = renderHook(() => useWorkflowForm(node, mockOnClose));
      const helpers = createMockFormikHelpers();

      act(() => {
        result.current.onAddObject(
          WorkflowDataType.onEnter,
          WorkflowActionType.updateAuthorizedMembers,
          helpers.setFieldValue,
          mockValues,
        );
      });

      const expectedAction: Action = {
        type: WorkflowActionType.updateAuthorizedMembers,
        params: { authorized_members: [] },
      };
      expect(helpers.setFieldValue).toHaveBeenCalledWith(WorkflowDataType.onEnter, [expectedAction]);
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
