import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Node, Edge } from 'reactflow';
import WorkflowEditionDrawer from './WorkflowEditionDrawer';
import { useWorkflowForm } from './hooks/useWorkflowForm';
import { WorkflowNodeType } from './utils';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------
vi.mock('./hooks/useWorkflowForm');

vi.mock('../../../../../components/i18n', () => ({
  useFormatter: () => ({ t_i18n: (key: string) => key }),
}));

vi.mock('./StatusForm', () => ({
  default: () => <div data-testid="status-form" />,
}));

vi.mock('./TransitionForm', () => ({
  default: () => <div data-testid="transition-form" />,
}));

vi.mock('@components/common/drawer/Drawer', () => ({
  default: ({
    title,
    open,
    onClose,
    children,
  }: {
    title: string;
    open: boolean;
    onClose: () => void;
    children: React.ReactNode;
  }) =>
    open ? (
      <div data-testid="drawer">
        <h2 data-testid="drawer-title">{title}</h2>
        <button data-testid="drawer-close" onClick={onClose}>
          Close
        </button>
        {children}
      </div>
    ) : null,
}));

vi.mock('@common/form/FormButtonContainer', () => ({
  default: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="form-buttons">{children}</div>
  ),
}));

vi.mock('@common/button/Button', () => ({
  default: ({
    children,
    onClick,
    disabled,
  }: {
    children: React.ReactNode;
    onClick?: () => void;
    disabled?: boolean;
  }) => (
    <button onClick={onClick} disabled={disabled}>
      {children}
    </button>
  ),
}));

// ---------------------------------------------------------------------------
// Default mock return values
// ---------------------------------------------------------------------------
const mockOnDelete = vi.fn();
const mockOnSubmit = vi.fn();
const mockOnClose = vi.fn();

const defaultFormHook = {
  drawerTitle: 'Edit status',
  isStatus: true,
  isNewStatus: false,
  onSubmit: mockOnSubmit,
  onDelete: mockOnDelete,
  validationSchema: undefined,
} as unknown as ReturnType<typeof useWorkflowForm>;

const statusNode: Node = {
  id: 'status-1',
  type: WorkflowNodeType.status,
  position: { x: 0, y: 0 },
  data: { statusTemplate: { id: 'st-1', name: 'Open', color: '#00FF00' } },
};

const placeholderNode: Node = {
  id: 'placeholder-1',
  type: WorkflowNodeType.placeholder,
  position: { x: 0, y: 0 },
  data: {},
};

const transitionEdge: Edge = {
  id: 'trans-1',
  source: 'status-1',
  target: 'status-2',
  data: { event: 'approve' },
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
describe('WorkflowEditionDrawer', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(useWorkflowForm).mockReturnValue(defaultFormHook);
  });

  describe('drawer visibility', () => {
    it('renders the drawer when open=true', () => {
      render(
        <WorkflowEditionDrawer
          open={true}
          selectedElement={statusNode}
          onClose={mockOnClose}
        />,
      );
      expect(screen.getByTestId('drawer')).toBeInTheDocument();
    });

    it('does not render the drawer content when open=false', () => {
      render(
        <WorkflowEditionDrawer
          open={false}
          selectedElement={statusNode}
          onClose={mockOnClose}
        />,
      );
      expect(screen.queryByTestId('drawer')).not.toBeInTheDocument();
    });

    it('shows the drawer title from useWorkflowForm', () => {
      render(
        <WorkflowEditionDrawer
          open={true}
          selectedElement={statusNode}
          onClose={mockOnClose}
        />,
      );
      expect(screen.getByTestId('drawer-title')).toHaveTextContent('Edit status');
    });
  });

  describe('form selection', () => {
    it('renders StatusForm when isStatus=true', () => {
      vi.mocked(useWorkflowForm).mockReturnValue({ ...defaultFormHook, isStatus: true } as unknown as ReturnType<typeof useWorkflowForm>);
      render(
        <WorkflowEditionDrawer
          open={true}
          selectedElement={statusNode}
          onClose={mockOnClose}
        />,
      );
      expect(screen.getByTestId('status-form')).toBeInTheDocument();
      expect(screen.queryByTestId('transition-form')).not.toBeInTheDocument();
    });

    it('renders TransitionForm when isStatus=false', () => {
      vi.mocked(useWorkflowForm).mockReturnValue({ ...defaultFormHook, isStatus: false } as unknown as ReturnType<typeof useWorkflowForm>);
      render(
        <WorkflowEditionDrawer
          open={true}
          selectedElement={transitionEdge}
          onClose={mockOnClose}
        />,
      );
      expect(screen.getByTestId('transition-form')).toBeInTheDocument();
      expect(screen.queryByTestId('status-form')).not.toBeInTheDocument();
    });
  });

  describe('footer buttons', () => {
    it('shows "Cancel" and "Add" buttons for a new status (placeholder)', () => {
      vi.mocked(useWorkflowForm).mockReturnValue({
        ...defaultFormHook,
        isStatus: true,
        isNewStatus: true,
        drawerTitle: 'Add status',
      } as unknown as ReturnType<typeof useWorkflowForm>);
      render(
        <WorkflowEditionDrawer
          open={true}
          selectedElement={placeholderNode}
          onClose={mockOnClose}
        />,
      );
      expect(screen.getByText('Cancel')).toBeInTheDocument();
      expect(screen.getByText('Add')).toBeInTheDocument();
    });

    it('shows "Delete" and "Update" buttons for an existing status', () => {
      vi.mocked(useWorkflowForm).mockReturnValue({
        ...defaultFormHook,
        isStatus: true,
        isNewStatus: false,
      } as unknown as ReturnType<typeof useWorkflowForm>);
      render(
        <WorkflowEditionDrawer
          open={true}
          selectedElement={statusNode}
          onClose={mockOnClose}
        />,
      );
      expect(screen.getByText('Delete')).toBeInTheDocument();
      expect(screen.getByText('Update')).toBeInTheDocument();
    });

    it('calls onDelete when the Cancel button is clicked', async () => {
      const user = userEvent.setup();
      vi.mocked(useWorkflowForm).mockReturnValue({
        ...defaultFormHook,
        isNewStatus: true,
      } as unknown as ReturnType<typeof useWorkflowForm>);
      render(
        <WorkflowEditionDrawer
          open={true}
          selectedElement={placeholderNode}
          onClose={mockOnClose}
        />,
      );
      await user.click(screen.getByText('Cancel'));
      expect(mockOnDelete).toHaveBeenCalled();
    });

    it('calls onDelete when the Delete button is clicked', async () => {
      const user = userEvent.setup();
      render(
        <WorkflowEditionDrawer
          open={true}
          selectedElement={statusNode}
          onClose={mockOnClose}
        />,
      );
      await user.click(screen.getByText('Delete'));
      expect(mockOnDelete).toHaveBeenCalled();
    });
  });

  describe('empty selected element', () => {
    it('renders drawer shell but no form when selectedElement is null', () => {
      render(
        <WorkflowEditionDrawer
          open={true}
          selectedElement={null as unknown as Node}
          onClose={mockOnClose}
        />,
      );
      expect(screen.getByTestId('drawer')).toBeInTheDocument();
      expect(screen.queryByTestId('status-form')).not.toBeInTheDocument();
      expect(screen.queryByTestId('transition-form')).not.toBeInTheDocument();
    });
  });
});
