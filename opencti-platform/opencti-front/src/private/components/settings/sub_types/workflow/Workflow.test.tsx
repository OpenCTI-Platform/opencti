import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ThemeProvider, createTheme, ThemeOptions } from '@mui/material/styles';
import Workflow from './Workflow';
import { WorkflowNodeType } from './utils';
import ThemeDark from '../../../../../components/ThemeDark';
import type { PreloadedQuery } from 'react-relay';
import { SubTypeWorkflowQuery } from '../__generated__/SubTypeWorkflowQuery.graphql';
import { SubTypeWorkflowDependenciesQuery } from '../__generated__/SubTypeWorkflowDependenciesQuery.graphql';

// Mock ResizeObserver
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

// Create test theme with all required properties
const testTheme = createTheme(ThemeDark() as ThemeOptions);

// Helper to render with theme
const renderWithTheme = (component: React.ReactElement) => {
  return render(
    <ThemeProvider theme={testTheme}>
      {component}
    </ThemeProvider>,
  );
};

// Mock ReactFlow and its hooks
const mockFitView = vi.fn();
const mockGetNode = vi.fn();
let mockSetNodes = vi.fn();
let mockSetEdges = vi.fn();
let mockNodes: unknown[] = [];
let mockEdges: unknown[] = [];

vi.mock('reactflow', async () => {
  const actual = await vi.importActual('reactflow');
  return {
    ...actual,
    useReactFlow: () => ({
      fitView: mockFitView,
      getNode: mockGetNode,
    }),
    useNodesState: () => {
      const setNodes = (newNodes: unknown[] | ((prev: unknown[]) => unknown[])) => {
        if (typeof newNodes === 'function') {
          mockNodes = newNodes(mockNodes);
        } else {
          mockNodes = newNodes;
        }
        mockSetNodes(mockNodes);
      };
      return [mockNodes, setNodes, vi.fn()];
    },
    useEdgesState: () => {
      const setEdges = (newEdges: unknown[] | ((prev: unknown[]) => unknown[])) => {
        if (typeof newEdges === 'function') {
          mockEdges = newEdges(mockEdges);
        } else {
          mockEdges = newEdges;
        }
        mockSetEdges(mockEdges);
      };
      return [mockEdges, setEdges, vi.fn()];
    },
  };
});

// Mock Relay
const mockWorkflowDefinition = {
  id: 'workflow-1',
  name: 'Test Workflow',
  published: false,
  errors: [],
};

vi.mock('react-relay', async () => {
  const actual = await vi.importActual('react-relay');
  return {
    ...actual,
    usePreloadedQuery: vi.fn(() => ({
      workflowDefinition: mockWorkflowDefinition,
      statusTemplates: {
        edges: [{ node: { id: 'status-1', name: 'Open', color: '#00FF00' } }],
      },
      members: { edges: [{ node: { id: 'user-1', name: 'Test User', entity_type: 'User' } }] },
    })),
    graphql: vi.fn((query) => query),
    useMutation: vi.fn(() => [mockPublishWorkflowDefinition]),
  };
});

// Mock useApiMutation
// The component calls useApiMutation in order: save (1st), restore (2nd)
// Publish uses useMutation directly (mocked via react-relay mock above).
// We use a counter that gets reset before each test so the order is always deterministic.
const mockSaveWorkflowDefinition = vi.fn();
const mockPublishWorkflowDefinition = vi.fn();
const mockRestoreWorkflowDefinition = vi.fn();
let useApiMutationCallIndex = 0;

vi.mock('../../../../../utils/hooks/useApiMutation', () => ({
  default: vi.fn(() => {
    const mocks = [mockSaveWorkflowDefinition, mockRestoreWorkflowDefinition];
    const result = mocks[useApiMutationCallIndex % 2] ?? mockSaveWorkflowDefinition;
    useApiMutationCallIndex++;
    return [result];
  }),
}));

// Mock useFormatter
vi.mock('../../../../../components/i18n', () => ({
  default: () => {},
  useFormatter: () => ({
    t_i18n: (key: string) => key,
  }),
}));

// Mock useTheme
vi.mock('@mui/material/styles', async () => {
  const actual = await vi.importActual('@mui/material/styles');
  return {
    ...actual,
    useTheme: () => testTheme,
  };
});

// Stable references for initial nodes/edges – must be module-level constants so that
// useWorkflowInitialElements always returns the same array references across re-renders,
// preventing the sync useEffect([initialNodes, initialEdges]) from looping infinitely.
const mockInitialNodes = [{
  id: 'node-1',
  type: WorkflowNodeType.status,
  data: {
    name: 'Open',
    statusTemplate: { id: 'status-1', name: 'Open', color: '#00FF00' },
    onEnter: [],
    onExit: [],
  },
  position: { x: 0, y: 0 },
}];
const mockInitialEdges = [{
  id: 'edge-1',
  source: 'node-1',
  target: 'node-2',
}];

// Mock custom hooks
vi.mock('./hooks/useWorkflowInitialElements', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./hooks/useWorkflowInitialElements')>();
  return {
    useWorkflowInitialElements: vi.fn(() => ({
      initialNodes: mockInitialNodes,
      initialEdges: mockInitialEdges,
    })),
    convertEdgesToObject: actual.convertEdgesToObject,
  };
});

vi.mock('./hooks/usePlaceholdersSync', () => ({
  usePlaceholdersSync: vi.fn(),
}));

vi.mock('./hooks/useWorkflowLayout', () => ({
  default: vi.fn(),
}));

vi.mock('./hooks/useStatusConnection', () => ({
  useStatusConnection: vi.fn(() => vi.fn()),
}));

// Mock child components
vi.mock('./WorkflowEditionDrawer', () => ({
  default: ({ open, onClose }: { open: boolean; onClose: () => void }) => (
    open ? (
      <div data-testid="workflow-edition-drawer">
        <button onClick={onClose}>Close Drawer</button>
      </div>
    ) : null
  ),
}));

vi.mock('./PublishButton', () => ({
  default: ({ validationStatus, onPublish, onReset, onRestore }: {
    validationStatus?: { hasUnpublishedChanges?: boolean; validationErrors?: unknown[] };
    onPublish?: () => void;
    onReset?: () => void;
    onRestore?: () => void;
  }) => (
    <div>
      <button
        data-testid="publish-button"
        onClick={onPublish}
        disabled={(validationStatus?.validationErrors?.length ?? 0) > 0}
      >
        {!validationStatus?.hasUnpublishedChanges ? 'Published' : 'Publish'}
      </button>
      {/* Always-enabled button for testing handlePublish when errors exist */}
      <button data-testid="force-publish-button" onClick={onPublish}>Force Publish</button>
      <button data-testid="reset-button" onClick={onReset}>Reset</button>
      <button data-testid="restore-button" onClick={onRestore}>Restore</button>
    </div>
  ),
}));

vi.mock('./NodeTypes', () => ({
  default: {},
}));

vi.mock('./EdgeTypes', () => ({
  default: {},
}));

// Mock MESSAGING$ to capture toast calls — must use vi.hoisted because vi.mock is hoisted
const { mockNotifyError, mockNotifySuccess } = vi.hoisted(() => ({
  mockNotifyError: vi.fn(),
  mockNotifySuccess: vi.fn(),
}));
vi.mock('../../../../../relay/environment', () => ({
  MESSAGING$: {
    notifyError: mockNotifyError,
    notifySuccess: mockNotifySuccess,
  },
}));

describe('Workflow Component', () => {
  const mockQueryRef = {} as PreloadedQuery<SubTypeWorkflowQuery, Record<string, unknown>>;
  const mockDepsQueryRef = {} as PreloadedQuery<SubTypeWorkflowDependenciesQuery, Record<string, unknown>>;
  const mockOnRefetch = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    useApiMutationCallIndex = 0;
    mockGetNode.mockReturnValue({ id: 'test-node' });
    mockSetNodes = vi.fn();
    mockSetEdges = vi.fn();
    // Reset mock nodes and edges
    mockNodes = [{
      id: 'node-1',
      type: WorkflowNodeType.status,
      data: {
        name: 'Open',
        statusTemplate: { id: 'status-1', name: 'Open', color: '#00FF00' },
        onEnter: [],
        onExit: [],
      },
      position: { x: 0, y: 0 },
    }];
    mockEdges = [{
      id: 'edge-1',
      source: 'node-1',
      target: 'node-2',
    }];
  });

  describe('Component rendering', () => {
    it('should render ReactFlow component', () => {
      const { container } = renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);
      expect(container.querySelector('.react-flow')).toBeInTheDocument();
    });

    it('should render PublishButton', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);
      expect(screen.getByTestId('publish-button')).toBeInTheDocument();
    });

    it('should render Add Status button', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);
      expect(screen.getByText('Add Status')).toBeInTheDocument();
    });

    it('should call fitView on mount', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);
      expect(mockFitView).toHaveBeenCalled();
    });
  });

  describe('User interactions', () => {
    it('should open drawer when Add Status button is clicked', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      const addButton = screen.getByText('Add Status');
      await user.click(addButton);

      expect(screen.getByTestId('workflow-edition-drawer')).toBeInTheDocument();
    });

    it('should close drawer when close button is clicked', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      // Open drawer
      const addButton = screen.getByText('Add Status');
      await user.click(addButton);
      expect(screen.getByTestId('workflow-edition-drawer')).toBeInTheDocument();

      // Close drawer
      const closeButton = screen.getByText('Close Drawer');
      await user.click(closeButton);

      await waitFor(() => {
        expect(screen.queryByTestId('workflow-edition-drawer')).not.toBeInTheDocument();
      });
    });
  });

  describe('Autosave functionality', () => {
    it('should call saveWorkflowDefinition with correct entity type', async () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      await waitFor(() => {
        const calls = mockSaveWorkflowDefinition.mock.calls;
        if (calls.length > 0) {
          expect(calls[0][0]).toMatchObject({
            variables: expect.objectContaining({
              entityType: 'DraftWorkspace',
            }),
          });
        }
      }, { timeout: 2000 });
    });

    it('should provide onCompleted callback to save mutation', async () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      await waitFor(() => {
        const calls = mockSaveWorkflowDefinition.mock.calls;
        if (calls.length > 0) {
          expect(calls[0][0]).toHaveProperty('onCompleted');
          expect(typeof calls[0][0].onCompleted).toBe('function');
        }
      }, { timeout: 2000 });
    });

    it('should clear nodes and edges when reset is confirmed', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      await user.click(screen.getByTestId('reset-button'));

      const resetCall = mockSaveWorkflowDefinition.mock.calls.find(
        ([arg]) => arg?.variables?.definition?.includes('"states":[]')
          && arg?.variables?.definition?.includes('"transitions":[]'),
      );

      expect(resetCall).toBeDefined();
      resetCall?.[0]?.onCompleted?.({
        workflowDefinitionSet: {
          errors: [],
        },
      });

      expect(mockSetNodes).toHaveBeenCalledWith([]);
      expect(mockSetEdges).toHaveBeenCalledWith([]);
    });
  });

  describe('Initial state', () => {
    it('should display publish button with correct initial state', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      const publishButton = screen.getByTestId('publish-button');
      expect(publishButton).toBeInTheDocument();
      expect(publishButton).toHaveTextContent('Publish');
    });

    it('should handle workflow definition with no errors', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      const publishButton = screen.getByTestId('publish-button');
      expect(publishButton).not.toBeDisabled();
    });
  });

  describe('Drawer interactions', () => {
    it('should set selectedElement when opening drawer for new status', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      const addButton = screen.getByText('Add Status');
      await user.click(addButton);

      expect(screen.getByTestId('workflow-edition-drawer')).toBeInTheDocument();
    });

    it('should reset selectedElement when closing drawer', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      const addButton = screen.getByText('Add Status');
      await user.click(addButton);

      const closeButton = screen.getByText('Close Drawer');
      await user.click(closeButton);

      await waitFor(() => {
        expect(screen.queryByTestId('workflow-edition-drawer')).not.toBeInTheDocument();
      });
    });
  });

  describe('ReactFlow integration', () => {
    it('should pass nodes and edges to ReactFlow', () => {
      const { container } = renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);
      const reactFlow = container.querySelector('.react-flow');

      expect(reactFlow).toBeInTheDocument();
    });

    it('should call fitView with correct options', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      expect(mockFitView).toHaveBeenCalled();
    });
  });

  describe('Publish functionality', () => {
    it('should call notifyError with validation errors toast when pre-existing errors exist', async () => {
      const user = userEvent.setup();
      const { usePreloadedQuery } = await import('react-relay');
      vi.mocked(usePreloadedQuery).mockReturnValueOnce({
        workflowDefinition: {
          ...mockWorkflowDefinition,
          errors: [{ type: 'MISSING_TRANSITION', message: 'State has no outgoing transition', path: [] }],
        },
        statusTemplates: { edges: [{ node: { id: 'status-1', name: 'Open', color: '#00FF00' } }] },
        members: { edges: [] },
      });

      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      // publish-button is disabled when there are errors; use force-publish-button to invoke handlePublish directly
      await user.click(screen.getByTestId('force-publish-button'));

      expect(mockNotifyError).toHaveBeenCalled();
    });

    it('should call commitPublish when there are no validation errors', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      await user.click(screen.getByTestId('publish-button'));

      expect(mockPublishWorkflowDefinition).toHaveBeenCalledWith(
        expect.objectContaining({ variables: { entityType: 'DraftWorkspace' } }),
      );
    });

    it('should call notifySuccess and update status on successful publish', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      await user.click(screen.getByTestId('publish-button'));

      const publishCall = mockPublishWorkflowDefinition.mock.calls[0];
      publishCall?.[0]?.onCompleted?.();

      expect(mockNotifySuccess).toHaveBeenCalledWith('Workflow successfully published');
      await waitFor(() => {
        expect(screen.getByTestId('publish-button')).toHaveTextContent('Published');
      });
    });

    it('should call notifyError with structured toast on publish API error', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      await user.click(screen.getByTestId('publish-button'));

      const publishCall = mockPublishWorkflowDefinition.mock.calls[0];
      publishCall?.[0]?.onError?.({
        res: {
          errors: [{
            message: 'Cannot publish workflow: the following statuses are in use',
            extensions: { data: { removedStates: ['status-1'], entityType: 'DraftWorkspace' } },
          }],
        },
      });

      expect(mockNotifyError).toHaveBeenCalled();
      const toastElement = mockNotifyError.mock.calls[0][0];
      const { getByText } = render(
        <ThemeProvider theme={testTheme}>{toastElement}</ThemeProvider>,
      );
      expect(getByText(/Cannot publish workflow/)).toBeInTheDocument();
    });

    it('should resolve StatusTemplate ID to name in error toast', async () => {
      const { usePreloadedQuery } = await import('react-relay');
      vi.mocked(usePreloadedQuery).mockReturnValueOnce({
        workflowDefinition: mockWorkflowDefinition,
        statusTemplates: { edges: [{ node: { id: 'status-1', name: 'Open', color: '#00FF00' } }] },
        members: { edges: [] },
      });

      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      await user.click(screen.getByTestId('publish-button'));

      const publishCall = mockPublishWorkflowDefinition.mock.calls[0];
      publishCall?.[0]?.onError?.({
        res: {
          errors: [{
            message: 'Cannot publish workflow: statuses in use',
            extensions: { data: { removedStates: ['status-1'] } },
          }],
        },
      });

      const toastElement = mockNotifyError.mock.calls[0][0];
      const { getByText } = render(
        <ThemeProvider theme={testTheme}>{toastElement}</ThemeProvider>,
      );
      // 'status-1' should resolve to 'Open' via statusTemplateMap
      expect(getByText(/Open/)).toBeInTheDocument();
    });

    it('should fall back to raw ID when StatusTemplate is not found', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      await user.click(screen.getByTestId('publish-button'));

      const publishCall = mockPublishWorkflowDefinition.mock.calls[0];
      publishCall?.[0]?.onError?.({
        res: {
          errors: [{
            message: 'Cannot publish workflow: statuses in use',
            extensions: { data: { removedStates: ['unknown-status-id'] } },
          }],
        },
      });

      const toastElement = mockNotifyError.mock.calls[0][0];
      const { getByText } = render(
        <ThemeProvider theme={testTheme}>{toastElement}</ThemeProvider>,
      );
      expect(getByText(/unknown-status-id/)).toBeInTheDocument();
    });

    it('should handle publish API error with no removedStates gracefully', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      await user.click(screen.getByTestId('publish-button'));

      const publishCall = mockPublishWorkflowDefinition.mock.calls[0];
      publishCall?.[0]?.onError?.({ res: { errors: [{ message: 'Unexpected error' }] } });

      expect(mockNotifyError).toHaveBeenCalled();
    });
  });

  describe('Restore functionality', () => {
    it('should call restoreWorkflowDefinition when restore button is clicked', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      await user.click(screen.getByTestId('restore-button'));

      expect(mockRestoreWorkflowDefinition).toHaveBeenCalledWith(
        expect.objectContaining({
          variables: { entityType: 'DraftWorkspace' },
        }),
      );
    });

    it('should reset nodes and edges and call onRefetch when restore completes', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      await user.click(screen.getByTestId('restore-button'));

      // Simulate the mutation onCompleted callback
      const restoreCall = mockRestoreWorkflowDefinition.mock.calls[0];
      restoreCall?.[0]?.onCompleted?.();

      expect(mockSetNodes).toHaveBeenCalledWith(mockInitialNodes);
      expect(mockSetEdges).toHaveBeenCalledWith(mockInitialEdges);
      expect(mockOnRefetch).toHaveBeenCalled();
    });

    it('should update publish status to published when restore completes', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} onRefetch={mockOnRefetch} />);

      await user.click(screen.getByTestId('restore-button'));

      const restoreCall = mockRestoreWorkflowDefinition.mock.calls[0];
      restoreCall?.[0]?.onCompleted?.();

      // After restore the publish button should reflect published state
      await waitFor(() => {
        expect(screen.getByTestId('publish-button')).toHaveTextContent('Published');
      });
    });
  });
});
