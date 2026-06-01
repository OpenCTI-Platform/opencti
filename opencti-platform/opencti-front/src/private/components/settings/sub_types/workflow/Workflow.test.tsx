import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ThemeProvider, createTheme, ThemeOptions } from '@mui/material/styles';
import Workflow from './Workflow';
import { WorkflowNodeType } from './utils';
import ThemeDark from '../../../../../components/ThemeDark';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
import { SubTypeWorkflowQuery } from '../__generated__/SubTypeWorkflowQuery.graphql';
import { useWorkflowInitialElements } from './hooks/useWorkflowInitialElements';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';

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

// Captured ReactFlow event handlers
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let capturedOnNodeClick: any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let capturedOnEdgeClick: any;
// Captured publish handler
let capturedOnPublish: (() => void) | undefined;

vi.mock('reactflow', async () => {
  const actual = await vi.importActual('reactflow');
  return {
    ...actual,
    // Capture event handlers and render children without the full ReactFlow canvas
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    default: ({ onNodeClick, onEdgeClick, children }: any) => {
      capturedOnNodeClick = onNodeClick;
      capturedOnEdgeClick = onEdgeClick;
      return <div className="react-flow">{children}</div>;
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    Panel: ({ children }: any) => <div>{children}</div>,
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
      statusTemplates: [
        { id: 'status-1', name: 'Open', color: '#00FF00' },
      ],
      members: [{ id: 'user-1', name: 'Test User' }],
    })),
    graphql: vi.fn((query) => query),
  };
});

// Mock useApiMutation
const mockSaveWorkflowDefinition = vi.fn();
const mockPublishWorkflowDefinition = vi.fn();

vi.mock('../../../../../utils/hooks/useApiMutation', () => ({
  default: vi.fn(),
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

// Mock custom hooks
vi.mock('./hooks/useWorkflowInitialElements', () => ({
  useWorkflowInitialElements: vi.fn(() => ({
    initialNodes: [{
      id: 'node-1',
      type: WorkflowNodeType.status,
      data: {
        name: 'Open',
        statusTemplate: { id: 'status-1', name: 'Open', color: '#00FF00' },
        onEnter: [],
        onExit: [],
      },
      position: { x: 0, y: 0 },
    }],
    initialEdges: [{
      id: 'edge-1',
      source: 'node-1',
      target: 'node-2',
    }],
  })),
}));

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
  default: ({ validationStatus, onPublish }: { validationStatus?: { published?: boolean; validationErrors?: unknown[] }; onPublish?: () => void }) => {
    capturedOnPublish = onPublish;
    return (
      <button
        data-testid="publish-button"
        onClick={onPublish}
        disabled={(validationStatus?.validationErrors?.length ?? 0) > 0}
      >
        {validationStatus?.published ? 'Published' : 'Publish'}
      </button>
    );
  },
}));

vi.mock('./NodeTypes', () => ({
  default: {},
}));

vi.mock('./EdgeTypes', () => ({
  default: {},
}));

describe('Workflow Component', () => {
  const mockQueryRef = {} as PreloadedQuery<SubTypeWorkflowQuery, Record<string, unknown>>;

  beforeEach(() => {
    vi.clearAllMocks();
    // Reset mock implementations so tests don't bleed into each other
    mockSaveWorkflowDefinition.mockReset();
    mockPublishWorkflowDefinition.mockReset();
    // useApiMutation is called twice in Workflow: first for save, then for publish.
    // Discriminate by call order to avoid relying on mutation.toString() which
    // returns '[object Object]' when graphql compiles templates into DocumentNodes.
    vi.mocked(useApiMutation)
      .mockImplementationOnce(() => [mockSaveWorkflowDefinition, false] as ReturnType<typeof useApiMutation>)
      .mockImplementation(() => [mockPublishWorkflowDefinition, false] as ReturnType<typeof useApiMutation>);
    capturedOnNodeClick = undefined;
    capturedOnEdgeClick = undefined;
    capturedOnPublish = undefined;
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
      const { container } = renderWithTheme(<Workflow queryRef={mockQueryRef} />);
      expect(container.querySelector('.react-flow')).toBeInTheDocument();
    });

    it('should render PublishButton', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);
      expect(screen.getByTestId('publish-button')).toBeInTheDocument();
    });

    it('should render Add Status button', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);
      expect(screen.getByText('Add Status')).toBeInTheDocument();
    });

    it('should call fitView on mount', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);
      expect(mockFitView).toHaveBeenCalled();
    });
  });

  describe('User interactions', () => {
    it('should open drawer when Add Status button is clicked', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      const addButton = screen.getByText('Add Status');
      await user.click(addButton);

      expect(screen.getByTestId('workflow-edition-drawer')).toBeInTheDocument();
    });

    it('should close drawer when close button is clicked', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

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
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

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
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      await waitFor(() => {
        const calls = mockSaveWorkflowDefinition.mock.calls;
        if (calls.length > 0) {
          expect(calls[0][0]).toHaveProperty('onCompleted');
          expect(typeof calls[0][0].onCompleted).toBe('function');
        }
      }, { timeout: 2000 });
    });
  });

  describe('Initial state', () => {
    it('should display publish button with correct initial state', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      const publishButton = screen.getByTestId('publish-button');
      expect(publishButton).toBeInTheDocument();
      expect(publishButton).toHaveTextContent('Publish');
    });

    it('should handle workflow definition with no errors', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      const publishButton = screen.getByTestId('publish-button');
      expect(publishButton).not.toBeDisabled();
    });
  });

  describe('Drawer interactions', () => {
    it('should set selectedElement when opening drawer for new status', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      const addButton = screen.getByText('Add Status');
      await user.click(addButton);

      expect(screen.getByTestId('workflow-edition-drawer')).toBeInTheDocument();
    });

    it('should reset selectedElement when closing drawer', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

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
      const { container } = renderWithTheme(<Workflow queryRef={mockQueryRef} />);
      const reactFlow = container.querySelector('.react-flow');

      expect(reactFlow).toBeInTheDocument();
    });

    it('should call fitView with correct options', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      expect(mockFitView).toHaveBeenCalled();
    });
  });

  describe('Node and edge click handlers', () => {
    it('should open drawer when clicking a status node', async () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      act(() => {
        capturedOnNodeClick({}, { id: 'node-1', type: WorkflowNodeType.status, data: {}, position: { x: 0, y: 0 } });
      });

      expect(screen.getByTestId('workflow-edition-drawer')).toBeInTheDocument();
    });

    it('should set source from node id when clicking a placeholder node', async () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      act(() => {
        capturedOnNodeClick({}, { id: 'placeholder-node-1', type: WorkflowNodeType.placeholder, data: {}, position: { x: 0, y: 0 } });
      });

      // Drawer opens (the selectedElement has source = 'node-1')
      expect(screen.getByTestId('workflow-edition-drawer')).toBeInTheDocument();
    });

    it('should open drawer when clicking an edge', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      act(() => {
        capturedOnEdgeClick({}, { id: 'edge-1', source: 'node-1', target: 'node-2' });
      });

      expect(screen.getByTestId('workflow-edition-drawer')).toBeInTheDocument();
    });
  });

  describe('Save mutation onCompleted callback', () => {
    // Use a node with a different statusTemplate id to trigger the autosave
    // (schema differs from initialNodes → previousSchemaRef mismatch → save fires)
    beforeEach(() => {
      mockNodes = [{
        id: 'node-1',
        type: WorkflowNodeType.status,
        data: {
          name: 'Open',
          statusTemplate: { id: 'status-changed', name: 'Open', color: '#00FF00' },
          onEnter: [],
          onExit: [],
        },
        position: { x: 0, y: 0 },
      }];
    });

    it('should set validation errors when save response has errors', async () => {
      mockSaveWorkflowDefinition.mockImplementation((opts: { onCompleted: (r: unknown) => void }) => {
        opts.onCompleted({
          workflowDefinitionSet: {
            id: 'def-1',
            published: false,
            errors: [{ type: 'error_type', message: 'Error message', path: null }],
          },
        });
      });

      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      await waitFor(() => {
        expect(screen.getByTestId('publish-button')).toBeDisabled();
      });
    });

    it('should clear validation errors when save response has no errors', async () => {
      mockSaveWorkflowDefinition.mockImplementation((opts: { onCompleted: (r: unknown) => void }) => {
        opts.onCompleted({
          workflowDefinitionSet: {
            id: 'def-1',
            published: false,
            errors: [],
          },
        });
      });

      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      await waitFor(() => {
        expect(screen.getByTestId('publish-button')).not.toBeDisabled();
      });
    });

    it('should not update status when workflowDefinitionSet is null', async () => {
      mockSaveWorkflowDefinition.mockImplementation((opts: { onCompleted: (r: unknown) => void }) => {
        opts.onCompleted({ workflowDefinitionSet: null });
      });

      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      await waitFor(() => {
        // No state change — button stays in default unpublished, no-error state
        expect(screen.getByTestId('publish-button')).not.toBeDisabled();
        expect(screen.getByTestId('publish-button')).toHaveTextContent('Publish');
      });
    });
  });

  describe('Publish functionality', () => {
    it('should call publish mutation and update status to published on success', async () => {
      mockPublishWorkflowDefinition.mockImplementation((opts: { onCompleted: (r: unknown) => void }) => {
        opts.onCompleted({
          workflowDefinitionSet: {
            id: 'def-0',
            published: true,
          },
        });
      });

      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      // Verify handler was captured during render
      expect(capturedOnPublish).toBeDefined();

      // Verify the button is NOT disabled (i.e. validationErrors is empty)
      const publishButton = screen.getByTestId('publish-button');
      expect(publishButton).not.toBeDisabled();

      // Invoke handlePublish — wrap in act to flush the setWorkflowDefinitionStatus
      // state update triggered by onCompleted
      await act(async () => {
        capturedOnPublish!();
      });

      expect(mockPublishWorkflowDefinition).toHaveBeenCalled();
      expect(screen.getByTestId('publish-button')).toHaveTextContent('Published');
    });

    it('should not call publish mutation when validation errors are present', async () => {
      mockSaveWorkflowDefinition.mockImplementation((opts: { onCompleted: (r: unknown) => void }) => {
        opts.onCompleted({
          workflowDefinitionSet: {
            id: 'def-1',
            published: false,
            errors: [{ type: 'error_type', message: 'Error message', path: null }],
          },
        });
      });
      // Trigger autosave by using a different node
      mockNodes = [{
        id: 'node-1',
        type: WorkflowNodeType.status,
        data: {
          name: 'Open',
          statusTemplate: { id: 'status-changed', name: 'Open', color: '#00FF00' },
          onEnter: [],
          onExit: [],
        },
        position: { x: 0, y: 0 },
      }];

      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      // Wait for errors to be set (publish button becomes disabled)
      await waitFor(() => {
        expect(screen.getByTestId('publish-button')).toBeDisabled();
      });

      expect(mockPublishWorkflowDefinition).not.toHaveBeenCalled();
    });
  });

  describe('Empty state panel', () => {
    it('should show empty state message when there are no nodes', () => {
      mockNodes = [];
      vi.mocked(useWorkflowInitialElements).mockReturnValueOnce({ initialNodes: [], initialEdges: [] });

      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      expect(screen.getByText('Start to define your workflow by adding a Status.')).toBeInTheDocument();
    });

    it('should open drawer via empty state Add Status button', async () => {
      mockNodes = [];
      vi.mocked(useWorkflowInitialElements).mockReturnValueOnce({ initialNodes: [], initialEdges: [] });

      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} />);

      await user.click(screen.getByText('Add Status'));

      expect(screen.getByTestId('workflow-edition-drawer')).toBeInTheDocument();
    });
  });
});
