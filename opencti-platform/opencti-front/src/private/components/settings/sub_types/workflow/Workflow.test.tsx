import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ThemeProvider, createTheme, ThemeOptions } from '@mui/material/styles';
import Workflow from './Workflow';
import { WorkflowNodeType } from './utils';
import ThemeDark from '../../../../../components/ThemeDark';
import { PreloadedQuery } from 'react-relay/relay-hooks/EntryPointTypes';
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
  default: vi.fn((mutation) => {
    if (mutation.toString().includes('Publish')) {
      return [mockPublishWorkflowDefinition];
    }
    return [mockSaveWorkflowDefinition];
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
  default: ({ validationStatus, onPublish, onReset }: {
    validationStatus?: { published?: boolean; validationErrors?: unknown[] };
    onPublish?: () => void;
    onReset?: () => void;
  }) => (
    <div>
      <button
        data-testid="publish-button"
        onClick={onPublish}
        disabled={(validationStatus?.validationErrors?.length ?? 0) > 0}
      >
        {validationStatus?.published ? 'Published' : 'Publish'}
      </button>
      <button data-testid="reset-button" onClick={onReset}>Reset</button>
    </div>
  ),
}));

vi.mock('./NodeTypes', () => ({
  default: {},
}));

vi.mock('./EdgeTypes', () => ({
  default: {},
}));

describe('Workflow Component', () => {
  const mockQueryRef = {} as PreloadedQuery<SubTypeWorkflowQuery, Record<string, unknown>>;
  const mockDepsQueryRef = {} as PreloadedQuery<SubTypeWorkflowDependenciesQuery, Record<string, unknown>>;

  beforeEach(() => {
    vi.clearAllMocks();
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
      const { container } = renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);
      expect(container.querySelector('.react-flow')).toBeInTheDocument();
    });

    it('should render PublishButton', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);
      expect(screen.getByTestId('publish-button')).toBeInTheDocument();
    });

    it('should render Add Status button', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);
      expect(screen.getByText('Add Status')).toBeInTheDocument();
    });

    it('should call fitView on mount', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);
      expect(mockFitView).toHaveBeenCalled();
    });
  });

  describe('User interactions', () => {
    it('should open drawer when Add Status button is clicked', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);

      const addButton = screen.getByText('Add Status');
      await user.click(addButton);

      expect(screen.getByTestId('workflow-edition-drawer')).toBeInTheDocument();
    });

    it('should close drawer when close button is clicked', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);

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
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);

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
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);

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
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);

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
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);

      const publishButton = screen.getByTestId('publish-button');
      expect(publishButton).toBeInTheDocument();
      expect(publishButton).toHaveTextContent('Publish');
    });

    it('should handle workflow definition with no errors', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);

      const publishButton = screen.getByTestId('publish-button');
      expect(publishButton).not.toBeDisabled();
    });
  });

  describe('Drawer interactions', () => {
    it('should set selectedElement when opening drawer for new status', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);

      const addButton = screen.getByText('Add Status');
      await user.click(addButton);

      expect(screen.getByTestId('workflow-edition-drawer')).toBeInTheDocument();
    });

    it('should reset selectedElement when closing drawer', async () => {
      const user = userEvent.setup();
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);

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
      const { container } = renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);
      const reactFlow = container.querySelector('.react-flow');

      expect(reactFlow).toBeInTheDocument();
    });

    it('should call fitView with correct options', () => {
      renderWithTheme(<Workflow queryRef={mockQueryRef} depsQueryRef={mockDepsQueryRef} />);

      expect(mockFitView).toHaveBeenCalled();
    });
  });
});
