import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../utils/tests/test-render';
import { defaultColumnsMap } from './dataTableUtils';

const withEntitiesWorkflowFlag = (enable: boolean) => createMockUserContext({
  settings: { platform_feature_flags: enable ? [{ id: 'ENTITIES_WORKFLOW', enable: true }] : [] },
});

vi.mock('../i18n', () => ({
  useFormatter: () => ({
    t_i18n: (s: string) => s,
    fsd: (s: string) => s,
    n: (s: number) => String(s),
    nsdt: (s: string) => s,
    ftd: (s: string) => s,
  }),
}));

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => vi.fn() };
});

const renderColumn = (columnId: string, data: Record<string, unknown>, userContext = withEntitiesWorkflowFlag(false)) => {
  const column = defaultColumnsMap.get(columnId);
  if (!column?.render) throw new Error(`render function not found for column "${columnId}"`);
  const Harness = () => <>{column.render?.(data)}</>;
  return testRender(<Harness />, { userContext });
};

describe('dataTableUtils - workflowInstance column', () => {
  const workflowInstanceCol = defaultColumnsMap.get('workflowInstance');

  it('is defined in defaultColumnsMap', () => {
    expect(workflowInstanceCol).toBeDefined();
  });

  it('has isSortable set to false', () => {
    expect(workflowInstanceCol?.isSortable).toBe(false);
  });

  it('has label "Workflow status"', () => {
    expect(workflowInstanceCol?.label).toBe('Workflow status');
  });

  it('has percentWidth of 12', () => {
    expect(workflowInstanceCol?.percentWidth).toBe(12);
  });

  it('renders ItemStatus with disabled=true when workflowInstance is undefined', () => {
    const { container } = renderColumn('workflowInstance', { workflowInstance: undefined });
    expect(container).toBeTruthy();
  });

  it('renders ItemStatus with disabled=false when workflowInstance.currentStatus is set', () => {
    const mockData = {
      workflowInstance: {
        id: 'instance-1',
        currentStatus: { id: 'status-1', template: { name: 'In Progress', color: '#ff0' } },
      },
    };
    const { getByText } = renderColumn('workflowInstance', mockData);
    expect(getByText('In Progress')).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Task 12: merged workflowInstance / x_opencti_workflow_id render logic
// ---------------------------------------------------------------------------
describe('dataTableUtils - Status column merge (Task 12)', () => {
  it('x_opencti_workflow_id column renders the legacy status when no workflowInstance is present', () => {
    const { getByText } = renderColumn('x_opencti_workflow_id', {
      status: { id: 'status-1', template: { name: 'Legacy status', color: '#ff0' } },
      workflowEnabled: true,
    });
    expect(getByText('Legacy status')).toBeDefined();
  });

  it('x_opencti_workflow_id column prefers workflowInstance.currentStatus when present and the flag is on', () => {
    const { getByText } = renderColumn(
      'x_opencti_workflow_id',
      {
        entity_type: 'Report',
        status: { id: 'status-1', template: { name: 'Legacy status', color: '#ff0' } },
        workflowEnabled: true,
        workflowInstance: {
          id: 'instance-1',
          currentStatus: { id: 'status-2', template: { name: 'New status', color: '#0f0' } },
        },
      },
      withEntitiesWorkflowFlag(true),
    );
    expect(getByText('New status')).toBeDefined();
  });

  it('x_opencti_workflow_id column falls back to legacy status when workflowInstance is present but the flag is off', () => {
    const { getByText } = renderColumn(
      'x_opencti_workflow_id',
      {
        entity_type: 'Report',
        status: { id: 'status-1', template: { name: 'Legacy status', color: '#ff0' } },
        workflowEnabled: true,
        workflowInstance: {
          id: 'instance-1',
          currentStatus: { id: 'status-2', template: { name: 'New status', color: '#0f0' } },
        },
      },
      withEntitiesWorkflowFlag(false),
    );
    expect(getByText('Legacy status')).toBeDefined();
  });

  it('falls back to legacy status when workflowInstance.id is an "initial-" placeholder (transitional safety net)', () => {
    const { getByText } = renderColumn(
      'x_opencti_workflow_id',
      {
        entity_type: 'Report',
        status: { id: 'status-1', template: { name: 'Legacy status', color: '#ff0' } },
        workflowEnabled: true,
        workflowInstance: {
          id: 'initial-entity-1',
          currentStatus: { id: 'status-2', template: { name: 'New status', color: '#0f0' } },
        },
      },
      withEntitiesWorkflowFlag(true),
    );
    expect(getByText('Legacy status')).toBeDefined();
  });

  it('workflowInstance column always uses the new status for DraftWorkspace regardless of the flag', () => {
    const mockData = {
      entity_type: 'DraftWorkspace',
      workflowInstance: {
        id: 'instance-1',
        currentStatus: { id: 'status-1', template: { name: 'In review', color: '#ff0' } },
      },
    };
    const { getByText } = renderColumn('workflowInstance', mockData, withEntitiesWorkflowFlag(false));
    expect(getByText('In review')).toBeDefined();
  });
});

