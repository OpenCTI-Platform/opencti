import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { fetchQuery } from '../../../../relay/environment';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { WorkflowBypassStatus } from './WorkflowBypassStatus';

const isBypassUserMock = vi.hoisted(() => vi.fn(() => true));
const mockCommit = vi.fn();

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    useMutation: () => [mockCommit, false] as const,
  };
});

vi.mock('../../../../utils/hooks/useGranted', () => ({
  default: () => false,
  isBypassUser: (...args: unknown[]) => isBypassUserMock(...args),
}));

vi.mock('../../../../relay/environment', async () => {
  const actual = await vi.importActual('../../../../relay/environment');
  return {
    ...actual,
    fetchQuery: vi.fn(),
    MESSAGING$: {
      notifySuccess: vi.fn(),
      notifyError: vi.fn(),
    },
  };
});

const withEntitiesWorkflowFlag = (enable: boolean) => createMockUserContext({
  settings: { platform_feature_flags: enable ? [{ id: 'ENTITIES_WORKFLOW', enable: true }] : [] },
});

const mockStatusesResponse = {
  statuses: {
    edges: [
      { node: { id: 'status-1', order: 1, type: 'Report', template: { name: 'New', color: '#ff0000' } } },
      { node: { id: 'status-2', order: 2, type: 'Report', template: { name: 'In Progress', color: '#00ff00' } } },
    ],
  },
};

describe('WorkflowBypassStatus', () => {
  const fetchQueryMock = fetchQuery as Mock;

  beforeEach(() => {
    mockCommit.mockReset();
    isBypassUserMock.mockReturnValue(true);
    fetchQueryMock.mockReset();
    fetchQueryMock.mockReturnValue({
      toPromise: () => Promise.resolve(mockStatusesResponse),
    });
  });

  it('renders null for non-admin users', () => {
    isBypassUserMock.mockReturnValue(false);
    const { container } = testRender(
      <WorkflowBypassStatus entityId="entity-1" entityType="Report" />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders null when the ENTITIES_WORKFLOW flag is off', () => {
    const { container } = testRender(
      <WorkflowBypassStatus entityId="entity-1" entityType="Report" />,
      { userContext: withEntitiesWorkflowFlag(false) },
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders the bypass icon button for admin users when the flag is on', () => {
    const { container } = testRender(
      <WorkflowBypassStatus entityId="entity-1" entityType="Report" />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    expect(container.firstChild).not.toBeNull();
  });

  it('fetches and displays the status list when opened', async () => {
    const { user } = testRender(
      <WorkflowBypassStatus entityId="entity-1" entityType="Report" />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    await user.click(screen.getByLabelText('Bypass status'));
    expect(await screen.findByText('New')).toBeDefined();
    expect(screen.getByText('In Progress')).toBeDefined();
  });

  it('opens the confirm dialog with applyTransitionActions enabled by default', async () => {
    const { user } = testRender(
      <WorkflowBypassStatus entityId="entity-1" entityType="Report" />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    await user.click(screen.getByLabelText('Bypass status'));
    await user.click(await screen.findByText('New'));
    expect(await screen.findByText('Bypass status')).toBeDefined();
    const toggle = screen.getByRole('checkbox') as HTMLInputElement;
    expect(toggle.checked).toBe(true);
  });

  it('calls the setWorkflowStatus mutation with the selected status and toggle value', async () => {
    const { user } = testRender(
      <WorkflowBypassStatus entityId="entity-1" entityType="Report" />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    await user.click(screen.getByLabelText('Bypass status'));
    await user.click(await screen.findByText('New'));
    await user.click(screen.getByRole('checkbox'));
    await user.click(screen.getByText('Apply'));
    await waitFor(() => {
      expect(mockCommit).toHaveBeenCalledOnce();
      const { variables } = mockCommit.mock.calls[0][0];
      expect(variables.entityId).toBe('entity-1');
      expect(variables.targetStatusId).toBe('status-1');
      expect(variables.applyTransitionActions).toBe(false);
    });
  });

  it('closes the dialog on Cancel without calling commit', async () => {
    const { user } = testRender(
      <WorkflowBypassStatus entityId="entity-1" entityType="Report" />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    await user.click(screen.getByLabelText('Bypass status'));
    await user.click(await screen.findByText('New'));
    await user.click(screen.getByText('Cancel'));
    await waitFor(() => expect(screen.queryByRole('checkbox')).toBeNull());
    expect(mockCommit).not.toHaveBeenCalled();
  });
});
