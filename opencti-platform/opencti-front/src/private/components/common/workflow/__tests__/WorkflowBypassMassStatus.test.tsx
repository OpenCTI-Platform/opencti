import { screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';
import { fetchQuery } from '../../../../../relay/environment';
import testRender, { createMockUserContext } from '../../../../../utils/tests/test-render';
import { WorkflowBypassMassStatus } from '../WorkflowBypassMassStatus';

const isBypassUserMock = vi.hoisted(() => vi.fn(() => true));
const onApplyMock = vi.fn();

vi.mock('../../../../../utils/hooks/useGranted', () => ({
  default: () => false,
  isBypassUser: (...args: unknown[]) => isBypassUserMock(...args),
}));

vi.mock('../../../../../relay/environment', async () => {
  const actual = await vi.importActual('../../../../../relay/environment');
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

const mockMe = { id: 'me-1', capabilities: [{ name: 'BYPASS' }] };

const mockStatusesResponse = {
  statuses: {
    edges: [
      { node: { id: 'status-1', order: 1, type: 'Report', template: { name: 'New', color: '#ff0000' } } },
      { node: { id: 'status-2', order: 2, type: 'Report', template: { name: 'In Progress', color: '#00ff00' } } },
    ],
  },
};

describe('WorkflowBypassMassStatus', () => {
  const fetchQueryMock = fetchQuery as Mock;

  beforeEach(() => {
    onApplyMock.mockReset();
    isBypassUserMock.mockReturnValue(true);
    fetchQueryMock.mockReset();
    fetchQueryMock.mockReturnValue({
      toPromise: () => Promise.resolve(mockStatusesResponse),
    });
  });

  it('renders null for non-bypass users', () => {
    isBypassUserMock.mockReturnValue(false);
    const { container } = testRender(
      <WorkflowBypassMassStatus entityType="Report" me={mockMe} onApply={onApplyMock} />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders null when the ENTITIES_WORKFLOW flag is off', () => {
    const { container } = testRender(
      <WorkflowBypassMassStatus entityType="Report" me={mockMe} onApply={onApplyMock} />,
      { userContext: withEntitiesWorkflowFlag(false) },
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders the status picker for bypass users when the flag is on', () => {
    const { container } = testRender(
      <WorkflowBypassMassStatus entityType="Report" me={mockMe} onApply={onApplyMock} />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    expect(container.firstChild).not.toBeNull();
  });

  it('fetches statuses scoped to GLOBAL when opened', async () => {
    const { user } = testRender(
      <WorkflowBypassMassStatus entityType="Report" me={mockMe} onApply={onApplyMock} />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    await user.click(screen.getByText('Select a status'));
    expect(await screen.findByText('New')).toBeDefined();
    expect(screen.getByText('In Progress')).toBeDefined();
    const [, variables] = fetchQueryMock.mock.calls[0];
    expect(variables.filters.filters).toContainEqual({ key: 'scope', values: ['GLOBAL'] });
    expect(variables.filters.filters).toContainEqual({ key: 'type', values: ['Report'] });
  });

  it('calls onApply with the selected status and applyTransitionActions=true by default', async () => {
    const { user } = testRender(
      <WorkflowBypassMassStatus entityType="Report" me={mockMe} onApply={onApplyMock} />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    await user.click(screen.getByText('Select a status'));
    await user.click(await screen.findByText('New'));
    await user.click(screen.getByText('Apply'));
    await waitFor(() => {
      expect(onApplyMock).toHaveBeenCalledWith('status-1', true);
    });
  });

  it('calls onApply with applyTransitionActions=false when the toggle is switched off', async () => {
    const { user } = testRender(
      <WorkflowBypassMassStatus entityType="Report" me={mockMe} onApply={onApplyMock} />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    await user.click(screen.getByText('Select a status'));
    await user.click(await screen.findByText('In Progress'));
    await user.click(screen.getByRole('checkbox'));
    await user.click(screen.getByText('Apply'));
    await waitFor(() => {
      expect(onApplyMock).toHaveBeenCalledWith('status-2', false);
    });
  });

  it('does not render a comment field', async () => {
    const { user } = testRender(
      <WorkflowBypassMassStatus entityType="Report" me={mockMe} onApply={onApplyMock} />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    await user.click(screen.getByText('Select a status'));
    await user.click(await screen.findByText('New'));
    expect(screen.queryByLabelText('Comment')).toBeNull();
    expect(screen.queryByRole('textbox')).toBeNull();
  });

  it('closes the picker on Cancel without calling onApply', async () => {
    const { user } = testRender(
      <WorkflowBypassMassStatus entityType="Report" me={mockMe} onApply={onApplyMock} />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    await user.click(screen.getByText('Select a status'));
    await user.click(await screen.findByText('New'));
    await user.click(screen.getByText('Cancel'));
    await waitFor(() => expect(screen.queryByRole('checkbox')).toBeNull());
    expect(onApplyMock).not.toHaveBeenCalled();
  });
});
