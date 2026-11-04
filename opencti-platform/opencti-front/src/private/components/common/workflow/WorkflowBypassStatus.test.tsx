import React from 'react';
import { act, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import WorkflowBypassStatus from './WorkflowBypassStatus';
import testRender from '../../../../utils/tests/test-render';
import type { WorkflowStatusStixDomainObject_data$key } from './__generated__/WorkflowStatusStixDomainObject_data.graphql';

const { commit, fetchStatuses, notifications, permissions } = vi.hoisted(() => ({
  commit: vi.fn(),
  fetchStatuses: vi.fn(),
  notifications: { notifySuccess: vi.fn(), notifyError: vi.fn(), notifyRelayError: vi.fn() },
  permissions: { bypass: true, enabled: true },
}));

vi.mock('./WorkflowStatus.graphql', () => ({
  workflowStatusStixDomainObjectFragment: {}, workflowBypassStatusesQuery: {}, workflowSetStatusMutation: {}, COMMENT_MAX_LENGTH: 1000,
}));
vi.mock('react-relay', async (importOriginal) => ({
  ...await importOriginal<typeof import('react-relay')>(),
  useFragment: (_fragment: unknown, data: unknown) => data,
  useMutation: () => [commit, false],
}));
vi.mock('../../../../utils/hooks/useHelper', () => ({ default: () => ({ isFeatureEnable: () => permissions.enabled }) }));
vi.mock('../../../../utils/hooks/useGranted', () => ({ isBypassUser: () => permissions.bypass }));
vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../relay/environment')>(),
  fetchQuery: (...args: unknown[]) => ({ toPromise: () => fetchStatuses(...args) }),
  MESSAGING$: notifications,
}));

const statuses = Array.from({ length: 105 }, (_, index) => ({
  status: { id: `status-${index}`, order: index, template: { name: `Status ${index}`, color: '#ff0000' } },
  onExit: [{ type: 'updateAuthorizedMembers', params: null }],
  onEnter: [{ type: 'validateDraft', params: null }],
  requiresShareOrganizationInput: false,
  requiresUnshareOrganizationInput: false,
}));
const entity = (pendingStatus: string | null = null, source = 0) => ({
  id: 'incident-1', entity_type: 'Incident', workflowInstance: { id: 'instance-1', pendingStatus, currentState: `state-${source}`, currentStatus: statuses[source].status },
}) as unknown as WorkflowStatusStixDomainObject_data$key;

const openDialog = async (onCompleted?: () => void) => {
  const rendered = testRender(<WorkflowBypassStatus data={entity()} entityType="Incident" onCompleted={onCompleted} />);
  return rendered;
};

const selectStatus = async (user: ReturnType<typeof testRender>['user'], name = 'Status 104') => {
  await user.click(screen.getByRole('combobox'));
  await user.click(await screen.findByRole('option', { name: new RegExp(`${name}$`) }));
};

beforeEach(() => {
  vi.clearAllMocks();
  permissions.bypass = true;
  permissions.enabled = true;
  fetchStatuses.mockResolvedValue({ workflowBypassStatuses: statuses });
});

describe('WorkflowBypassStatus', () => {
  it('confirms a status without hooks and keeps the current status until completion', async () => {
    fetchStatuses.mockResolvedValue({ workflowBypassStatuses: [{ ...statuses[104], onExit: [], onEnter: [] }] });
    const { user } = await openDialog();
    expect(screen.getByRole('combobox')).toHaveTextContent('Status 0');
    await selectStatus(user);
    expect(screen.getByRole('dialog')).toBeVisible();
    expect(screen.getByText('No actions are configured for this transition. The status will be changed directly.')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Apply actions' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Update status only' })).toBeNull();
    expect(commit).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Update status' }));
    expect(commit).toHaveBeenCalledOnce();
    expect(commit.mock.calls[0][0].variables).toMatchObject({ targetStatusId: 'status-104', applyTransitionActions: false });
    expect(screen.getByRole('combobox', { hidden: true })).toHaveTextContent('Status 0');
  });

  it('previews source and target hooks and cancels without changing status', async () => {
    const { user } = await openDialog();
    await selectStatus(user);
    expect(screen.getByText('On exit actions')).toBeVisible();
    expect(screen.getByText('On enter actions')).toBeVisible();
    expect(screen.getByText('Update authorized members')).toBeVisible();
    expect(screen.getByText('Validate draft')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(commit).not.toHaveBeenCalled();
  });

  it('dismisses stale confirmation when the source status changes', async () => {
    const { user, rerender } = await openDialog();
    await selectStatus(user);
    rerender(<WorkflowBypassStatus data={entity(null, 1)} entityType="Incident" />);
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(screen.getByRole('combobox')).toHaveTextContent('Status 1');
    expect(commit).not.toHaveBeenCalled();
  });

  it('supports keyboard-only retry after loading fails', async () => {
    fetchStatuses.mockRejectedValueOnce(new Error('Unavailable'));
    const { user } = await openDialog();
    await user.tab();
    await user.keyboard('{Enter}');
    await screen.findByRole('button', { name: 'Retry' });
    await user.tab();
    expect(screen.getByRole('button', { name: 'Retry' })).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(await screen.findByRole('option', { name: /Status 104$/ })).toBeVisible();
  });
  it.each([true, false])('never sends comment or runtime inputs when actions=%s', async (actions) => {
    fetchStatuses.mockResolvedValue({ workflowBypassStatuses: [{
      ...statuses[104], requiresShareOrganizationInput: true, requiresUnshareOrganizationInput: true,
    }] });
    const { user } = await openDialog();
    await selectStatus(user);
    expect(screen.queryByLabelText('Comment')).toBeNull();
    await user.click(screen.getByRole('button', { name: actions ? 'Apply actions' : 'Update status only' }));
    expect(commit).toHaveBeenCalledOnce();
    expect(commit.mock.calls[0][0].variables).toEqual({ entityId: 'incident-1', targetStatusId: 'status-104', applyTransitionActions: actions });
  });

  it.each(['completed', 'pending'])('requests a fresh entity after %s and releases controls when refresh settles', async (executionStatus) => {
    const onCompleted = vi.fn();
    const { user, rerender } = await openDialog(onCompleted);
    await selectStatus(user);
    await user.click(screen.getByRole('button', { name: 'Apply actions' }));
    act(() => commit.mock.calls[0][0].onCompleted({ setWorkflowStatus: { success: true, executionStatus } }, null));
    expect(onCompleted).toHaveBeenCalledOnce();
    rerender(<WorkflowBypassStatus data={entity()} entityType="Incident" onCompleted={onCompleted} refreshing />);
    expect(screen.getByRole('combobox')).toBeDisabled();
    rerender(<WorkflowBypassStatus data={entity()} entityType="Incident" onCompleted={onCompleted} refreshing={false} />);
    expect(screen.getByRole('combobox')).toBeEnabled();
  });

  it('does not refresh a rejected bypass', async () => {
    const onCompleted = vi.fn();
    const { user } = await openDialog(onCompleted);
    await selectStatus(user);
    await user.click(screen.getByRole('button', { name: 'Apply actions' }));
    act(() => commit.mock.calls[0][0].onCompleted({ setWorkflowStatus: { success: false, reason: 'Denied' } }, null));
    expect(onCompleted).not.toHaveBeenCalled();
  });

  it.each(['bypass', 'enabled'] as const)('hides the control and never queries when %s is false', (permission) => {
    permissions[permission] = false;
    testRender(<WorkflowBypassStatus data={entity()} entityType="Incident" />);
    expect(screen.queryByRole('combobox')).toBeNull();
    expect(fetchStatuses).not.toHaveBeenCalled();
  });

  it.each(['pending', 'error'])('disables bypass while the instance is %s', (pendingStatus) => {
    testRender(<WorkflowBypassStatus data={entity(pendingStatus)} entityType="Incident" />);
    expect(screen.getByRole('combobox')).toBeDisabled();
    expect(fetchStatuses).not.toHaveBeenCalled();
  });

  it('shows loading, then all published mapped choices in server order', async () => {
    let resolve!: (data: unknown) => void;
    fetchStatuses.mockReturnValue(new Promise((done) => {
      resolve = done;
    }));
    const { user } = testRender(<WorkflowBypassStatus data={entity()} entityType="Incident" />);
    await user.click(screen.getByRole('combobox'));
    expect(screen.getByRole('status')).toHaveTextContent('Loading');
    expect(screen.queryByRole('dialog')).toBeNull();
    await act(async () => resolve({ workflowBypassStatuses: statuses }));
    expect(fetchStatuses).toHaveBeenCalledWith(expect.anything(), { entityId: 'incident-1' });
    expect(screen.getAllByRole('option').map((option) => option.textContent)).toEqual(statuses.map(({ status }) => `${status.order + 1}${status.template.name}`));
  });

  it('notifies query failures and supports retry', async () => {
    fetchStatuses.mockRejectedValueOnce(new Error('Unavailable'));
    const { user } = testRender(<WorkflowBypassStatus data={entity()} entityType="Incident" />);
    await user.click(screen.getByRole('combobox'));
    await user.click(await screen.findByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('option', { name: /Status 104$/ })).toBeVisible();
    expect(notifications.notifyError).toHaveBeenCalledOnce();
    expect(fetchStatuses).toHaveBeenCalledTimes(2);
  });

  it('does not allow submission with no mapped target', async () => {
    fetchStatuses.mockResolvedValue({ workflowBypassStatuses: [] });
    const { user } = testRender(<WorkflowBypassStatus data={entity()} entityType="Incident" />);
    await user.click(screen.getByRole('combobox'));
    expect(await screen.findByText('No available status')).toBeVisible();
    expect(screen.queryByRole('option')).toBeNull();
    expect(commit).not.toHaveBeenCalled();
  });

  it.each([true, false])('submits once with actions=%s', async (actions) => {
    const { user } = await openDialog();
    await selectStatus(user);
    const apply = screen.getByRole('button', { name: actions ? 'Apply actions' : 'Update status only' });
    await user.dblClick(apply);
    expect(commit).toHaveBeenCalledOnce();
    expect(commit.mock.calls[0][0].variables).toEqual({ entityId: 'incident-1', targetStatusId: 'status-104', applyTransitionActions: actions });
    expect(apply).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    act(() => commit.mock.calls[0][0].onCompleted({ setWorkflowStatus: { success: true, executionStatus: 'completed' } }, null));
    expect(notifications.notifySuccess).toHaveBeenCalledWith('Status updated');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('keeps the dialog open and permits retry after a business failure', async () => {
    const { user } = await openDialog();
    await selectStatus(user);
    await user.click(screen.getByRole('button', { name: 'Apply actions' }));
    act(() => commit.mock.calls[0][0].onCompleted({ setWorkflowStatus: { success: false, reason: 'Status is no longer mapped' } }, null));
    expect(notifications.notifyError).toHaveBeenCalledWith('Status is no longer mapped');
    expect(screen.getByRole('dialog')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Apply actions' }));
    expect(commit).toHaveBeenCalledTimes(2);
  });

  it('releases submission after a transport failure through the API mutation handler', async () => {
    const { user } = await openDialog();
    await selectStatus(user);
    await user.click(screen.getByRole('button', { name: 'Apply actions' }));
    act(() => commit.mock.calls[0][0].onError(new Error('Network unavailable')));
    expect(notifications.notifyRelayError).toHaveBeenCalledOnce();
    expect(screen.getByRole('button', { name: 'Apply actions' })).toBeEnabled();
  });

  it('reports queued work without claiming the status is updated and blocks further bypass', async () => {
    const { user, rerender } = await openDialog();
    await selectStatus(user);
    await user.click(screen.getByRole('button', { name: 'Apply actions' }));
    act(() => commit.mock.calls[0][0].onCompleted({ setWorkflowStatus: { success: true, executionStatus: 'pending' } }, null));
    expect(notifications.notifySuccess).not.toHaveBeenCalledWith('Status updated');
    expect(notifications.notifySuccess).toHaveBeenCalledWith('Transition started in background');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(screen.getByRole('combobox')).toBeDisabled();
    rerender(<WorkflowBypassStatus data={entity('pending')} entityType="Incident" />);
    rerender(<WorkflowBypassStatus data={entity()} entityType="Incident" />);
    expect(screen.getByRole('combobox')).toBeEnabled();
  });
});
