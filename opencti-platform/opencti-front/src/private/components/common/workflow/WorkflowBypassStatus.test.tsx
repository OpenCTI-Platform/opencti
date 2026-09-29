import React from 'react';
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import WorkflowBypassStatus from './WorkflowBypassStatus';
import testRender from '../../../../utils/tests/test-render';
import { COMMENT_MAX_LENGTH } from './WorkflowStatus.graphql';
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
vi.mock('../form/ObjectOrganizationField', async () => {
  const { useFormikContext } = await import('formik');
  return {
    default: ({ name, label, disabled }: { name: string; label: string; disabled: boolean }) => {
      const { values, setFieldValue } = useFormikContext<Record<string, { value: string; label: string }[]>>();
      return <label>{label}<input type="checkbox" disabled={disabled} checked={values[name].length > 0} onChange={(event) => setFieldValue(name, event.target.checked ? [{ value: `${name}-org`, label: 'Organization' }] : [])} /></label>;
    },
  };
});

const statuses = Array.from({ length: 105 }, (_, index) => ({
  status: { id: `status-${index}`, template: { name: `Status ${index}`, color: '#ff0000' } },
  requiresShareOrganizationInput: false,
  requiresUnshareOrganizationInput: false,
}));
const entity = (pendingStatus: string | null = null) => ({
  id: 'incident-1', entity_type: 'Incident', workflowInstance: { id: 'instance-1', pendingStatus },
}) as unknown as WorkflowStatusStixDomainObject_data$key;

const openDialog = async (onCompleted?: () => void) => {
  const rendered = testRender(<WorkflowBypassStatus data={entity()} entityType="Incident" onCompleted={onCompleted} />);
  await rendered.user.click(screen.getByRole('button', { name: 'Bypass status' }));
  await waitFor(() => expect(screen.getByRole('combobox')).toBeEnabled());
  return rendered;
};

const selectStatus = async (user: ReturnType<typeof testRender>['user'], name = 'Status 104') => {
  await user.click(screen.getByRole('combobox'));
  await user.click(await screen.findByRole('option', { name }));
};

beforeEach(() => {
  vi.clearAllMocks();
  permissions.bypass = true;
  permissions.enabled = true;
  fetchStatuses.mockResolvedValue({ workflowBypassStatuses: statuses });
});

describe('WorkflowBypassStatus', () => {
  it.each(['share', 'unshare', 'both'])('requires %s organizations and combines selected runtime inputs', async (mode) => {
    fetchStatuses.mockResolvedValue({ workflowBypassStatuses: [{
      ...statuses[104], requiresShareOrganizationInput: mode !== 'unshare', requiresUnshareOrganizationInput: mode !== 'share',
    }] });
    const { user } = await openDialog();
    expect(screen.queryByLabelText('Organizations to share with')).toBeNull();
    await selectStatus(user);
    const apply = screen.getByRole('button', { name: 'Apply' });
    expect(apply).toBeDisabled();
    fireEvent.submit(apply.closest('form')!);
    await act(async () => {});
    expect(commit).not.toHaveBeenCalled();
    if (mode !== 'unshare') await user.click(screen.getByLabelText('Organizations to share with'));
    if (mode === 'both') expect(apply).toBeDisabled();
    if (mode !== 'share') await user.click(screen.getByLabelText('Organizations to unshare from'));
    await user.click(apply);
    expect(commit.mock.calls[0][0].variables.runtimeParams).toEqual({
      ...(mode !== 'unshare' ? { shareOrganizationIds: ['shareOrganizations-org'] } : {}),
      ...(mode !== 'share' ? { unshareOrganizationIds: ['unshareOrganizations-org'] } : {}),
    });
  });

  it.each(['toggle', 'target'])('hides organization inputs and omits stale runtime values after changing %s', async (change) => {
    fetchStatuses.mockResolvedValue({ workflowBypassStatuses: [statuses[0], {
      ...statuses[104], requiresShareOrganizationInput: true, requiresUnshareOrganizationInput: true,
    }] });
    const { user } = await openDialog();
    await selectStatus(user);
    await user.click(screen.getByLabelText('Organizations to share with'));
    if (change === 'toggle') await user.click(screen.getByRole('switch'));
    else await selectStatus(user, 'Status 0');
    expect(screen.queryByLabelText('Organizations to share with')).toBeNull();
    expect(screen.queryByLabelText('Organizations to unshare from')).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Apply' }));
    expect(commit).toHaveBeenCalledOnce();
    expect(commit.mock.calls[0][0].variables.runtimeParams).toBeUndefined();
  });

  it.each(['completed', 'pending'])('requests a fresh entity after %s and releases controls when refresh settles', async (executionStatus) => {
    const onCompleted = vi.fn();
    const { user, rerender } = await openDialog(onCompleted);
    await selectStatus(user);
    await user.click(screen.getByRole('button', { name: 'Apply' }));
    act(() => commit.mock.calls[0][0].onCompleted({ setWorkflowStatus: { success: true, executionStatus } }, null));
    expect(onCompleted).toHaveBeenCalledOnce();
    rerender(<WorkflowBypassStatus data={entity()} entityType="Incident" onCompleted={onCompleted} refreshing />);
    expect(screen.getByRole('button', { name: 'Bypass status' })).toBeDisabled();
    rerender(<WorkflowBypassStatus data={entity()} entityType="Incident" onCompleted={onCompleted} refreshing={false} />);
    expect(screen.getByRole('button', { name: 'Bypass status' })).toBeEnabled();
  });

  it('does not refresh a rejected bypass', async () => {
    const onCompleted = vi.fn();
    const { user } = await openDialog(onCompleted);
    await selectStatus(user);
    await user.click(screen.getByRole('button', { name: 'Apply' }));
    act(() => commit.mock.calls[0][0].onCompleted({ setWorkflowStatus: { success: false, reason: 'Denied' } }, null));
    expect(onCompleted).not.toHaveBeenCalled();
  });

  it.each(['bypass', 'enabled'] as const)('hides the control and never queries when %s is false', (permission) => {
    permissions[permission] = false;
    testRender(<WorkflowBypassStatus data={entity()} entityType="Incident" />);
    expect(screen.queryByRole('button', { name: 'Bypass status' })).toBeNull();
    expect(fetchStatuses).not.toHaveBeenCalled();
  });

  it.each(['pending', 'error'])('disables bypass while the instance is %s', (pendingStatus) => {
    testRender(<WorkflowBypassStatus data={entity(pendingStatus)} entityType="Incident" />);
    expect(screen.getByRole('button', { name: 'Bypass status' })).toBeDisabled();
    expect(fetchStatuses).not.toHaveBeenCalled();
  });

  it('shows loading, then all published mapped choices in server order', async () => {
    let resolve!: (data: unknown) => void;
    fetchStatuses.mockReturnValue(new Promise((done) => {
      resolve = done;
    }));
    const { user } = testRender(<WorkflowBypassStatus data={entity()} entityType="Incident" />);
    await user.click(screen.getByRole('button', { name: 'Bypass status' }));
    expect(screen.getByRole('status')).toHaveTextContent('Loading');
    expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
    await act(async () => resolve({ workflowBypassStatuses: statuses }));
    expect(fetchStatuses).toHaveBeenCalledWith(expect.anything(), { entityId: 'incident-1' });
    await user.click(screen.getByRole('combobox'));
    expect(screen.getAllByRole('option').map((option) => option.textContent)).toEqual(statuses.map(({ status }) => status.template.name));
  });

  it('notifies query failures and supports retry', async () => {
    fetchStatuses.mockRejectedValueOnce(new Error('Unavailable'));
    const { user } = testRender(<WorkflowBypassStatus data={entity()} entityType="Incident" />);
    await user.click(screen.getByRole('button', { name: 'Bypass status' }));
    await user.click(await screen.findByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(screen.getByRole('combobox')).toBeEnabled());
    expect(notifications.notifyError).toHaveBeenCalledOnce();
    expect(fetchStatuses).toHaveBeenCalledTimes(2);
  });

  it('does not allow submission with no mapped target', async () => {
    fetchStatuses.mockResolvedValue({ workflowBypassStatuses: [] });
    const { user } = testRender(<WorkflowBypassStatus data={entity()} entityType="Incident" />);
    await user.click(screen.getByRole('button', { name: 'Bypass status' }));
    expect(await screen.findByText('No available status')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled();
  });

  it.each([true, false])('submits once with actions=%s and a trimmed comment', async (actions) => {
    const { user } = await openDialog();
    await selectStatus(user);
    await user.type(screen.getByLabelText('Comment'), '  Ready  ');
    if (!actions) await user.click(screen.getByRole('switch'));
    const apply = screen.getByRole('button', { name: 'Apply' });
    await user.dblClick(apply);
    expect(commit).toHaveBeenCalledOnce();
    expect(commit.mock.calls[0][0].variables).toEqual({ entityId: 'incident-1', targetStatusId: 'status-104', applyTransitionActions: actions, comment: 'Ready' });
    expect(apply).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    act(() => commit.mock.calls[0][0].onCompleted({ setWorkflowStatus: { success: true, executionStatus: 'completed' } }, null));
    expect(notifications.notifySuccess).toHaveBeenCalledWith('Status updated');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('retains inputs and permits retry after a business failure', async () => {
    const { user } = await openDialog();
    await selectStatus(user);
    await user.type(screen.getByLabelText('Comment'), 'Keep this');
    await user.click(screen.getByRole('button', { name: 'Apply' }));
    act(() => commit.mock.calls[0][0].onCompleted({ setWorkflowStatus: { success: false, reason: 'Status is no longer mapped' } }, null));
    expect(notifications.notifyError).toHaveBeenCalledWith('Status is no longer mapped');
    expect(screen.getByLabelText('Comment')).toHaveValue('Keep this');
    await user.click(screen.getByRole('button', { name: 'Apply' }));
    expect(commit).toHaveBeenCalledTimes(2);
  });

  it('releases submission after a transport failure through the API mutation handler', async () => {
    const { user } = await openDialog();
    await selectStatus(user);
    await user.click(screen.getByRole('button', { name: 'Apply' }));
    act(() => commit.mock.calls[0][0].onError(new Error('Network unavailable')));
    expect(notifications.notifyRelayError).toHaveBeenCalledOnce();
    expect(screen.getByRole('button', { name: 'Apply' })).toBeEnabled();
  });

  it('reports queued work without claiming the status is updated and blocks further bypass', async () => {
    const { user, rerender } = await openDialog();
    await selectStatus(user);
    await user.click(screen.getByRole('button', { name: 'Apply' }));
    act(() => commit.mock.calls[0][0].onCompleted({ setWorkflowStatus: { success: true, executionStatus: 'pending' } }, null));
    expect(notifications.notifySuccess).not.toHaveBeenCalledWith('Status updated');
    expect(notifications.notifySuccess).toHaveBeenCalledWith('Transition started in background');
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(screen.getByRole('button', { name: 'Bypass status' })).toBeDisabled();
    rerender(<WorkflowBypassStatus data={entity('pending')} entityType="Incident" />);
    rerender(<WorkflowBypassStatus data={entity()} entityType="Incident" />);
    expect(screen.getByRole('button', { name: 'Bypass status' })).toBeEnabled();
  });

  it('enforces COMMENT_MAX_LENGTH even for bypass users', async () => {
    const { user } = await openDialog();
    await selectStatus(user);
    const comment = screen.getByLabelText('Comment');
    expect(comment).toHaveAttribute('maxlength', String(COMMENT_MAX_LENGTH));
    fireEvent.change(comment, { target: { value: 'x'.repeat(COMMENT_MAX_LENGTH + 1) } });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled());
    expect(commit).not.toHaveBeenCalled();
  });
});
