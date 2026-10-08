import React, { Suspense } from 'react';
import { act, fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { useFragment, useLazyLoadQuery } from 'react-relay';
import { MockPayloadGenerator } from 'relay-test-utils';
import { WorkflowTransitionsForEntity } from './WorkflowTransitions';
import { WorkflowStatusForEntity } from './WorkflowStatus';
import reportQuery from '../../analyses/reports/__generated__/RootReportQuery.graphql';
import reportFragment from '../../analyses/reports/__generated__/Report_report.graphql';
import type { RootReportQuery } from '../../analyses/reports/__generated__/RootReportQuery.graphql';
import type { Report_report$key } from '../../analyses/reports/__generated__/Report_report.graphql';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { FIVE_SECONDS } from '../../../../utils/Time';
import type { WorkflowStatusStixDomainObject_data$data } from './__generated__/WorkflowStatusStixDomainObject_data.graphql';

vi.mock('../../drafts/useSwitchDraft', () => ({ default: () => ({ exitDraft: vi.fn() }) }));
vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../relay/environment')>(),
  fetchQuery: () => ({ toPromise: async () => ({ workflowBypassStatuses: [{ status: { id: 'status-B', order: 0, template: { name: 'B', color: '#00ff00' } }, onExit: [{ type: 'log', params: null }], onEnter: [], requiresShareOrganizationInput: false, requiresUnshareOrganizationInput: false }] }) }),
}));

const status = (name: string) => ({ id: `status-${name}`, order: 1, template: { id: `template-${name}`, name, color: '#00ff00' } });
const instance = (pendingStatus: string | null, name = 'A') => ({
  id: 'instance-1', currentState: name, currentStatus: status(name), lastHistoryEntry: null,
  pendingStatus, pendingError: pendingStatus === 'error' ? 'Action failed' : null,
  pendingTransition: pendingStatus === 'pending' ? { event: 'approve', toState: 'B', triggeredAt: null, syncActions: [], asyncActions: [] } : null,
  allowedTransitions: [{ event: 'approve', toState: 'B', actions: [], comment: null, closingReason: null, requiresShareOrganizationInput: false, requiresUnshareOrganizationInput: false, toStatus: status('B') }],
});

const Harness = () => {
  const query = useLazyLoadQuery<RootReportQuery>(reportQuery, { id: 'entity-1' });
  const report = useFragment<Report_report$key>(reportFragment, query.report);
  return report && (
    <>
      <span data-testid="legacy-status">{report.status?.template?.name}</span>
      <WorkflowStatusForEntity data={report} entityType="Report">
        <WorkflowTransitionsForEntity data={report} entityType="Report" />
      </WorkflowStatusForEntity>
    </>
  );
};

const setup = async (pendingStatus: string | null = 'pending', enabled = true, access = 'edit', capability = 'KNOWLEDGE_KNUPDATE',
  allowedTransitions: NonNullable<WorkflowStatusStixDomainObject_data$data['workflowInstance']>['allowedTransitions'] = instance(null).allowedTransitions) => {
  vi.useFakeTimers();
  const rendered = testRender(<Suspense><Harness /></Suspense>, {
    userContext: createMockUserContext({
      me: { capabilities: [{ name: capability }], capabilitiesInDraft: [] },
      settings: { platform_feature_flags: enabled ? [{ id: 'ENTITIES_WORKFLOW', enable: true }] : [] },
    }),
  });
  await act(async () => rendered.relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
    Report: () => ({ id: 'entity-1', currentUserAccessRight: access, status: status('A'), workflowInstance: { ...instance(pendingStatus), allowedTransitions } }),
  })));
  return rendered;
};

const resolveRefresh = async (relayEnv: ReturnType<typeof testRender>['relayEnv'], pendingStatus: string | null, name = 'A') => {
  const operation = relayEnv.mock.getMostRecentOperation();
  expect(operation.request.node.params.name).toBe('WorkflowStatusEntityQuery');
  expect(operation.request.variables).toEqual({ id: 'entity-1' });
  await act(async () => relayEnv.mock.resolve(operation, {
    data: { stixDomainObject: { __typename: 'Report', id: 'entity-1', entity_type: 'Report', currentUserAccessRight: 'edit', status: status(name), workflowInstance: instance(pendingStatus, name) } },
  }));
};

afterEach(() => vi.useRealTimers());

describe('WorkflowTransitionsForEntity refresh', () => {
  it.each([2, 3])('opens a menu for %s entity transitions without executing any of them', async (count) => {
    const transitions = instance(null).allowedTransitions;
    const { relayEnv, user } = await setup(null, true, 'edit', 'KNOWLEDGE_KNUPDATE', [
      transitions[0],
      { ...transitions[0], event: 'close', actions: ['log'] },
      ...(count === 3 ? [{ ...transitions[0], event: 'review', actions: ['log', 'updateAuthorizedMembers'] }] : []),
    ]);
    vi.useRealTimers();
    await user.click(screen.getByRole('button', { name: 'Next status' }));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(screen.getByRole('menuitem', { name: 'approve' })).toBeVisible();
    expect(screen.getAllByRole('menuitem')).toHaveLength(count);
    expect(screen.getByText('(+1 action required)')).toBeVisible();
    if (count === 3) expect(screen.getByText('(+2 actions required)')).toBeVisible();
    await user.click(screen.getByRole('menuitem', { name: /^close/ }));
    expect(relayEnv.mock.getMostRecentOperation().request.variables.eventName).toBe('close');
  });

  it('supports keyboard dismissal and selection of the first transition', async () => {
    const transition = instance(null).allowedTransitions[0];
    const { relayEnv, user } = await setup(null, true, 'edit', 'KNOWLEDGE_KNUPDATE', [transition, { ...transition, event: 'close' }]);
    vi.useRealTimers();
    const trigger = screen.getByRole('button', { name: 'Next status' });
    trigger.focus();
    await user.keyboard('{Enter}');
    expect(screen.getByRole('menu')).toBeVisible();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('menu')).toBeNull();
    expect(trigger).toHaveFocus();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    await user.keyboard('{Enter}{ArrowDown}{Home}{Enter}');
    expect(relayEnv.mock.getMostRecentOperation().request.variables.eventName).toBe('approve');
  });

  it('allows closing the bypass dialog after a hook failure updates the Relay instance', async () => {
    const { relayEnv, user } = await setup(null, true, 'edit', 'BYPASS');
    vi.useRealTimers();
    await user.click(screen.getByRole('combobox'));
    await user.click(await screen.findByRole('option', { name: /^1\s*B$/ }));
    await user.click(screen.getByRole('button', { name: 'Apply actions' }));
    await act(async () => relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      WorkflowTriggerResult: () => ({ success: false, reason: 'Hook failed', executionStatus: 'error', instance: instance('error'), entity: null }),
    })));
    expect(screen.getByRole('button', { name: 'Apply actions' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.getByRole('button', { name: 'Clear' })).toBeEnabled();
  });

  it.each(['completed', 'pending'])('refreshes projected status after a %s bypass through the shared owner', async (executionStatus) => {
    const { relayEnv, user } = await setup(null, true, 'edit', 'BYPASS');
    vi.useRealTimers();
    await user.click(screen.getByRole('combobox'));
    await user.click(await screen.findByRole('option', { name: /^1\s*B$/ }));
    await user.click(screen.getByRole('button', { name: 'Apply actions' }));
    await act(async () => relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      WorkflowTriggerResult: () => ({ success: true, reason: null, executionStatus, instance: instance(null), entity: null }),
    })));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
    expect(screen.getByRole('combobox')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'approve' })).toBeDisabled();
    await resolveRefresh(relayEnv, null, 'B');
    expect(screen.getByTestId('legacy-status')).toHaveTextContent('B');
    expect(screen.getByRole('combobox')).toBeEnabled();
    expect(screen.getByRole('button', { name: 'approve' })).toBeEnabled();
  });

  it.each([null, 'error'])('refreshes pending to %s in Relay and stops polling', async (pendingStatus) => {
    const { relayEnv } = await setup();
    act(() => vi.advanceTimersByTime(FIVE_SECONDS));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
    act(() => vi.advanceTimersByTime(FIVE_SECONDS));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
    await resolveRefresh(relayEnv, pendingStatus, pendingStatus === null ? 'B' : 'A');
    expect(screen.queryByRole('progressbar')).toBeNull();
    if (pendingStatus === 'error') expect(screen.getByText('Transition failed')).toBeVisible();
    else {
      expect(screen.getByRole('button', { name: 'approve' })).toBeEnabled();
      expect(screen.getByTestId('legacy-status')).toHaveTextContent('B');
      expect(relayEnv.getStore().getSource().get('entity-1')?.status).toEqual({ __ref: 'status-B' });
      expect(relayEnv.getStore().getSource().get('instance-1')?.currentState).toBe('B');
    }
    act(() => vi.advanceTimersByTime(FIVE_SECONDS * 2));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it.each(['completed', 'pending'])('refreshes after a successful %s mutation and holds controls until the query settles', async (executionStatus) => {
    const { relayEnv } = await setup(null);
    fireEvent.click(screen.getByRole('button', { name: 'approve' }));
    await act(async () => relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      WorkflowTriggerResult: () => ({ success: true, reason: null, executionStatus, instance: instance(null), entity: null }),
    })));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
    expect(screen.getByRole('button', { name: 'approve' })).toBeDisabled();
    await resolveRefresh(relayEnv, null, 'B');
    expect(screen.getByRole('button', { name: 'approve' })).toBeEnabled();
    expect(screen.getByTestId('legacy-status')).toHaveTextContent('B');
  });

  it('releases controls on refresh failure after a successful mutation', async () => {
    const { relayEnv } = await setup(null);
    fireEvent.click(screen.getByRole('button', { name: 'approve' }));
    await act(async () => relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      WorkflowTriggerResult: () => ({ success: true, executionStatus: 'completed', instance: instance(null), entity: null }),
    })));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
    await act(async () => relayEnv.mock.rejectMostRecentOperation(new Error('Unavailable')));
    expect(screen.getByRole('button', { name: 'approve' })).toBeEnabled();
    act(() => vi.advanceTimersByTime(FIVE_SECONDS * 2));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it.each([[false, 'edit'], [true, 'view']] as const)('never polls with enabled=%s and access=%s', async (enabled, access) => {
    const { relayEnv } = await setup('pending', enabled, access);
    act(() => vi.advanceTimersByTime(FIVE_SECONDS * 2));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(screen.queryByRole('progressbar')).toBeNull();
  });

  it('allows retrying a failed pending refresh', async () => {
    const { relayEnv } = await setup();
    act(() => vi.advanceTimersByTime(FIVE_SECONDS));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
    await act(async () => relayEnv.mock.rejectMostRecentOperation(new Error('Unavailable')));
    act(() => vi.advanceTimersByTime(FIVE_SECONDS * 2));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await resolveRefresh(relayEnv, null, 'B');
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();
    expect(screen.getByTestId('legacy-status')).toHaveTextContent('B');
  });

  it('cancels polling and the active refresh on unmount', async () => {
    const { relayEnv, unmount } = await setup();
    act(() => vi.advanceTimersByTime(FIVE_SECONDS));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
    unmount();
    act(() => vi.advanceTimersByTime(FIVE_SECONDS * 2));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });
});
