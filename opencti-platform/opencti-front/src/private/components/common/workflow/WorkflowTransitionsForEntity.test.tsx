import React, { Suspense } from 'react';
import { act, fireEvent, screen, within } from '@testing-library/react';
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

vi.mock('../form/OpenVocabField', () => ({ default: () => null }));
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
  allowedTransitions: [{ event: 'approve', toState: 'B', actions: [], comment: null, closingReason: null, requiresShareOrganizationInput: false, requiresUnshareOrganizationInput: false, requestAccessOutcome: null, toStatus: status('B') }],
  blockedTransitions: [] as BlockedTransitions,
});

type BlockedTransitions = NonNullable<WorkflowStatusStixDomainObject_data$data['workflowInstance']>['blockedTransitions'];
const assigneeCondition = { mode: 'and', filters: [{ key: ['objectAssignee'], values: ['@me'], operator: 'eq', mode: 'or' }], filterGroups: [] };
const blockedAnswer = { event: 'answer', toState: 'C', blockingConditions: JSON.stringify(assigneeCondition), toStatus: status('C') };

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
  allowedTransitions: NonNullable<WorkflowStatusStixDomainObject_data$data['workflowInstance']>['allowedTransitions'] = instance(null).allowedTransitions,
  draftContext: { id: string; name: string } | null = null, blockedTransitions: BlockedTransitions = []) => {
  vi.useFakeTimers();
  const rendered = testRender(<Suspense><Harness /></Suspense>, {
    userContext: createMockUserContext({
      me: { capabilities: [{ name: capability }], capabilitiesInDraft: [], draftContext },
      settings: { platform_feature_flags: enabled ? [{ id: 'ENTITIES_WORKFLOW', enable: true }] : [] },
    }),
  });
  await act(async () => rendered.relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
    Report: () => ({ id: 'entity-1', currentUserAccessRight: access, status: status('A'), workflowInstance: { ...instance(pendingStatus), allowedTransitions, blockedTransitions } }),
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

describe('WorkflowTransitionsForEntity in a draft', () => {
  it('shows the status but no transition, bypass or clear control', async () => {
    await setup('error', true, 'admin', 'BYPASS', instance(null).allowedTransitions, { id: 'draft-1', name: 'Draft' });

    expect(screen.getByText('A')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'approve' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Clear' })).not.toBeInTheDocument();
    expect(screen.queryByTestId('workflow-transitions-error')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Change status')).not.toBeInTheDocument();
  });
});

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

  // A closing reason is only asked on the way into a final state: the one stored on the entity is not carried over
  it('does not pre-fill the closing reason with the current one', async () => {
    const rendered = testRender(<Suspense><Harness /></Suspense>, {
      userContext: createMockUserContext({
        me: { capabilities: [{ name: 'KNOWLEDGE_KNUPDATE' }], capabilitiesInDraft: [] },
        settings: { platform_feature_flags: [{ id: 'ENTITIES_WORKFLOW', enable: true }] },
      }),
    });
    const transition = { ...instance(null).allowedTransitions[0], closingReason: 'allowed' };
    await act(async () => rendered.relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      Report: () => ({
        id: 'entity-1', currentUserAccessRight: 'edit', status: status('A'), x_opencti_closing_reason: 'duplicate',
        workflowInstance: { ...instance(null), allowedTransitions: [transition] },
      }),
    })));
    await rendered.user.click(screen.getByRole('button', { name: 'approve' }));
    await rendered.user.click(await screen.findByRole('button', { name: 'Confirm' }));
    const mutation = rendered.relayEnv.mock.getAllOperations().find((operation) => operation.request.node.params.name === 'WorkflowStatusTriggerMutation');
    expect(mutation?.request.variables).toMatchObject({ eventName: 'approve' });
    expect(mutation?.request.variables.closingReason).toBeNull();
  });

  // A condition such as "assignee is @me" depends on these fields, and our own edits never come back through the subscription
  it.each(['objectAssignee', 'objectParticipant'])('refetches the allowed transitions when %s changes in Relay', async (field) => {
    const { relayEnv } = await setup(null);
    expect(screen.getByRole('button', { name: 'approve' })).toBeVisible();
    act(() => relayEnv.commitUpdate((store) => {
      const user = store.create('user-1', 'User');
      user.setValue('user-1', 'id');
      store.get('entity-1')?.setLinkedRecords([user], field);
    }));
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.node.params.name).toBe('WorkflowStatusEntityQuery');
    const transitions = instance(null).allowedTransitions;
    await act(async () => relayEnv.mock.resolve(operation, {
      data: { stixDomainObject: { __typename: 'Report', id: 'entity-1', entity_type: 'Report', currentUserAccessRight: 'edit', status: status('A'), workflowInstance: {
        ...instance(null), allowedTransitions: [...transitions, { ...transitions[0], event: 'answer' }],
      } } },
    }));
    expect(screen.getByRole('button', { name: 'Next status' })).toBeVisible();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  // Labels, markings, confidence... can all flip a knowledge condition: the modification date moves on every edit
  it('refetches the allowed transitions when the entity is modified', async () => {
    const { relayEnv } = await setup(null);
    act(() => relayEnv.commitUpdate((store) => {
      store.get('entity-1')?.setValue('2026-11-16T10:00:00.000Z', 'updated_at');
    }));
    expect(relayEnv.mock.getMostRecentOperation().request.node.params.name).toBe('WorkflowStatusEntityQuery');
  });

  it('does not refetch the allowed transitions when another field changes', async () => {
    const { relayEnv } = await setup(null);
    act(() => relayEnv.commitUpdate((store) => {
      store.get('entity-1')?.setValue('Renamed', 'name');
    }));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
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

describe('WorkflowTransitionsForEntity blocked transitions', () => {
  it('shows a blocked transition as a disabled menu item', async () => {
    const { relayEnv, user } = await setup(null, true, 'edit', 'KNOWLEDGE_KNUPDATE', instance(null).allowedTransitions, null, [blockedAnswer]);
    vi.useRealTimers();
    await user.click(screen.getByRole('button', { name: 'Next status' }));
    expect(screen.getAllByRole('menuitem')).toHaveLength(2);
    const blocked = screen.getByRole('menuitem', { name: 'answer' });
    expect(blocked).toHaveAttribute('aria-disabled', 'true');
    fireEvent.click(blocked);
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('shows the blocked reason on hover', async () => {
    const { user } = await setup(null, true, 'edit', 'KNOWLEDGE_KNUPDATE', instance(null).allowedTransitions, null, [blockedAnswer]);
    vi.useRealTimers();
    await user.click(screen.getByRole('button', { name: 'Next status' }));
    await user.hover(screen.getByTestId('workflow-blocked-transition-answer'));
    expect((await screen.findAllByText('Requires'))[0]).toBeInTheDocument();
  });

  it('renders a disabled button when the only transition is blocked', async () => {
    await setup(null, true, 'edit', 'KNOWLEDGE_KNUPDATE', [], null, [blockedAnswer]);
    const blocked = screen.getByRole('button', { name: 'answer' });
    expect(blocked).toBeDisabled();
    // A lock tells a blocked action apart from the status chip next to it
    expect(within(blocked).getByTestId('LockOutlinedIcon')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Next status' })).toBeNull();
  });
});
