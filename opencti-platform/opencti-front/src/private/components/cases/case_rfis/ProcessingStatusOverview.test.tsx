import React from 'react';
import { act, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import ProcessingStatusOverview from './ProcessingStatusOverview';
import type { CaseRfi_caseRfi$data } from './__generated__/CaseRfi_caseRfi.graphql';

vi.mock('react-relay', async (importOriginal) => ({
  ...await importOriginal<typeof import('react-relay')>(),
  useFragment: (_fragment: unknown, data: unknown) => data,
}));
vi.mock('../../drafts/useSwitchDraft', () => ({ default: () => ({ exitDraft: vi.fn() }) }));

const status = (name: string, color = '#888888') => ({ id: `status-${name}`, order: 1, template: { name, color } });
const transition = (event: string, name: string, color: string, requestAccessOutcome: string | null) => ({
  event, toState: name, actions: [], comment: null, requiresShareOrganizationInput: false, requiresUnshareOrganizationInput: false,
  requestAccessOutcome, toStatus: status(name, color),
});
const decisionTransitions = [
  transition('Accept', 'Approved', '#00ff00', 'APPROVED'),
  transition('Reject', 'Declined', '#ff0000', 'DECLINED'),
  transition('Escalate', 'Escalated', '#0000ff', null),
];

const makeRfi = ({ transitions = decisionTransitions, isUserCanAction = true, workflowDriven = true, entities = ['entity-1', 'entity-2'] } = {}) => ({
  id: 'rfi-1',
  entity_type: 'Case-Rfi',
  currentUserAccessRight: 'edit',
  status: status('New'),
  workflowEnabled: true,
  createdBy: { id: 'org-1', name: 'ACME', entity_type: 'Organization' },
  x_opencti_request_access: JSON.stringify({ entities, members: ['org-1'], status: 'NEW' }),
  requestAccessConfiguration: {
    isUserCanAction,
    // The configured statuses never decide which transitions are outcomes: Escalated is configured as approved on purpose
    configuration: {
      approved_status: { id: 'status-Escalated', template: { color: '#00ff00' } },
      declined_status: { id: 'status-Other', template: { color: '#ff0000' } },
    },
  },
  workflowInstance: workflowDriven ? {
    id: 'instance-1', scope: 'REQUEST_ACCESS', currentState: 'New', currentStatus: status('Under review'), lastHistoryEntry: null,
    pendingStatus: null, pendingError: null, pendingTransition: null, allowedTransitions: transitions,
  } : null,
}) as unknown as CaseRfi_caseRfi$data;

const userContext = (capabilities = ['KNOWLEDGE_KNUPDATE', 'KNOWLEDGE_KNUPDATE_KNORGARESTRICT'], enabled = true) => createMockUserContext({
  me: { id: 'user-1', capabilities: capabilities.map((name) => ({ name })), capabilitiesInDraft: [] },
  settings: { platform_feature_flags: enabled ? [{ id: 'ENTITIES_WORKFLOW', enable: true }] : [] },
});

const renderOverview = (rfi = makeRfi(), capabilities?: string[], enabled = true) => {
  return testRender(<ProcessingStatusOverview data={rfi} />, { userContext: userContext(capabilities, enabled) });
};

const confirmAccept = async (rendered: ReturnType<typeof renderOverview>) => {
  await rendered.user.click(screen.getByRole('button', { name: 'Accept' }));
  await rendered.user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirm' }));
  const operation = rendered.relayEnv.mock.getMostRecentOperation();
  expect(operation.request.variables).toMatchObject({ entityId: 'rfi-1', eventName: 'Accept' });
  return operation;
};

describe('ProcessingStatusOverview', () => {
  it('renders one button per allowed transition coloured by target status', () => {
    renderOverview();
    expect(screen.getByText('Processing status')).toBeVisible();
    expect(screen.getByText('Under review')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Next status' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Validate' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Accept' })).toHaveStyle({ color: '#00ff00' });
    expect(screen.getByRole('button', { name: 'Reject' })).toHaveStyle({ color: '#ff0000' });
    expect(screen.getByRole('button', { name: 'Escalate' })).toHaveStyle({ color: '#0000ff' });
  });

  it('no buttons in Approved or Declined', () => {
    renderOverview(makeRfi({ transitions: [] }));
    expect(screen.getByText('Under review')).toBeVisible();
    expect(screen.queryAllByRole('button')).toHaveLength(0);
  });

  it('buttons disabled with tooltip when the user cannot act', async () => {
    const { user } = renderOverview(makeRfi({ isUserCanAction: false }));
    expect(screen.getByRole('button', { name: 'Accept' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Reject' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Escalate' })).toBeEnabled();
    await user.hover(screen.getByRole('button', { name: 'Accept' }).parentElement as HTMLElement);
    expect(await screen.findByRole('tooltip')).toHaveTextContent('You need to be able to edit the RFI and share knowledge');
  });

  it('Accept dialog says what will be shared and with whom', async () => {
    const rendered = renderOverview();
    const { user, relayEnv } = rendered;
    await user.click(screen.getByRole('button', { name: 'Reject' }));
    expect(within(screen.getByRole('dialog')).getByText('The applicant will be notified.')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    const operation = await confirmAccept(rendered);
    expect(operation.request.node.params.name).toBe('WorkflowStatusTriggerMutation');
    expect(screen.getByText('This will share 2 requested entities with ACME and notify the applicant.')).toBeVisible();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
  });

  it('fires a transition that decides nothing without a confirmation dialog', async () => {
    const { user, relayEnv } = renderOverview();
    await user.click(screen.getByRole('button', { name: 'Escalate' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(relayEnv.mock.getMostRecentOperation().request.variables).toMatchObject({ entityId: 'rfi-1', eventName: 'Escalate' });
  });

  it('names the single requested entity and falls back to the requesting organization', async () => {
    const rfi = { ...makeRfi({ entities: ['entity-1'] }), createdBy: null } as unknown as CaseRfi_caseRfi$data;
    const { user } = renderOverview(rfi);
    await user.click(screen.getByRole('button', { name: 'Accept' }));
    expect(screen.getByText('This will share the requested entity with the requesting organization and notify the applicant.')).toBeVisible();
  });

  it.each([
    ['a business failure', 'resolve'],
    ['a GraphQL error', 'reject'],
  ])('refreshes the decision buttons after %s', async (_case, outcome) => {
    const rendered = renderOverview();
    const { relayEnv } = rendered;
    await confirmAccept(rendered);
    await act(async () => {
      if (outcome === 'reject') {
        relayEnv.mock.rejectMostRecentOperation(new Error('Already decided'));
      } else {
        relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
          WorkflowTriggerResult: () => ({ success: false, reason: 'Already decided', executionStatus: null, instance: null, entity: null }),
        }));
      }
    });
    const refresh = relayEnv.mock.getMostRecentOperation();
    expect(refresh.request.node.params.name).toBe('WorkflowStatusEntityQuery');
    expect(refresh.request.variables).toEqual({ id: 'rfi-1' });
  });

  it('legacy RFI still shows Validate and Decline', () => {
    renderOverview(makeRfi({ workflowDriven: false }));
    expect(screen.getByText('Processing status')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Validate' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Decline' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Accept' })).toBeNull();
  });

  it('keeps Validate and Decline with the flag off even for a workflow-driven RFI', () => {
    renderOverview(makeRfi(), undefined, false);
    expect(screen.getByRole('button', { name: 'Validate' })).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Accept' })).toBeNull();
  });

  it('bypass control shown to BYPASS users', () => {
    renderOverview(makeRfi(), ['BYPASS']);
    expect(screen.getByRole('combobox', { name: 'Status' })).toBeVisible();
    renderOverview(makeRfi(), ['KNOWLEDGE_KNUPDATE']);
    expect(screen.getAllByRole('combobox', { name: 'Status' })).toHaveLength(1);
  });
});
