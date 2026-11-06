import React from 'react';
import { screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import ProcessingStatusOverview, { RequestAccessTransitions } from './ProcessingStatusOverview';
import type { CaseRfi_caseRfi$data } from './__generated__/CaseRfi_caseRfi.graphql';

vi.mock('react-relay', async (importOriginal) => ({
  ...await importOriginal<typeof import('react-relay')>(),
  useFragment: (_fragment: unknown, data: unknown) => data,
}));
vi.mock('../../drafts/useSwitchDraft', () => ({ default: () => ({ exitDraft: vi.fn() }) }));

const status = (name: string, color = '#888888') => ({ id: `status-${name}`, order: 1, template: { name, color } });
const transition = (event: string, name: string, color: string) => ({
  event, toState: name, actions: [], comment: null, requiresShareOrganizationInput: false, requiresUnshareOrganizationInput: false, toStatus: status(name, color),
});
const decisionTransitions = [
  transition('Accept', 'Approved', '#00ff00'),
  transition('Reject', 'Declined', '#ff0000'),
  transition('Escalate', 'Escalated', '#0000ff'),
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
    configuration: {
      approved_status: { id: 'status-Approved', template: { color: '#00ff00' } },
      declined_status: { id: 'status-Declined', template: { color: '#ff0000' } },
    },
  },
  workflowInstance: workflowDriven ? {
    id: 'instance-1', scope: 'REQUEST_ACCESS', currentState: 'New', currentStatus: status('New'), lastHistoryEntry: null,
    pendingStatus: null, pendingError: null, pendingTransition: null, allowedTransitions: transitions,
  } : null,
}) as unknown as CaseRfi_caseRfi$data;

const userContext = (capabilities = ['KNOWLEDGE_KNUPDATE', 'KNOWLEDGE_KNUPDATE_KNORGARESTRICT']) => createMockUserContext({
  me: { id: 'user-1', capabilities: capabilities.map((name) => ({ name })), capabilitiesInDraft: [] },
  settings: { platform_feature_flags: [{ id: 'ENTITIES_WORKFLOW', enable: true }] },
});

const renderTransitions = (rfi = makeRfi(), capabilities?: string[]) => testRender(<RequestAccessTransitions data={rfi} />, { userContext: userContext(capabilities) });

describe('ProcessingStatusOverview', () => {
  it('renders one button per allowed transition coloured by target status', () => {
    renderTransitions();
    expect(screen.queryByRole('button', { name: 'Next status' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Accept' })).toHaveStyle({ color: '#00ff00' });
    expect(screen.getByRole('button', { name: 'Reject' })).toHaveStyle({ color: '#ff0000' });
    expect(screen.getByRole('button', { name: 'Escalate' })).toHaveStyle({ color: '#0000ff' });
  });

  it('no buttons in Approved or Declined', () => {
    renderTransitions(makeRfi({ transitions: [] }));
    expect(screen.queryAllByRole('button')).toHaveLength(0);
  });

  it('buttons disabled with tooltip when the user cannot act', async () => {
    const { user } = renderTransitions(makeRfi({ isUserCanAction: false }));
    expect(screen.getByRole('button', { name: 'Accept' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Reject' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Escalate' })).toBeEnabled();
    await user.hover(screen.getByRole('button', { name: 'Accept' }).parentElement as HTMLElement);
    expect(await screen.findByRole('tooltip')).toHaveTextContent('You need to be able to edit the RFI and share knowledge');
  });

  it('Accept dialog says what will be shared and with whom', async () => {
    const { user, relayEnv } = renderTransitions();
    await user.click(screen.getByRole('button', { name: 'Reject' }));
    expect(within(screen.getByRole('dialog')).getByText('The applicant will be notified.')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    await user.click(screen.getByRole('button', { name: 'Accept' }));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText('This will share 2 requested entities with ACME and notify the applicant.')).toBeVisible();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    await user.click(within(dialog).getByRole('button', { name: 'Confirm' }));
    expect(relayEnv.mock.getMostRecentOperation().request.variables).toMatchObject({ entityId: 'rfi-1', eventName: 'Accept' });
  });

  it('names the single requested entity and falls back to the requesting organization', async () => {
    const rfi = { ...makeRfi({ entities: ['entity-1'] }), createdBy: null } as unknown as CaseRfi_caseRfi$data;
    const { user } = renderTransitions(rfi);
    await user.click(screen.getByRole('button', { name: 'Accept' }));
    expect(screen.getByText('This will share the requested entity with the requesting organization and notify the applicant.')).toBeVisible();
  });

  it('legacy RFI still shows Validate and Decline', () => {
    testRender(<ProcessingStatusOverview data={makeRfi({ workflowDriven: false })} />, { userContext: userContext() });
    expect(screen.getByRole('button', { name: 'Validate' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Decline' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Accept' })).toBeNull();
  });

  it('bypass control shown to BYPASS users', () => {
    renderTransitions(makeRfi(), ['BYPASS']);
    expect(screen.getByRole('combobox', { name: 'Status' })).toBeVisible();
    renderTransitions(makeRfi(), ['KNOWLEDGE_KNUPDATE']);
    expect(screen.getAllByRole('combobox', { name: 'Status' })).toHaveLength(1);
  });
});
