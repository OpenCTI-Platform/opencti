import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import WorkflowStatus, { WorkflowClosingReasonForEntity, WorkflowStatusForEntity } from './WorkflowStatus';
import WorkflowTransitions, { WorkflowTransitionsForEntity } from './WorkflowTransitions';
import testRender from '../../../../utils/tests/test-render';
import type { WorkflowStatus_data$key } from './__generated__/WorkflowStatus_data.graphql';
import { CommentMode } from '../../settings/sub_types/workflow/utils';
import useHelper from '../../../../utils/hooks/useHelper';
import type { WorkflowStatusStixDomainObject_data$key } from './__generated__/WorkflowStatusStixDomainObject_data.graphql';

// ---------------------------------------------------------------------------
// Relay mocks
// ---------------------------------------------------------------------------
const mockCommit = vi.fn();
const { mockExitDraft, mockNavigate, permissions } = vi.hoisted(() => ({
  mockExitDraft: vi.fn(), mockNavigate: vi.fn(), permissions: { bypass: false, mandatoryFields: false },
}));

vi.mock('./WorkflowStatus.graphql', () => ({
  workflowStatusFragment: {},
  workflowStatusStixDomainObjectFragment: {},
  workflowStatusTriggerMutation: {},
  workflowStatusClearMutation: {},
  workflowStatusEntityQuery: {},
  workflowSetStatusMutation: {},
  workflowBypassStatusesQuery: {},
  COMMENT_MAX_LENGTH: 1000,
}));

vi.mock('../form/ObjectOrganizationField', async () => {
  const { useField } = await import('formik');
  return {
    default: ({ name, label, disabled }: { name: string; label: string; disabled?: boolean }) => {
      const [, , helpers] = useField(name);
      return <button type="button" disabled={disabled} onClick={() => helpers.setValue([{ value: `${name}-1`, label }])}>{label}</button>;
    },
  };
});

vi.mock('../form/OpenVocabField', () => ({
  default: ({ name, label, onChange }: { name: string; label: string; onChange: (name: string, value: string) => void }) => (
    <button type="button" onClick={() => onChange(name, 'false-positive')}>{label}</button>
  ),
}));

vi.mock('../../../../utils/hooks/useHelper', () => ({
  default: vi.fn(),
}));

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    createFragmentContainer: (component: React.ComponentType) => component,
    useFragment: (_fragment: unknown, data: unknown) => data,
    useMutation: () => [mockCommit, false] as const,
    fetchQuery: () => ({
      subscribe: ({ complete }: { complete: () => void }) => {
        complete();
        return { unsubscribe: vi.fn() };
      },
    }),
  };
});

vi.mock('../../drafts/useSwitchDraft', () => ({
  default: () => ({ exitDraft: mockExitDraft }),
}));

vi.mock('react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router')>();
  return { ...actual, useNavigate: () => mockNavigate };
});

vi.mock('../../../../utils/hooks/useGranted', () => ({
  default: () => permissions.mandatoryFields,
  isBypassUser: () => permissions.bypass,
  KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS: 'KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS',
}));

vi.mock('../../../../relay/environment', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../relay/environment')>();
  return {
    ...actual,
    MESSAGING$: {
      notifySuccess: vi.fn(),
      notifyError: vi.fn(),
    },
  };
});

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
const makeStatus = (color = '#ff0000', name = 'In review') => ({
  id: 'status-1',
  template: { name, color },
});

const makeDraft = (overrides: Record<string, unknown> = {}): WorkflowStatus_data$key => ({
  id: 'draft-1',
  entity_id: 'entity-1',
  processingCount: 0,
  workflowInstance: {
    id: 'instance-1',
    currentState: 'in_review',
    currentStatus: makeStatus(),
    lastHistoryEntry: null,
    allowedTransitions: [],
  },
  ...overrides,
} as unknown as WorkflowStatus_data$key);

const makeTransition = (overrides: Record<string, unknown> = {}) => ({
  event: 'approve',
  toState: 'approved',
  actions: [],
  comment: null,
  toStatus: makeStatus('#00ff00', 'Approved'),
  ...overrides,
});

beforeEach(() => {
  permissions.bypass = false;
  permissions.mandatoryFields = false;
  mockExitDraft.mockClear();
  mockNavigate.mockClear();
  vi.mocked(useHelper).mockReturnValue({ isFeatureEnable: () => false } as unknown as ReturnType<typeof useHelper>);
});

// ---------------------------------------------------------------------------
// WorkflowStatus (display component)
// ---------------------------------------------------------------------------
describe('WorkflowStatus', () => {
  it('renders null when workflowInstance is absent', () => {
    const { container } = testRender(
      <WorkflowStatus data={makeDraft({ workflowInstance: null })} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it('does not render a comment icon when lastHistoryEntry has no comment', () => {
    testRender(<WorkflowStatus data={makeDraft()} />);
    expect(document.querySelector('[data-testid="CommentOutlinedIcon"]')).toBeNull();
  });

  it('preserves the unknown badge for a draft workflow without a projected status', () => {
    testRender(<WorkflowStatus data={makeDraft({ workflowInstance: { currentStatus: null, lastHistoryEntry: null } })} />);
    expect(screen.getByText('Unknown')).toBeVisible();
  });

  it('renders a comment icon when lastHistoryEntry has a comment', () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: { comment: 'Looks good' },
        allowedTransitions: [],
      },
    });
    testRender(<WorkflowStatus data={draft} />);
    expect(document.querySelector('[data-testid="CommentOutlinedIcon"]')).not.toBeNull();
  });

  it('opens a popover with the comment text when the comment icon is clicked', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: { comment: 'Looks good' },
        allowedTransitions: [],
      },
    });
    const { user } = testRender(<WorkflowStatus data={draft} />);
    const iconButton = document.querySelector('[aria-label="View last comment"]') as HTMLElement;
    await user.click(iconButton);
    expect(await screen.findByText('Looks good')).toBeDefined();
  });

  it('closes the popover when clicking outside', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: { comment: 'Looks good' },
        allowedTransitions: [],
      },
    });
    const { user } = testRender(<WorkflowStatus data={draft} />);
    const iconButton = document.querySelector('[aria-label="View last comment"]') as HTMLElement;
    await user.click(iconButton);
    await screen.findByText('Looks good');
    // Press Escape to close (clicking document.body doesn't trigger MUI backdrop in jsdom)
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByText('Looks good')).toBeNull());
  });

  it('renders null for a non-DraftWorkspace entityType when the ENTITIES_WORKFLOW flag is off', () => {
    vi.mocked(useHelper).mockReturnValue({ isFeatureEnable: () => false } as unknown as ReturnType<typeof useHelper>);
    const { container } = testRender(
      <WorkflowStatus data={makeDraft()} entityType="Incident" />,
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders for a non-DraftWorkspace entityType when the ENTITIES_WORKFLOW flag is on', () => {
    vi.mocked(useHelper).mockReturnValue({ isFeatureEnable: () => true } as unknown as ReturnType<typeof useHelper>);
    testRender(<WorkflowStatus data={makeDraft()} entityType="Incident" />);
    expect(screen.getByText('In review')).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// WorkflowTransitions
// ---------------------------------------------------------------------------
describe('WorkflowStatusForEntity', () => {
  const entity = (workflowInstance: unknown = {
    currentStatus: makeStatus(), lastHistoryEntry: { comment: 'Entity comment' },
  }) => ({ id: 'incident-1', entity_type: 'Incident', workflowInstance }) as unknown as WorkflowStatusStixDomainObject_data$key;

  it('retains the legacy status while the flag is off', () => {
    testRender(<WorkflowStatusForEntity data={entity()} entityType="Incident" fallback={<span>Legacy status</span>} />);
    expect(screen.getByText('Legacy status')).toBeVisible();
    expect(screen.queryByText('In review')).toBeNull();
  });

  it('renders the generic status and comment when enabled', async () => {
    vi.mocked(useHelper).mockReturnValue({ isFeatureEnable: () => true } as unknown as ReturnType<typeof useHelper>);
    const { user } = testRender(<WorkflowStatusForEntity data={entity()} entityType="Incident" fallback={<span>Legacy status</span>} />);
    expect(screen.getByText('In review')).toBeVisible();
    expect(screen.queryByText('Legacy status')).toBeNull();
    await user.click(screen.getByRole('button', { name: 'View last comment' }));
    expect(await screen.findByText('Entity comment')).toBeVisible();
  });

  it.each([null, { currentStatus: null, lastHistoryEntry: null }])('retains the legacy status when workflow status is missing', (workflowInstance) => {
    vi.mocked(useHelper).mockReturnValue({ isFeatureEnable: () => true } as unknown as ReturnType<typeof useHelper>);
    testRender(<WorkflowStatusForEntity data={entity(workflowInstance)} entityType="Incident" fallback={<span>Legacy status</span>} />);
    expect(screen.getByText('Legacy status')).toBeVisible();
  });
});

describe('WorkflowTransitions', () => {
  beforeEach(() => {
    mockCommit.mockReset();
  });

  const transitionDraft = (transition = makeTransition(), overrides: Record<string, unknown> = {}) => makeDraft({
    workflowInstance: {
      id: 'instance-1', currentState: 'in_review', currentStatus: makeStatus(), lastHistoryEntry: null,
      allowedTransitions: [transition], pendingStatus: null, pendingTransition: null,
      ...overrides,
    },
    processingCount: 2,
  });

  it('shows all inputs and processing warnings in one form and submits once', async () => {
    const draft = transitionDraft(makeTransition({
      actions: ['validateDraft'], comment: CommentMode.required,
      requiresShareOrganizationInput: true, requiresUnshareOrganizationInput: true,
    }));
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByRole('button', { name: 'approve' }));
    expect(screen.getAllByRole('dialog')).toHaveLength(1);
    expect(screen.getByText('Ongoing processes')).toBeVisible();
    const submit = screen.getByRole('button', { name: 'Approve' });
    expect(submit).toBeDisabled();
    await user.type(screen.getByLabelText(/Comment/), '  Ready  ');
    const [shareOrganizations, unshareOrganizations] = screen.getAllByRole('button', { name: 'Organizations' });
    await user.click(shareOrganizations);
    await user.click(unshareOrganizations);
    await waitFor(() => expect(submit).toBeEnabled());
    await user.click(submit);
    await waitFor(() => expect(mockCommit).toHaveBeenCalledOnce());
    expect(mockCommit.mock.calls[0][0].variables).toEqual({
      entityId: 'draft-1', eventName: 'approve', comment: 'Ready',
      runtimeParams: { shareOrganizationIds: ['shareOrganizations-1'], unshareOrganizationIds: ['unshareOrganizations-1'] },
    });
    expect(submit).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
  });

  it('allows bypassing required comments but still enforces the length limit', async () => {
    permissions.mandatoryFields = true;
    const { user } = testRender(<WorkflowTransitions data={transitionDraft(makeTransition({ comment: CommentMode.required }))} />);
    await user.click(screen.getByRole('button', { name: 'approve' }));
    expect(screen.getByRole('button', { name: 'Confirm' })).not.toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Comment/), { target: { value: 'x'.repeat(1001) } });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Confirm' })).toBeDisabled());
    expect(mockCommit).not.toHaveBeenCalled();
  });

  it('does not expose Clear to users without bypass permission after an async error', () => {
    testRender(<WorkflowTransitions data={transitionDraft(makeTransition(), { pendingStatus: 'error' })} />);
    expect(screen.getByText('Transition failed')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Clear' })).toBeNull();
  });

  it('exposes Clear to bypass users after an async error', () => {
    permissions.bypass = true;
    testRender(<WorkflowTransitions data={transitionDraft(makeTransition(), { pendingStatus: 'error' })} />);
    expect(screen.getByRole('button', { name: 'Clear' })).toBeVisible();
  });

  it('does not offer transitions while pending details are unavailable', () => {
    testRender(<WorkflowTransitions data={transitionDraft(makeTransition(), { pendingStatus: 'pending' })} />);
    expect(screen.queryByRole('button', { name: 'approve' })).toBeNull();
  });

  it.each(['error', null])('does not navigate when pending validation becomes %s without reaching its target', (pendingStatus) => {
    const pendingTransition = { event: 'approve', toState: 'approved', syncActions: [{ type: 'validateDraft' }], asyncActions: [] };
    const { rerender } = testRender(<WorkflowTransitions data={transitionDraft(makeTransition(), { pendingStatus: 'pending', pendingTransition })} />);
    rerender(<WorkflowTransitions data={transitionDraft(makeTransition(), { pendingStatus })} />);
    expect(mockExitDraft).not.toHaveBeenCalled();
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('exits the draft only after pending validation reaches the target state', () => {
    const pendingTransition = { event: 'approve', toState: 'approved', syncActions: [{ type: 'validateDraft' }], asyncActions: [] };
    const { rerender } = testRender(<WorkflowTransitions data={transitionDraft(makeTransition(), { pendingStatus: 'pending', pendingTransition })} />);
    rerender(<WorkflowTransitions data={transitionDraft(makeTransition(), { currentState: 'approved' })} />);
    expect(mockExitDraft).toHaveBeenCalledOnce();
  });

  it('gates the generic wrapper and never runs draft navigation', async () => {
    const entity = { ...transitionDraft(makeTransition({ actions: ['validateDraft'] })), currentUserAccessRight: 'edit' } as unknown as WorkflowStatusStixDomainObject_data$key;
    const { rerender, user, container } = testRender(<WorkflowTransitionsForEntity data={entity} entityType="Incident" />);
    expect(container.firstChild).toBeNull();
    vi.mocked(useHelper).mockReturnValue({ isFeatureEnable: () => true } as unknown as ReturnType<typeof useHelper>);
    rerender(<WorkflowTransitionsForEntity data={entity} entityType="Incident" />);
    await user.click(screen.getByRole('button', { name: 'approve' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    act(() => mockCommit.mock.calls[0][0].onCompleted({ triggerWorkflowEvent: { success: true, executionStatus: 'completed' } }));
    expect(mockExitDraft).not.toHaveBeenCalled();
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('renders null when workflowInstance is absent', () => {
    const { container } = testRender(
      <WorkflowTransitions data={makeDraft({ workflowInstance: null })} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders null when allowedTransitions is empty', () => {
    const { container } = testRender(
      <WorkflowTransitions data={makeDraft()} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders a single button when there is one transition', () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve' })],
      },
    });
    testRender(<WorkflowTransitions data={draft} />);
    expect(screen.getByRole('button', { name: 'approve' })).toBeDefined();
    expect(screen.queryByRole('button', { name: 'Next status' })).toBeNull();
  });

  it('renders a dropdown menu when there are two transitions', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [
          makeTransition({ event: 'approve' }),
          makeTransition({ event: 'reject' }),
        ],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByRole('button', { name: 'Next status' }));
    expect(screen.getAllByRole('menuitem')).toHaveLength(2);
  });

  it('renders a dropdown menu when there are three or more transitions', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [
          makeTransition({ event: 'approve' }),
          makeTransition({ event: 'reject' }),
          makeTransition({ event: 'escalate' }),
        ],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('Next status'));
    expect(await screen.findByText('approve')).toBeDefined();
    expect(await screen.findByText('reject')).toBeDefined();
    expect(await screen.findByText('escalate')).toBeDefined();
  });

  it('calls commit directly when transition has no comment config', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: null })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    expect(mockCommit).toHaveBeenCalledOnce();
  });

  it('opens optional comment dialog when transition has comment: "allowed"', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: CommentMode.allowed })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    expect(await screen.findByText('You can optionally add a comment before changing the status.')).toBeDefined();
    expect(screen.getByText('Confirm').closest('button')).not.toBeDisabled();
  });

  it('opens required comment dialog when transition has comment: "required"', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: CommentMode.required })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    expect(await screen.findByText('A comment is required before changing the status.')).toBeDefined();
    expect(screen.getByText('Confirm').closest('button')).toBeDisabled();
  });

  it('enables Confirm when a required comment is filled in', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: CommentMode.required })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    await user.type(await screen.findByLabelText(/Comment/), 'My mandatory comment');
    expect(screen.getByText('Confirm').closest('button')).not.toBeDisabled();
  });

  it('displays the character counter (0 / 1000) on dialog open', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: CommentMode.allowed })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    expect(await screen.findByText('0 / 1000')).toBeDefined();
  });

  it('updates the character counter as the user types', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: CommentMode.allowed })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    await user.type(await screen.findByLabelText(/Comment/), 'Hello');
    expect(screen.getByText('5 / 1000')).toBeDefined();
  });

  it('calls commit with trimmed comment on Confirm', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: CommentMode.allowed })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    await user.type(await screen.findByLabelText(/Comment/), '  my comment  ');
    await user.click(screen.getByText('Confirm'));
    await waitFor(() => {
      expect(mockCommit).toHaveBeenCalledOnce();
      expect(mockCommit.mock.calls[0][0].variables.comment).toBe('my comment');
    });
  });

  it('calls commit with comment: null when no comment is entered on an optional dialog', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: CommentMode.allowed })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    await screen.findByLabelText(/Comment/);
    await user.click(screen.getByText('Confirm'));
    await waitFor(() => {
      expect(mockCommit).toHaveBeenCalledOnce();
      expect(mockCommit.mock.calls[0][0].variables.comment).toBeUndefined();
    });
  });

  it('closes the comment dialog on Cancel without calling commit', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: CommentMode.allowed })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    const confirmButton = await screen.findByText('Confirm');
    // Click the Cancel button that is in the same dialog as the Confirm button
    const cancelButton = confirmButton.closest('[role="dialog"]')
      ? confirmButton.closest('[role="dialog"]')!.querySelector('button[type="button"]')
      : screen.getAllByText('Cancel')[0];
    await user.click(cancelButton as HTMLElement);
    await waitFor(() => expect(screen.queryByText('Confirm')).toBeNull());
    expect(mockCommit).not.toHaveBeenCalled();
  });

  it('renders null for a non-DraftWorkspace entityType when the ENTITIES_WORKFLOW flag is off', () => {
    vi.mocked(useHelper).mockReturnValue({ isFeatureEnable: () => false } as unknown as ReturnType<typeof useHelper>);
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve' })],
      },
    });
    const { container } = testRender(<WorkflowTransitions data={draft} entityType="Incident" />);
    expect(container.firstChild).toBeNull();
  });

  it('renders for a non-DraftWorkspace entityType when the ENTITIES_WORKFLOW flag is on', () => {
    vi.mocked(useHelper).mockReturnValue({ isFeatureEnable: () => true } as unknown as ReturnType<typeof useHelper>);
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve' })],
      },
    });
    testRender(<WorkflowTransitions data={draft} entityType="Incident" />);
    expect(screen.getByText('approve')).not.toBeNull();
  });
});

describe('Workflow closing reason', () => {
  beforeEach(() => {
    mockCommit.mockClear();
  });

  it('requires a closing reason before confirming and submits it', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'close', closingReason: CommentMode.required })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('close'));
    expect(await screen.findByText('A closing reason is required before changing the status.')).toBeDefined();
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeDisabled();

    await user.click(screen.getByRole('button', { name: 'Closing reason' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Confirm' })).not.toBeDisabled());
    await user.click(screen.getByRole('button', { name: 'Confirm' }));

    expect(mockCommit).toHaveBeenCalledTimes(1);
    expect(mockCommit.mock.calls[0][0].variables).toMatchObject({ eventName: 'close', closingReason: 'false-positive' });
  });

  it('displays the closing reason of an entity when the workflow UI is enabled', () => {
    vi.mocked(useHelper).mockReturnValue({ isFeatureEnable: () => true } as unknown as ReturnType<typeof useHelper>);
    const entity = { x_opencti_closing_reason: 'duplicate' } as unknown as WorkflowStatusStixDomainObject_data$key;
    testRender(<WorkflowClosingReasonForEntity data={entity} entityType="Case-Incident" />);
    expect(screen.getByText('Closing reason')).toBeVisible();
    expect(screen.getByText('duplicate')).toBeVisible();
  });

  it('hides the closing reason when the workflow UI is disabled', () => {
    const entity = { x_opencti_closing_reason: 'duplicate' } as unknown as WorkflowStatusStixDomainObject_data$key;
    testRender(<WorkflowClosingReasonForEntity data={entity} entityType="Case-Incident" />);
    expect(screen.queryByText('duplicate')).toBeNull();
  });
});
