import { screen, waitFor } from '@testing-library/react';
import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { CommentMode } from '../../settings/sub_types/workflow/utils';
import type { WorkflowStatus_data$key } from './__generated__/WorkflowStatus_data.graphql';
import type { WorkflowStatusStixDomainObject_data$key } from './__generated__/WorkflowStatusStixDomainObject_data.graphql';
import WorkflowStatus, { WorkflowStatusForEntity } from './WorkflowStatus';
import WorkflowTransitions, { WorkflowTransitionsForEntity } from './WorkflowTransitions';

const withEntitiesWorkflowFlag = (enable: boolean) => createMockUserContext({
  settings: { platform_feature_flags: enable ? [{ id: 'ENTITIES_WORKFLOW', enable: true }] : [] },
});

// ---------------------------------------------------------------------------
// Relay mocks
// ---------------------------------------------------------------------------
const mockCommit = vi.fn();

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    createFragmentContainer: (component: React.ComponentType) => component,
    useFragment: (_fragment: unknown, data: unknown) => data,
    useMutation: () => [mockCommit, false] as const,
  };
});

vi.mock('../../drafts/useSwitchDraft', () => ({
  default: () => ({ exitDraft: vi.fn() }),
}));

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => vi.fn() };
});

vi.mock('../../../../utils/hooks/useGranted', () => ({
  default: () => false,
  isBypassUser: () => false,
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

  it('renders for DraftWorkspace regardless of the ENTITIES_WORKFLOW flag (default entityType)', () => {
    const { container } = testRender(
      <WorkflowStatus data={makeDraft()} />,
      { userContext: withEntitiesWorkflowFlag(false) },
    );
    expect(container.firstChild).not.toBeNull();
  });

  it('renders null for a non-DraftWorkspace entityType when the ENTITIES_WORKFLOW flag is off', () => {
    const { container } = testRender(
      <WorkflowStatus data={makeDraft()} entityType="Incident" />,
      { userContext: withEntitiesWorkflowFlag(false) },
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders for a non-DraftWorkspace entityType when the ENTITIES_WORKFLOW flag is on', () => {
    const { container } = testRender(
      <WorkflowStatus data={makeDraft()} entityType="Incident" />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    expect(container.firstChild).not.toBeNull();
  });

  it('does not render a comment icon when lastHistoryEntry has no comment', () => {
    testRender(<WorkflowStatus data={makeDraft()} />);
    expect(document.querySelector('[data-testid="CommentOutlinedIcon"]')).toBeNull();
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

  it('does not render a closing-reason icon when lastHistoryEntry has no closing_reason', () => {
    testRender(<WorkflowStatus data={makeDraft()} />);
    expect(document.querySelector('[data-testid="AssignmentTurnedInOutlinedIcon"]')).toBeNull();
  });

  it('renders a closing-reason icon when lastHistoryEntry has a closing_reason', () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: { closing_reason: 'No longer relevant' },
        allowedTransitions: [],
      },
    });
    testRender(<WorkflowStatus data={draft} />);
    expect(document.querySelector('[data-testid="AssignmentTurnedInOutlinedIcon"]')).not.toBeNull();
  });

  it('opens a popover with the closing-reason text when the closing-reason icon is clicked', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: { closing_reason: 'No longer relevant' },
        allowedTransitions: [],
      },
    });
    const { user } = testRender(<WorkflowStatus data={draft} />);
    const iconButton = document.querySelector('[aria-label="View closing reason"]') as HTMLElement;
    await user.click(iconButton);
    expect(await screen.findByText('No longer relevant')).toBeDefined();
  });

  it('renders both the comment and closing-reason icons when both are present on the same history entry', () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: { comment: 'Looks good', closing_reason: 'No longer relevant' },
        allowedTransitions: [],
      },
    });
    testRender(<WorkflowStatus data={draft} />);
    expect(document.querySelector('[data-testid="CommentOutlinedIcon"]')).not.toBeNull();
    expect(document.querySelector('[data-testid="AssignmentTurnedInOutlinedIcon"]')).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// WorkflowTransitions
// ---------------------------------------------------------------------------
describe('WorkflowTransitions', () => {
  beforeEach(() => {
    mockCommit.mockReset();
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

  it('renders null for a non-DraftWorkspace entityType when the ENTITIES_WORKFLOW flag is off', () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve' })],
      },
    });
    const { container } = testRender(
      <WorkflowTransitions data={draft} entityType="Incident" />,
      { userContext: withEntitiesWorkflowFlag(false) },
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders transitions for a non-DraftWorkspace entityType when the ENTITIES_WORKFLOW flag is on', () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve' })],
      },
    });
    testRender(
      <WorkflowTransitions data={draft} entityType="Incident" />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    expect(screen.getByText('approve')).toBeDefined();
  });

  it('renders one button per transition when fewer than 3 transitions', () => {
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
    testRender(<WorkflowTransitions data={draft} />);
    expect(screen.getByText('approve')).toBeDefined();
    expect(screen.getByText('reject')).toBeDefined();
  });

  it('renders a dropdown menu when 3 or more transitions', async () => {
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

  it('opens the closing-reason dialog when the transition isClosingTransition is true', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: null, isClosingTransition: true })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    expect(await screen.findByLabelText(/Closing reason/)).toBeDefined();
  });

  it('does not open the closing-reason dialog when the transition isClosingTransition is false', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: null, isClosingTransition: false })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    expect(mockCommit).toHaveBeenCalledOnce();
  });

  it('calls commit with the trimmed closing reason on Apply', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: null, isClosingTransition: true })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    await user.type(await screen.findByLabelText(/Closing reason/), '  no longer needed  ');
    await user.click(screen.getByText('Apply'));
    await waitFor(() => {
      expect(mockCommit.mock.calls[0][0].variables.closingReason).toBe('no longer needed');
    });
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
    expect(screen.getByText('Apply').closest('button')).not.toBeDisabled();
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
    expect(screen.getByText('Apply').closest('button')).toBeDisabled();
  });

  it('enables Apply when a required comment is filled in', async () => {
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
    expect(screen.getByText('Apply').closest('button')).not.toBeDisabled();
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

  it('calls commit with trimmed comment on Apply', async () => {
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
    await user.click(screen.getByText('Apply'));
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
    await user.click(screen.getByText('Apply'));
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
    const confirmButton = await screen.findByText('Apply');
    // Click the Cancel button that is in the same dialog as the Apply button
    const cancelButton = confirmButton.closest('[role="dialog"]')
      ? confirmButton.closest('[role="dialog"]')!.querySelector('button[type="button"]')
      : screen.getAllByText('Cancel')[0];
    await user.click(cancelButton as HTMLElement);
    await waitFor(() => expect(screen.queryByText('Apply')).toBeNull());
    expect(mockCommit).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// WorkflowStatusForEntity / WorkflowTransitionsForEntity (generic StixDomainObject wrappers)
// ---------------------------------------------------------------------------
describe('WorkflowStatusForEntity', () => {
  const makeEntity = (overrides: Record<string, unknown> = {}) => ({
    id: 'entity-1',
    entity_type: 'Report',
    workflowInstance: {
      id: 'instance-1',
      currentState: 'in_review',
      currentStatus: makeStatus(),
      lastHistoryEntry: null,
      allowedTransitions: [],
    },
    ...overrides,
  } as unknown as WorkflowStatusStixDomainObject_data$key);

  it('renders null when workflowInstance is absent', () => {
    const { container } = testRender(
      <WorkflowStatusForEntity data={makeEntity({ workflowInstance: null })} entityType="Report" />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders null when the ENTITIES_WORKFLOW flag is off', () => {
    const { container } = testRender(
      <WorkflowStatusForEntity data={makeEntity()} entityType="Report" />,
      { userContext: withEntitiesWorkflowFlag(false) },
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders the status when the ENTITIES_WORKFLOW flag is on', () => {
    const { container } = testRender(
      <WorkflowStatusForEntity data={makeEntity()} entityType="Report" />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    expect(container.firstChild).not.toBeNull();
  });
});

describe('WorkflowTransitionsForEntity', () => {
  const makeEntity = (overrides: Record<string, unknown> = {}) => ({
    id: 'entity-1',
    entity_type: 'Report',
    workflowInstance: {
      id: 'instance-1',
      currentState: 'in_review',
      currentStatus: makeStatus(),
      lastHistoryEntry: null,
      allowedTransitions: [makeTransition({ event: 'approve' })],
    },
    ...overrides,
  } as unknown as WorkflowStatusStixDomainObject_data$key);

  it('renders null when the ENTITIES_WORKFLOW flag is off', () => {
    const { container } = testRender(
      <WorkflowTransitionsForEntity data={makeEntity()} entityType="Report" />,
      { userContext: withEntitiesWorkflowFlag(false) },
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders transition buttons when the ENTITIES_WORKFLOW flag is on', () => {
    testRender(
      <WorkflowTransitionsForEntity data={makeEntity()} entityType="Report" />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    expect(screen.getByText('approve')).toBeDefined();
  });

  it('calls commit when clicking a transition button', async () => {
    mockCommit.mockReset();
    const { user } = testRender(
      <WorkflowTransitionsForEntity data={makeEntity()} entityType="Report" />,
      { userContext: withEntitiesWorkflowFlag(true) },
    );
    await user.click(screen.getByText('approve'));
    expect(mockCommit).toHaveBeenCalledOnce();
  });
});
