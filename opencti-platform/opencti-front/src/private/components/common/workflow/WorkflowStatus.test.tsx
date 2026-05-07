import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import WorkflowStatus, { WorkflowTransitions } from './WorkflowStatus';
import testRender from '../../../../utils/tests/test-render';
import type { WorkflowStatus_data$key } from './__generated__/WorkflowStatus_data.graphql';

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
  KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS: 'KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS',
}));

vi.mock('../../../../relay/environment', () => ({
  MESSAGING$: {
    notifySuccess: vi.fn(),
    notifyError: vi.fn(),
  },
}));

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

  it('does not render a comment icon when lastHistoryEntry has no comment', () => {
    testRender(<WorkflowStatus data={makeDraft()} />);
    expect(document.querySelector('[data-testid="ReviewsOutlinedIcon"]')).toBeNull();
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
    expect(document.querySelector('[data-testid="ReviewsOutlinedIcon"]')).not.toBeNull();
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

  it('opens optional comment dialog when transition has comment: "allowed"', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: 'allowed' })],
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
        allowedTransitions: [makeTransition({ event: 'approve', comment: 'required' })],
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
        allowedTransitions: [makeTransition({ event: 'approve', comment: 'required' })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    await user.type(await screen.findByLabelText('Comment'), 'My mandatory comment');
    expect(screen.getByText('Confirm').closest('button')).not.toBeDisabled();
  });

  it('displays the character counter (0 / 5000) on dialog open', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: 'allowed' })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    expect(await screen.findByText('0 / 5000')).toBeDefined();
  });

  it('updates the character counter as the user types', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: 'allowed' })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    await user.type(await screen.findByLabelText('Comment'), 'Hello');
    expect(screen.getByText('5 / 5000')).toBeDefined();
  });

  it('calls commit with trimmed comment on Confirm', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: 'allowed' })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    await user.type(await screen.findByLabelText('Comment'), '  my comment  ');
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
        allowedTransitions: [makeTransition({ event: 'approve', comment: 'allowed' })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    await screen.findByLabelText('Comment');
    await user.click(screen.getByText('Confirm'));
    await waitFor(() => {
      expect(mockCommit).toHaveBeenCalledOnce();
      expect(mockCommit.mock.calls[0][0].variables.comment).toBe(null);
    });
  });

  it('closes the comment dialog on Cancel without calling commit', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        allowedTransitions: [makeTransition({ event: 'approve', comment: 'allowed' })],
      },
    });
    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    await screen.findByText('Confirm');
    await user.click(screen.getByText('Cancel'));
    await waitFor(() => expect(screen.queryByText('Confirm')).toBeNull());
    expect(mockCommit).not.toHaveBeenCalled();
  });
});
