/**
 * Tests for WorkflowTransitions.tsx — focusing on pending/error state branches
 * that are not covered by WorkflowStatus.test.tsx (which tests the normal transition UI).
 */
import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { screen } from '@testing-library/react';
import { WorkflowTransitions } from './WorkflowTransitions';
import testRender from '../../../../utils/tests/test-render';
import type { workflowStatus_data$key } from './__generated__/workflowStatus_data.graphql';

// ---------------------------------------------------------------------------
// Relay + router mocks (same pattern as WorkflowStatus.test.tsx)
// ---------------------------------------------------------------------------
const mockCommit = vi.fn();
const mockCommitRetry = vi.fn();
const mockCommitClear = vi.fn();

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    createFragmentContainer: (component: React.ComponentType) => component,
    useFragment: (_fragment: unknown, data: unknown) => data,
    useMutation: vi.fn()
      .mockImplementationOnce(() => [mockCommit, false])
      .mockImplementationOnce(() => [mockCommitRetry, false])
      .mockImplementationOnce(() => [mockCommitClear, false])
      .mockImplementation(() => [vi.fn(), false]),
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

vi.mock('../../../../relay/environment', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../relay/environment')>();
  return {
    ...actual,
    MESSAGING$: { notifySuccess: vi.fn(), notifyError: vi.fn() },
  };
});

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
const makeStatus = () => ({
  id: 'status-1',
  template: { name: 'In review', color: '#ff0000' },
});

const makeDraft = (overrides: Record<string, unknown> = {}): workflowStatus_data$key => ({
  id: 'draft-1',
  entity_id: 'entity-1',
  processingCount: 0,
  workflowInstance: {
    id: 'instance-1',
    currentState: 'in_review',
    currentStatus: makeStatus(),
    lastHistoryEntry: null,
    allowedTransitions: [],
    pendingStatus: null,
    pendingTransition: null,
    pendingError: null,
  },
  ...overrides,
} as unknown as workflowStatus_data$key);

const makePendingDraft = (asyncActions = [{ id: 's1', workId: 'w1', type: 'asyncBulkAction', status: 'pending', expectedCount: 20, processedCount: 5 }]) =>
  makeDraft({
    workflowInstance: {
      id: 'instance-1',
      currentState: 'in_review',
      currentStatus: makeStatus(),
      lastHistoryEntry: null,
      allowedTransitions: [],
      pendingStatus: 'pending',
      pendingError: null,
      pendingTransition: {
        event: 'Sharing with partners',
        toState: 'shared',
        triggeredAt: new Date().toISOString(),
        asyncActions,
      },
    },
  });

const makeErrorDraft = (pendingError?: string) =>
  makeDraft({
    workflowInstance: {
      id: 'instance-1',
      currentState: 'in_review',
      currentStatus: makeStatus(),
      lastHistoryEntry: null,
      allowedTransitions: [],
      pendingStatus: 'error',
      pendingError: pendingError ?? null,
      pendingTransition: null,
    },
  });

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('WorkflowTransitions – pending state UI', () => {
  beforeEach(() => {
    mockCommit.mockReset();
    mockCommitRetry.mockReset();
    mockCommitClear.mockReset();
  });

  it('renders null when workflowInstance is absent', () => {
    const { container } = testRender(
      <WorkflowTransitions data={makeDraft({ workflowInstance: null })} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders the event name and a spinner when a transition is pending', () => {
    testRender(<WorkflowTransitions data={makePendingDraft()} />);
    expect(screen.getByText('Sharing with partners')).toBeDefined();
    // CircularProgress renders an svg with role="progressbar"
    expect(document.querySelector('[role="progressbar"]')).not.toBeNull();
  });

  it('renders the progress counter (processedCount / expectedCount) when expectedCount > 0', () => {
    testRender(<WorkflowTransitions data={makePendingDraft()} />);
    expect(screen.getByText('5 / 20')).toBeDefined();
  });

  it('hides the progress counter when expectedCount is 0', () => {
    const draft = makePendingDraft([{ id: 's1', workId: 'w1', type: 'asyncBulkAction', status: 'pending', expectedCount: 0, processedCount: 0 }]);
    testRender(<WorkflowTransitions data={draft} />);
    expect(screen.queryByText(/\//)).toBeNull();
  });

  it('does NOT render transition buttons while pending', () => {
    const pendingDraft = makePendingDraft();
    testRender(<WorkflowTransitions data={pendingDraft} />);
    // No "approve" or similar buttons
    expect(screen.queryByRole('button')).toBeNull();
  });
});

describe('WorkflowTransitions – error state UI', () => {
  beforeEach(() => {
    mockCommit.mockReset();
    mockCommitRetry.mockReset();
    mockCommitClear.mockReset();
  });

  it('renders "Transition failed" text and an error icon when pendingStatus is error', () => {
    testRender(<WorkflowTransitions data={makeErrorDraft()} />);
    expect(screen.getByText('Transition failed')).toBeDefined();
  });

  it('renders Retry and Clear buttons in the error state', () => {
    testRender(<WorkflowTransitions data={makeErrorDraft()} />);
    expect(screen.getByText('Retry')).toBeDefined();
    expect(screen.getByText('Clear')).toBeDefined();
  });

  it('Retry button is not disabled when not currently retrying or clearing', () => {
    testRender(<WorkflowTransitions data={makeErrorDraft()} />);
    const retryBtn = screen.getByText('Retry').closest('button');
    expect(retryBtn).not.toBeDisabled();
  });

  it('does NOT render normal transition buttons in error state', () => {
    const errorDraft = makeErrorDraft('task failed');
    testRender(<WorkflowTransitions data={errorDraft} />);
    // Only Retry and Clear buttons should be present
    const buttons = screen.getAllByRole('button');
    const buttonTexts = buttons.map((b) => b.textContent ?? '');
    expect(buttonTexts.some((t) => t.includes('Retry'))).toBe(true);
    expect(buttonTexts.some((t) => t.includes('Clear'))).toBe(true);
    expect(buttonTexts.some((t) => !t.includes('Retry') && !t.includes('Clear') && t.trim() !== '')).toBe(false);
  });
});

describe('WorkflowTransitions – validate draft dialog', () => {
  beforeEach(() => {
    mockCommit.mockReset();
    mockCommitRetry.mockReset();
    mockCommitClear.mockReset();
  });

  it('shows the validate draft dialog when currentStep is validate', async () => {
    const draft = makeDraft({
      workflowInstance: {
        id: 'instance-1',
        currentState: 'in_review',
        currentStatus: makeStatus(),
        lastHistoryEntry: null,
        pendingStatus: null,
        pendingError: null,
        pendingTransition: null,
        allowedTransitions: [
          {
            event: 'approve',
            toState: 'approved',
            actions: ['validateDraft'],
            comment: null,
            requiresShareOrganizationInput: false,
            requiresUnshareOrganizationInput: false,
            toStatus: makeStatus(),
          },
        ],
      },
    });

    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    expect(await screen.findByText('Do you want to approve this draft and send it to ingestion?')).toBeDefined();
  });

  it('shows a warning Alert when processingCount > 0 in the validate dialog', async () => {
    const draft = {
      ...makeDraft({
        processingCount: 3,
        workflowInstance: {
          id: 'instance-1',
          currentState: 'in_review',
          currentStatus: makeStatus(),
          lastHistoryEntry: null,
          pendingStatus: null,
          pendingError: null,
          pendingTransition: null,
          allowedTransitions: [
            {
              event: 'approve',
              toState: 'approved',
              actions: ['validateDraft'],
              comment: null,
              requiresShareOrganizationInput: false,
              requiresUnshareOrganizationInput: false,
              toStatus: makeStatus(),
            },
          ],
        },
      }),
    };

    const { user } = testRender(<WorkflowTransitions data={draft} />);
    await user.click(screen.getByText('approve'));
    expect(await screen.findByText('Ongoing processes')).toBeDefined();
  });
});
