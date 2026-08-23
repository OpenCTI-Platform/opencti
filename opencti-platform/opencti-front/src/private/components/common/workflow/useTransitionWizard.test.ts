import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CommentMode } from '../../settings/sub_types/workflow/utils';
import { useTransitionWizard } from './useTransitionWizard';

// ---------------------------------------------------------------------------
// Hoisted mock functions — accessible inside vi.mock factory closures
// ---------------------------------------------------------------------------
const {
  mockCommit,
  mockCommitClear,
  mockNotifySuccess,
  mockExitDraft,
  mockNavigate,
} = vi.hoisted(() => ({
  mockCommit: vi.fn(),
  mockCommitClear: vi.fn(),
  mockNotifySuccess: vi.fn(),
  mockExitDraft: vi.fn(),
  mockNavigate: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

// Distinguish mutations by identity so useMutation can return the right commit fn
// in every test, without relying on a fragile mockImplementationOnce queue.
vi.mock('./WorkflowStatus.graphql', () => ({
  workflowStatusTriggerMutation: { __id: 'trigger' },
  workflowStatusClearMutation: { __id: 'clear' },
  workflowStatusFragment: {},
  COMMENT_MAX_LENGTH: 1000,
}));

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    useMutation: (mutation: { __id?: string }) => {
      if (mutation?.__id === 'trigger') return [mockCommit, false];
      if (mutation?.__id === 'clear') return [mockCommitClear, false];
      return [vi.fn(), false];
    },
  };
});

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => mockNavigate };
});

vi.mock('../../drafts/useSwitchDraft', () => ({
  default: () => ({ exitDraft: mockExitDraft }),
}));

vi.mock('../../../../utils/hooks/useGranted', () => ({
  default: () => false,
  KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS: 'KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS',
}));

vi.mock('../../../../components/i18n', () => ({
  useFormatter: () => ({ t_i18n: (s: string) => s }),
}));

vi.mock('../../../../relay/environment', () => ({
  MESSAGING$: { notifySuccess: mockNotifySuccess, notifyError: vi.fn() },
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const renderWizard = (entityNavigationId: string | null = null, draftId?: string) =>
  renderHook(() => useTransitionWizard({ entityId: 'entity-1', entityNavigationId, draftId }));

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('useTransitionWizard – handleTransition', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('fires mutation directly when no wizard steps are needed (no org, no comment, no validateDraft)', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', ['someAction'], null, false, false);
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    expect(result.current.wizard).toBeNull();
  });

  it('opens wizard with org-picker step when requiresShareOrg=true', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, true, false);
    });

    expect(result.current.wizard).not.toBeNull();
    expect(result.current.wizard!.steps).toEqual(['org-picker']);
    expect(mockCommit).not.toHaveBeenCalled();
  });

  it('opens wizard with org-picker step when requiresUnshareOrg=true', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, false, true);
    });

    expect(result.current.wizard!.steps).toEqual(['org-picker']);
  });

  it('opens wizard with comment step when comment mode is "allowed"', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], CommentMode.allowed, false, false);
    });

    expect(result.current.wizard!.steps).toEqual(['comment']);
  });

  it('opens wizard with comment step when comment mode is "required"', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], CommentMode.required, false, false);
    });

    expect(result.current.wizard!.steps).toEqual(['comment']);
  });

  it('adds validate step when actions include validateDraft', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', ['validateDraft'], null, false, false);
    });

    expect(result.current.wizard!.steps).toEqual(['validate']);
  });

  it('includes org-picker, comment and validate together when all are needed', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', ['validateDraft'], CommentMode.required, true, false);
    });

    expect(result.current.wizard!.steps).toEqual(['org-picker', 'comment', 'validate']);
  });

  it('adds closing-reason step when the transition is closing', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, false, false, true);
    });

    expect(result.current.wizard!.steps).toEqual(['closing-reason']);
  });

  it('does NOT add closing-reason step when the transition is not closing', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, false, false, false);
    });

    expect(result.current.wizard).toBeNull();
  });
});

describe('useTransitionWizard – handleApplyWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('fires the mutation once with shareOrganizationIds built from the form values, and closes the wizard', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, true, false);
    });

    act(() => {
      result.current.handleApplyWizard({
        comment: '',
        shareOrganizations: [{ value: 'org-1' }],
        unshareOrganizations: [],
      });
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [{ variables }] = mockCommit.mock.calls[0];
    expect(variables.runtimeParams.shareOrganizationIds).toEqual(['org-1']);
    expect(result.current.wizard).toBeNull();
  });

  it('fires the mutation once with unshareOrganizationIds built from the form values', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, false, true);
    });

    act(() => {
      result.current.handleApplyWizard({
        comment: '',
        shareOrganizations: [],
        unshareOrganizations: [{ value: 'org-x' }],
      });
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [{ variables }] = mockCommit.mock.calls[0];
    expect(variables.runtimeParams.unshareOrganizationIds).toEqual(['org-x']);
  });

  it('fires the mutation with the trimmed comment', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], CommentMode.allowed, false, false);
    });

    act(() => {
      result.current.handleApplyWizard({
        comment: '  my comment  ',
        shareOrganizations: [],
        unshareOrganizations: [],
      });
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [{ variables }] = mockCommit.mock.calls[0];
    expect(variables.comment).toBe('my comment');
  });

  it('fires the mutation with the trimmed closing reason', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, false, false, true);
    });

    act(() => {
      result.current.handleApplyWizard({
        comment: '',
        closingReason: '  no longer needed  ',
        shareOrganizations: [],
        unshareOrganizations: [],
      });
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [{ variables }] = mockCommit.mock.calls[0];
    expect(variables.closingReason).toBe('no longer needed');
  });

  it('passes undefined closingReason when the closing reason field is empty', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, false, false, true);
    });

    act(() => {
      result.current.handleApplyWizard({
        comment: '',
        closingReason: '',
        shareOrganizations: [],
        unshareOrganizations: [],
      });
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [{ variables }] = mockCommit.mock.calls[0];
    expect(variables.closingReason).toBeUndefined();
  });

  it('passes undefined comment when the comment field is empty', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], CommentMode.allowed, false, false);
    });

    act(() => {
      result.current.handleApplyWizard({ comment: '', shareOrganizations: [], unshareOrganizations: [] });
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [{ variables }] = mockCommit.mock.calls[0];
    expect(variables.comment).toBeUndefined();
  });

  it('combines org picker and comment and validate in a single fire when all steps are included', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', ['validateDraft'], CommentMode.required, true, false);
    });

    act(() => {
      result.current.handleApplyWizard({
        comment: 'approved',
        shareOrganizations: [{ value: 'org-1' }],
        unshareOrganizations: [],
      });
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [{ variables }] = mockCommit.mock.calls[0];
    expect(variables.runtimeParams.shareOrganizationIds).toEqual(['org-1']);
    expect(variables.comment).toBe('approved');
    expect(result.current.wizard).toBeNull();
  });

  it('does nothing when called with no wizard open', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleApplyWizard({ comment: '', shareOrganizations: [], unshareOrganizations: [] });
    });

    expect(mockCommit).not.toHaveBeenCalled();
  });
});

describe('useTransitionWizard – fireTransition response handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls notifySuccess and does NOT navigate when executionStatus is pending', () => {
    const { result } = renderWizard('nav-entity-1');

    act(() => {
      result.current.handleTransition('submit', [], null, false, false);
    });

    // Simulate the mutation onCompleted callback
    const [{ onCompleted }] = mockCommit.mock.calls[0];
    act(() => {
      onCompleted({ triggerWorkflowEvent: { success: true, executionStatus: 'pending' } });
    });

    expect(mockNotifySuccess).toHaveBeenCalledWith('Workflow transition started in background');
    expect(mockExitDraft).not.toHaveBeenCalled();
  });

  it('calls exitDraft when sync validateDraft completes successfully', () => {
    const { result } = renderWizard('nav-entity-1');

    act(() => {
      result.current.handleTransition('submit', ['validateDraft'], null, false, false);
    });

    // validate is the only step → apply immediately fires the transition
    act(() => {
      result.current.handleApplyWizard({ comment: '', shareOrganizations: [], unshareOrganizations: [] });
    });

    const [{ onCompleted }] = mockCommit.mock.calls[0];
    act(() => {
      onCompleted({ triggerWorkflowEvent: { success: true, executionStatus: 'completed' } });
    });

    expect(mockExitDraft).toHaveBeenCalledTimes(1);
  });
});

describe('useTransitionWizard – handleClear', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls notifySuccess when clear completes', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleClear();
    });

    const [{ onCompleted }] = mockCommitClear.mock.calls[0];
    act(() => {
      onCompleted({});
    });

    expect(mockNotifySuccess).toHaveBeenCalledWith('Pending workflow state cleared');
  });
});

describe('useTransitionWizard – notifyBackgroundTransitionComplete', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls notifySuccess and exits draft', () => {
    const { result } = renderWizard('nav-1');

    act(() => {
      result.current.notifyBackgroundTransitionComplete();
    });

    expect(mockNotifySuccess).toHaveBeenCalledWith('Draft validated successfully');
    expect(mockExitDraft).toHaveBeenCalledTimes(1);
  });
});

describe('useTransitionWizard – localStorage draft comment seen', () => {
  const DRAFT_ID = 'draft-abc';
  const STORAGE_KEY = `opencti-draft-comment-seen-${DRAFT_ID}`;
  const NEW_TIMESTAMP = '2024-06-01T12:00:00.000Z';

  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.clear();
  });

  afterEach(() => {
    window.localStorage.clear();
  });

  it('writes the new timestamp to localStorage when the mutation returns lastHistoryEntry', () => {
    const { result } = renderWizard(null, DRAFT_ID);

    act(() => {
      result.current.handleTransition('submit', [], null, false, false);
    });

    const [{ onCompleted }] = mockCommit.mock.calls[0];
    act(() => {
      onCompleted({
        triggerWorkflowEvent: {
          success: true,
          executionStatus: 'completed',
          instance: { lastHistoryEntry: { timestamp: NEW_TIMESTAMP } },
        },
      });
    });

    expect(window.localStorage.getItem(STORAGE_KEY)).toBe(NEW_TIMESTAMP);
  });

  it('does not write localStorage when no draftId is provided', () => {
    const { result } = renderWizard(null, undefined);

    act(() => {
      result.current.handleTransition('submit', [], null, false, false);
    });

    const [{ onCompleted }] = mockCommit.mock.calls[0];
    act(() => {
      onCompleted({
        triggerWorkflowEvent: {
          success: true,
          executionStatus: 'completed',
          instance: { lastHistoryEntry: { timestamp: NEW_TIMESTAMP } },
        },
      });
    });

    expect(window.localStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it('does not write localStorage when instance has no lastHistoryEntry', () => {
    const { result } = renderWizard(null, DRAFT_ID);

    act(() => {
      result.current.handleTransition('submit', [], null, false, false);
    });

    const [{ onCompleted }] = mockCommit.mock.calls[0];
    act(() => {
      onCompleted({
        triggerWorkflowEvent: {
          success: true,
          executionStatus: 'completed',
          instance: { lastHistoryEntry: null },
        },
      });
    });

    expect(window.localStorage.getItem(STORAGE_KEY)).toBeNull();
  });
});
