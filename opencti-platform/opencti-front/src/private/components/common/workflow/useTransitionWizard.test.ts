import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { useTransitionWizard } from './useTransitionWizard';
import { CommentMode } from '../../settings/sub_types/workflow/utils';

// ---------------------------------------------------------------------------
// Hoisted mock functions — accessible inside vi.mock factory closures
// ---------------------------------------------------------------------------
const {
  mockCommit,
  mockCommitClear,
  mockNotifySuccess,
  mockNotifyError,
  mockRelayErrorHandling,
  mockExitDraft,
  mockNavigate,
} = vi.hoisted(() => ({
  mockCommit: vi.fn(),
  mockCommitClear: vi.fn(),
  mockNotifySuccess: vi.fn(),
  mockNotifyError: vi.fn(),
  mockRelayErrorHandling: vi.fn(),
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

vi.mock('react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router')>();
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
  MESSAGING$: { notifySuccess: mockNotifySuccess, notifyError: mockNotifyError },
  relayErrorHandling: mockRelayErrorHandling,
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const renderWizard = (entityNavigationId: string | null = null, draftId?: string) =>
  renderHook(() => useTransitionWizard({ entityId: 'entity-1', entityNavigationId, draftId }));

const emptyValues = { comment: '', shareOrganizations: [], unshareOrganizations: [] };

describe('useTransitionWizard consolidated submission', () => {
  beforeEach(() => vi.clearAllMocks());

  const values = {
    comment: '  approved  ',
    shareOrganizations: [{ value: 'org-1' }],
    unshareOrganizations: [{ value: 'org-2' }],
  };

  it('submits combined inputs once and remains busy until completion', async () => {
    const { result } = renderWizard('nav-1', 'draft-1');
    act(() => result.current.handleTransition('approve', ['validateDraft'], CommentMode.required, true, true));
    let submitted: Promise<void>;
    act(() => {
      submitted = result.current.handleApplyWizard(values);
      result.current.handleApplyWizard(values);
    });
    expect(mockCommit).toHaveBeenCalledTimes(1);
    expect(result.current.approving).toBe(true);
    expect(mockCommit.mock.calls[0][0].variables).toEqual({
      entityId: 'entity-1', eventName: 'approve', comment: 'approved',
      runtimeParams: { shareOrganizationIds: ['org-1'], unshareOrganizationIds: ['org-2'] },
    });
    await act(async () => {
      mockCommit.mock.calls[0][0].onCompleted({ triggerWorkflowEvent: { success: true, executionStatus: 'completed' } });
      await submitted;
    });
    expect(result.current.approving).toBe(false);
    expect(result.current.wizard).toBeNull();
    expect(mockExitDraft).toHaveBeenCalledOnce();
  });

  it('keeps the form available for retry after a business failure', async () => {
    const { result } = renderWizard();
    act(() => result.current.handleTransition('approve', [], CommentMode.required));
    act(() => {
      result.current.handleApplyWizard(values);
    });
    await act(async () => mockCommit.mock.calls[0][0].onCompleted({ triggerWorkflowEvent: { success: false, reason: 'Denied' } }));
    expect(result.current.approving).toBe(false);
    expect(result.current.wizard?.event).toBe('approve');
    act(() => {
      result.current.handleApplyWizard(values);
    });
    expect(mockCommit).toHaveBeenCalledTimes(2);
  });

  it('delegates transport errors to central Relay handling and permits retry', async () => {
    const { result } = renderWizard();
    act(() => result.current.handleTransition('approve', [], CommentMode.allowed));
    act(() => {
      result.current.handleApplyWizard(values);
    });
    const error = new Error('Network unavailable');
    await act(async () => mockCommit.mock.calls[0][0].onError(error));
    expect(mockRelayErrorHandling).toHaveBeenCalledExactlyOnceWith(error);
    expect(mockNotifyError).not.toHaveBeenCalled();
    expect(result.current.approving).toBe(false);
    act(() => {
      result.current.handleApplyWizard(values);
    });
    expect(mockCommit).toHaveBeenCalledTimes(2);
  });

  it('never opens draft validation or exits a draft for a generic entity', () => {
    const { result } = renderWizard('entity-1');
    act(() => result.current.handleTransition('approve', ['validateDraft']));
    expect(result.current.wizard).toBeNull();
    expect(mockCommit).toHaveBeenCalledOnce();
    act(() => mockCommit.mock.calls[0][0].onCompleted({ triggerWorkflowEvent: { success: true, executionStatus: 'completed' } }));
    act(() => result.current.notifyBackgroundTransitionComplete());
    expect(mockExitDraft).not.toHaveBeenCalled();
    expect(mockNavigate).not.toHaveBeenCalled();
  });
});

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

  it('opens the form with sharing when requiresShareOrg=true', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, true, false);
    });

    expect(result.current.wizard).not.toBeNull();
    expect(result.current.wizard?.requiresShareOrg).toBe(true);
    expect(mockCommit).not.toHaveBeenCalled();
  });

  it('opens the form with unsharing when requiresUnshareOrg=true', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, false, true);
    });

    expect(result.current.wizard?.requiresUnshareOrg).toBe(true);
  });

  it('opens the form with an optional comment', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], CommentMode.allowed, false, false);
    });

    expect(result.current.wizard?.commentMode).toBe(CommentMode.allowed);
  });

  it('opens the form with a required comment', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], CommentMode.required, false, false);
    });

    expect(result.current.wizard?.commentMode).toBe(CommentMode.required);
  });

  it('requires confirmation when draft actions include validateDraft', () => {
    const { result } = renderWizard(null, 'draft-1');

    act(() => {
      result.current.handleTransition('submit', ['validateDraft'], null, false, false);
    });

    expect(result.current.wizard?.requiresValidation).toBe(true);
  });

  it('includes all applicable inputs in one form', () => {
    const { result } = renderWizard(null, 'draft-1');

    act(() => {
      result.current.handleTransition('submit', ['validateDraft'], CommentMode.required, true, false);
    });

    expect(result.current.wizard).toMatchObject({
      requiresShareOrg: true, commentMode: CommentMode.required, requiresValidation: true,
    });
  });
});

describe('useTransitionWizard organization inputs', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('submits shareOrganizationIds in runtimeParams', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, true, false);
    });

    act(() => {
      result.current.handleApplyWizard({ ...emptyValues, shareOrganizations: [{ value: 'org-1' }] });
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [variables] = mockCommit.mock.calls[0];
    expect(variables.variables.runtimeParams.shareOrganizationIds).toEqual(['org-1']);
  });

  it('submits unshareOrganizationIds in runtimeParams', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, false, true);
    });

    act(() => {
      result.current.handleApplyWizard({ ...emptyValues, unshareOrganizations: [{ value: 'org-x' }] });
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [variables] = mockCommit.mock.calls[0];
    expect(variables.variables.runtimeParams.unshareOrganizationIds).toEqual(['org-x']);
  });
});

describe('useTransitionWizard comment inputs', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('fires mutation with the trimmed comment', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], CommentMode.allowed, false, false);
    });

    act(() => {
      result.current.handleApplyWizard({ ...emptyValues, comment: '  my comment  ' });
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [{ variables }] = mockCommit.mock.calls[0];
    expect(variables.comment).toBe('my comment');
  });

  it('passes undefined comment when the comment field is empty', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], CommentMode.allowed, false, false);
    });

    act(() => {
      result.current.handleApplyWizard(emptyValues);
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [{ variables }] = mockCommit.mock.calls[0];
    expect(variables.comment).toBeUndefined();
  });
});

describe('useTransitionWizard closing reason inputs', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('opens the form when the transition enables a closing reason', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('close', [], null, false, false, CommentMode.required);
    });

    expect(mockCommit).not.toHaveBeenCalled();
    expect(result.current.wizard?.closingReasonMode).toBe(CommentMode.required);
  });

  it('fires the mutation directly when the closing reason is disabled', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('close', [], null, false, false, CommentMode.disabled);
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
  });

  it('submits the selected closing reason', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('close', [], null, false, false, CommentMode.allowed);
    });
    act(() => {
      result.current.handleApplyWizard({ ...emptyValues, closingReason: 'false-positive' });
    });

    const [{ variables }] = mockCommit.mock.calls[0];
    expect(variables.closingReason).toBe('false-positive');
  });

  it('passes undefined closing reason when none is selected', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('close', [], null, false, false, CommentMode.allowed);
    });
    act(() => {
      result.current.handleApplyWizard({ ...emptyValues, closingReason: '' });
    });

    const [{ variables }] = mockCommit.mock.calls[0];
    expect(variables.closingReason).toBeUndefined();
  });
});

describe('useTransitionWizard draft confirmation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('submits draft validation after confirmation', () => {
    const { result } = renderWizard(null, 'draft-1');

    act(() => {
      result.current.handleTransition('submit', ['validateDraft'], null, false, false);
    });

    expect(result.current.wizard?.requiresValidation).toBe(true);

    act(() => {
      result.current.handleApplyWizard(emptyValues);
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
  });
});

describe('useTransitionWizard – fireTransition response handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('notifies the returned business failure reason without reporting success', () => {
    const { result } = renderWizard();
    act(() => result.current.handleTransition('submit', []));
    const [{ onCompleted }] = mockCommit.mock.calls[0];
    act(() => onCompleted({ triggerWorkflowEvent: { success: false, reason: 'Transition denied' } }));
    expect(mockNotifyError).toHaveBeenCalledWith('Transition denied');
    expect(mockNotifySuccess).not.toHaveBeenCalled();
    expect(mockExitDraft).not.toHaveBeenCalled();
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
    const { result } = renderWizard('nav-entity-1', 'draft-1');

    act(() => {
      result.current.handleTransition('submit', ['validateDraft'], null, false, false);
    });

    act(() => {
      result.current.handleApplyWizard(emptyValues);
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
    const { result } = renderWizard('nav-1', 'draft-1');

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
