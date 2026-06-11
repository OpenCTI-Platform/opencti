import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useTransitionWizard } from './useTransitionWizard';
import { CommentMode } from '../../settings/sub_types/workflow/utils';

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
const renderWizard = (entityNavigationId: string | null = null) =>
  renderHook(() => useTransitionWizard({ entityId: 'entity-1', entityNavigationId }));

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

  it('opens wizard at org-picker step when requiresShareOrg=true', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, true, false);
    });

    expect(result.current.wizard).not.toBeNull();
    expect(result.current.currentStep).toBe('org-picker');
    expect(mockCommit).not.toHaveBeenCalled();
  });

  it('opens wizard at org-picker step when requiresUnshareOrg=true', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, false, true);
    });

    expect(result.current.currentStep).toBe('org-picker');
  });

  it('opens wizard at comment step when comment mode is "allowed"', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], CommentMode.allowed, false, false);
    });

    expect(result.current.currentStep).toBe('comment');
  });

  it('opens wizard at comment step when comment mode is "required"', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], CommentMode.required, false, false);
    });

    expect(result.current.currentStep).toBe('comment');
  });

  it('adds validate step when actions include validateDraft', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', ['validateDraft'], null, false, false);
    });

    expect(result.current.currentStep).toBe('validate');
  });

  it('queues org-picker → comment → validate when all are needed', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', ['validateDraft'], CommentMode.required, true, false);
    });

    expect(result.current.currentStep).toBe('org-picker');
    // After org-picker, comment step should come next
    expect(result.current.wizard!.steps).toEqual(['org-picker', 'comment', 'validate']);
  });
});

describe('useTransitionWizard – handleOrgPickerSubmit', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('advances with shareOrganizationIds in runtimeParams', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, true, false);
    });

    act(() => {
      result.current.handleOrgPickerSubmit(
        { shareOrganizations: [{ value: 'org-1' }], unshareOrganizations: [] },
        { resetForm: vi.fn() },
      );
    });

    // No more steps after org-picker with no comment or validate → mutation fires
    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [variables] = mockCommit.mock.calls[0];
    expect(variables.variables.runtimeParams.shareOrganizationIds).toEqual(['org-1']);
  });

  it('advances with unshareOrganizationIds in runtimeParams', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], null, false, true);
    });

    act(() => {
      result.current.handleOrgPickerSubmit(
        { shareOrganizations: [], unshareOrganizations: [{ value: 'org-x' }] },
        { resetForm: vi.fn() },
      );
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [variables] = mockCommit.mock.calls[0];
    expect(variables.variables.runtimeParams.unshareOrganizationIds).toEqual(['org-x']);
  });
});

describe('useTransitionWizard – handleConfirmComment', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('fires mutation with the trimmed comment and clears commentValue', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], CommentMode.allowed, false, false);
    });

    act(() => {
      result.current.setCommentValue('  my comment  ');
    });

    act(() => {
      result.current.handleConfirmComment();
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [{ variables }] = mockCommit.mock.calls[0];
    expect(variables.comment).toBe('my comment');
    expect(result.current.commentValue).toBe('');
  });

  it('passes undefined comment when the comment field is empty', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', [], CommentMode.allowed, false, false);
    });

    act(() => {
      result.current.handleConfirmComment();
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
    const [{ variables }] = mockCommit.mock.calls[0];
    expect(variables.comment).toBeUndefined();
  });
});

describe('useTransitionWizard – handleValidateDraft', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('advances the wizard (fires mutation when validate is the last step)', () => {
    const { result } = renderWizard();

    act(() => {
      result.current.handleTransition('submit', ['validateDraft'], null, false, false);
    });

    expect(result.current.currentStep).toBe('validate');

    act(() => {
      result.current.handleValidateDraft();
    });

    expect(mockCommit).toHaveBeenCalledTimes(1);
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

    // validate step fires
    act(() => {
      result.current.handleValidateDraft();
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
