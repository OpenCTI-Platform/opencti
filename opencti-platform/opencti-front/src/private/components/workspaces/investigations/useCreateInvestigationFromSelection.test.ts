import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import useCreateInvestigationFromSelection from './useCreateInvestigationFromSelection';

const { commitMutation, navigate, mutationState } = vi.hoisted(() => ({
  commitMutation: vi.fn(),
  navigate: vi.fn(),
  mutationState: { inFlight: false },
}));

vi.mock('../../../../utils/hooks/useApiMutation', () => ({
  default: () => [commitMutation, mutationState.inFlight],
}));

vi.mock('react-router-dom', () => ({
  useNavigate: () => navigate,
}));

describe('useCreateInvestigationFromSelection', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-09-07T12:34:56.000Z'));
    vi.clearAllMocks();
    mutationState.inFlight = false;
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('creates a timestamped investigation containing the supplied entities', () => {
    const { result } = renderHook(() => useCreateInvestigationFromSelection());

    act(() => result.current.createInvestigation(['entity--1', 'relationship--2']));

    expect(commitMutation).toHaveBeenCalledWith(expect.objectContaining({
      variables: {
        input: {
          type: 'investigation',
          name: 'Investigation 2026-09-07T12:34:56.000Z',
          investigated_entities_ids: ['entity--1', 'relationship--2'],
          refresh_interval: null,
        },
      },
    }));
  });

  it('opens the newly created investigation', () => {
    const { result } = renderHook(() => useCreateInvestigationFromSelection());

    act(() => result.current.createInvestigation(['entity--1']));
    const mutationConfig = commitMutation.mock.calls[0][0];
    act(() => mutationConfig.onCompleted({ workspaceAdd: { id: 'workspace--1' } }));

    expect(navigate).toHaveBeenCalledWith('/dashboard/workspaces/investigations/workspace--1');
  });

  it('exposes the mutation in-flight state', () => {
    mutationState.inFlight = true;

    const { result } = renderHook(() => useCreateInvestigationFromSelection());

    expect(result.current.creating).toBe(true);
  });
});
