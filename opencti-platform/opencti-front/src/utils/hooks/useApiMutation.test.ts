import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook } from '@testing-library/react';
import { GraphQLTaggedNode } from 'relay-runtime';
import useApiMutation from './useApiMutation';
import * as useDeferredCreationModule from './useDeferredCreation';

// ── Relay mocks ──────────────────────────────────────────────────────────────

const mockCommit = vi.fn();
vi.mock('react-relay', async () => {
  const actual = await vi.importActual('react-relay');
  return {
    ...actual,
    useMutation: () => [mockCommit, false],
  };
});

// ── Silence MESSAGING$ side-effects ─────────────────────────────────────────

vi.mock('../../relay/environment', () => ({
  MESSAGING$: { notifyError: vi.fn(), notifyRelayError: vi.fn(), notifyCustomRelayError: vi.fn(), notifySuccess: vi.fn() },
  relayErrorHandling: vi.fn(),
}));

// ── Helpers ──────────────────────────────────────────────────────────────────

const fakeQuery = {} as GraphQLTaggedNode;

/** Render the hook and return the commit function. */
const renderCommit = () => {
  const { result } = renderHook(() => useApiMutation(fakeQuery));
  const [commit] = result.current;
  return commit;
};

// ── Tests ────────────────────────────────────────────────────────────────────

describe('useApiMutation – normal mode (isDeferredMode = false)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(useDeferredCreationModule, 'useDeferredCreation').mockReturnValue({
      isDeferredMode: false,
      captureInput: vi.fn(),
    });
  });

  it('delegates to the real commit when not in deferred mode', () => {
    const commit = renderCommit();
    const args = { variables: { input: { name: 'Test' } }, onCompleted: vi.fn() };

    commit(args as Parameters<typeof commit>[0]);

    expect(mockCommit).toHaveBeenCalledOnce();
    expect(args.onCompleted).not.toHaveBeenCalled(); // called by relay, not by us
  });
});

describe('useApiMutation – deferred mode (isDeferredMode = true)', () => {
  const captureInput = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(useDeferredCreationModule, 'useDeferredCreation').mockReturnValue({
      isDeferredMode: true,
      captureInput,
    });
  });

  it('does NOT call the real commit', () => {
    const commit = renderCommit();
    commit({ variables: { input: { name: 'Intercepted' } } } as Parameters<typeof commit>[0]);

    expect(mockCommit).not.toHaveBeenCalled();
  });

  it('captures variables.input for SDO-style mutations', () => {
    const commit = renderCommit();
    const inputData = { name: 'New Malware', is_family: true };

    commit({ variables: { input: inputData } } as Parameters<typeof commit>[0]);

    expect(captureInput).toHaveBeenCalledWith(inputData);
  });

  it('captures full variables for SCO-style flat mutations (no input key)', () => {
    const commit = renderCommit();
    const scoVariables = { type: 'IPv4-Addr', IPv4Addr: { value: '1.2.3.4' } };

    commit({ variables: scoVariables } as Parameters<typeof commit>[0]);

    expect(captureInput).toHaveBeenCalledWith(scoVariables);
  });

  it('calls onCompleted with an empty response to close the form', () => {
    const commit = renderCommit();
    const onCompleted = vi.fn();

    commit({ variables: { input: { name: 'Test' } }, onCompleted } as Parameters<typeof commit>[0]);

    expect(onCompleted).toHaveBeenCalledWith({}, null);
  });

  it('does not throw when onCompleted is absent', () => {
    const commit = renderCommit();
    expect(() => {
      commit({ variables: { input: { name: 'Test' } } } as Parameters<typeof commit>[0]);
    }).not.toThrow();
  });
});
