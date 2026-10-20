import { describe, it, expect, vi } from 'vitest';
import { act } from '@testing-library/react';
import { fetchQuery } from 'react-relay';
import { testRenderHook } from '../../../utils/tests/test-render';
import useKillChainNames from './useKillChainNames';

// Spied on, not replaced: the query still goes through the mock environment.
vi.mock('react-relay', async (importOriginal) => {
  const original = await importOriginal<typeof import('react-relay')>();
  return { ...original, fetchQuery: vi.fn(original.fetchQuery) };
});

const killChainNames = (names: string[]) => ({
  data: { runtimeAttributes: { edges: names.map((name) => ({ node: { id: name, value: name } })) } },
});

describe('useKillChainNames', () => {
  it('is loading, then ready with the names the platform holds', () => {
    const { relayEnv, hook } = testRenderHook(() => useKillChainNames());
    expect(hook.result.current).toEqual({ names: [], status: 'loading' });
    act(() => {
      relayEnv.mock.resolveMostRecentOperation(killChainNames(['lockheed-martin', 'mitre-attack']));
    });
    expect(hook.result.current).toEqual({ names: ['lockheed-martin', 'mitre-attack'], status: 'ready' });
  });

  it('is in error, with no name, when the lookup fails', () => {
    const { relayEnv, hook } = testRenderHook(() => useKillChainNames());
    act(() => {
      relayEnv.mock.rejectMostRecentOperation(new Error('FORBIDDEN_ACCESS'));
    });
    expect(hook.result.current).toEqual({ names: [], status: 'error' });
  });

  it('refreshes the names from the network, so a kill chain created since the first load is listed', () => {
    testRenderHook(() => useKillChainNames());
    expect(fetchQuery).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      { first: 500 },
      { fetchPolicy: 'network-only' },
    );
  });
});
