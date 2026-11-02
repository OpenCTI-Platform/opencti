import { describe, it, expect } from 'vitest';
import React from 'react';
import { act, renderHook } from '@testing-library/react';
import { createMockEnvironment } from 'relay-test-utils';
import { ProvidersWrapper, testRenderHook } from '../../../utils/tests/test-render';
import useKillChainNames, { KILL_CHAIN_NAMES_LIMIT } from './useKillChainNames';

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

  // Asserted through the mock environment, not a spy on `react-relay`: a module mock is not reliably the instance the
  // hook imports when test files share a worker (vitest `isolate: false`), so a spy could record no call (#19469).
  it('refreshes the names from the network, so a kill chain created since the first load is listed', () => {
    const relayEnv = createMockEnvironment();
    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <ProvidersWrapper relayEnv={relayEnv}>{children}</ProvidersWrapper>
    );

    const first = renderHook(() => useKillChainNames(), { wrapper });
    act(() => {
      relayEnv.mock.resolveMostRecentOperation(killChainNames(['lockheed-martin']));
    });
    expect(first.result.current).toEqual({ names: ['lockheed-martin'], status: 'ready' });
    first.unmount();

    // Mounted again on the same environment, with the names already in its store: a new network request is issued.
    const second = renderHook(() => useKillChainNames(), { wrapper });
    const pending = relayEnv.mock.getAllOperations();
    expect(pending).toHaveLength(1);
    expect(pending[0].request.variables).toEqual({ first: KILL_CHAIN_NAMES_LIMIT });
    act(() => {
      relayEnv.mock.resolveMostRecentOperation(killChainNames(['lockheed-martin', 'mitre-attack']));
    });
    expect(second.result.current).toEqual({ names: ['lockheed-martin', 'mitre-attack'], status: 'ready' });
  });
});
