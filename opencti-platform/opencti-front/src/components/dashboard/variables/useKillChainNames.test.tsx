import { describe, it, expect } from 'vitest';
import { act, renderHook } from '@testing-library/react';
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

  // Asserted on the mock environment, not on a spy of `fetchQuery`: the front tests run with `isolate: false`, so a
  // `vi.mock('react-relay')` does not apply once another test file has loaded the module, and the spy records nothing.
  it('refreshes the names from the network, so a kill chain created since the first load is listed', () => {
    const { relayEnv, hook } = testRenderHook(() => useKillChainNames());
    expect(relayEnv.mock.getMostRecentOperation().request.variables).toEqual({ first: KILL_CHAIN_NAMES_LIMIT });
    act(() => {
      relayEnv.mock.resolveMostRecentOperation(killChainNames(['mitre-attack']));
    });
    hook.unmount();
    // Mounted again on the same environment, whose store already holds the first answer: the names are asked again
    const remount = renderHook(() => useKillChainNames(), {
      wrapper: ({ children }) => <ProvidersWrapper relayEnv={relayEnv}>{children}</ProvidersWrapper>,
    });
    expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
    expect(remount.result.current).toEqual({ names: [], status: 'loading' });
    act(() => {
      relayEnv.mock.resolveMostRecentOperation(killChainNames(['lockheed-martin', 'mitre-attack']));
    });
    expect(remount.result.current).toEqual({ names: ['lockheed-martin', 'mitre-attack'], status: 'ready' });
  });
});
