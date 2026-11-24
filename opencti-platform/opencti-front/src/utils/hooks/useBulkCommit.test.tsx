import { describe, expect, it, vi } from 'vitest';
import { act } from '@testing-library/react';
import { MutationParameters } from 'relay-runtime';
import { UseMutationConfig } from 'react-relay';
import { testRenderHook } from '../tests/test-render';
import useBulkCommit from './useBulkCommit';

interface FakeMutation extends MutationParameters {
  variables: { value: string };
  response: { xAdd: { id: string } };
}

describe('useBulkCommit', () => {
  it('passes each step response to onStepCompleted', () => {
    const commit = (config: UseMutationConfig<FakeMutation>) => {
      config.onCompleted?.({ xAdd: { id: config.variables.value === 'one' ? 'a' : 'b' } }, null);
    };
    const { hook } = testRenderHook(() => useBulkCommit<FakeMutation>({ commit }));
    const onStepCompleted = vi.fn();

    act(() => {
      hook.result.current.bulkCommit({ variables: [{ value: 'one' }, { value: 'two' }], onStepCompleted });
    });

    expect(onStepCompleted).toHaveBeenNthCalledWith(1, { value: 'one' }, { xAdd: { id: 'a' } });
    expect(onStepCompleted).toHaveBeenNthCalledWith(2, { value: 'two' }, { xAdd: { id: 'b' } });
  });
});
