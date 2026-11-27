import { describe, expect, it, vi } from 'vitest';
import React from 'react';
import { act, screen } from '@testing-library/react';
import { MutationParameters } from 'relay-runtime';
import { UseMutationConfig } from 'react-relay';
import testRender, { testRenderHook } from '../tests/test-render';
import useBulkCommit from './useBulkCommit';
import { CreationFeedbackContext } from './useCreationFeedback';

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

  it('tells the surrounding view when a bulk creation starts, completes and ends', () => {
    const commit = (config: UseMutationConfig<FakeMutation>) => {
      config.onCompleted?.({ xAdd: { id: config.variables.value } }, null);
    };
    const bulkCreation = {
      onBulkStart: vi.fn(),
      onBulkCompleted: vi.fn(),
      onBulkEnd: vi.fn(),
      containerType: 'Report',
      progress: null,
      resultMessage: null,
    };
    let bulk: ReturnType<typeof useBulkCommit<FakeMutation>> | undefined;
    const Harness = () => {
      bulk = useBulkCommit<FakeMutation>({ commit });
      return null;
    };
    testRender(
      <CreationFeedbackContext.Provider value={{ silenceCreationSuccess: true, bulkCreation }}>
        <Harness />
      </CreationFeedbackContext.Provider>,
    );

    // A single object is not a bulk creation
    act(() => bulk?.bulkCommit({ variables: [{ value: 'one' }] }));
    expect(bulkCreation.onBulkStart).not.toHaveBeenCalled();
    expect(bulkCreation.onBulkCompleted).not.toHaveBeenCalled();

    act(() => bulk?.bulkCommit({ variables: [{ value: 'one' }, { value: 'two' }] }));
    expect(bulkCreation.onBulkStart).toHaveBeenCalledOnce();
    expect(bulkCreation.onBulkCompleted).toHaveBeenCalledOnce();

    act(() => bulk?.resetBulk());
    expect(bulkCreation.onBulkEnd).toHaveBeenCalledOnce();
  });

  it('shows the extra results once all the objects are created', () => {
    const commit = (config: UseMutationConfig<FakeMutation>) => {
      config.onCompleted?.({ xAdd: { id: config.variables.value } }, null);
    };
    let bulk: ReturnType<typeof useBulkCommit<FakeMutation>> | undefined;
    const Harness = () => {
      bulk = useBulkCommit<FakeMutation>({ commit });
      const { BulkResult } = bulk;
      return <BulkResult variablesToString={(v) => v.value} extraResults={['2 indicators created']} />;
    };
    testRender(<Harness />);

    // Nothing created yet
    expect(screen.queryByText('2 indicators created')).toBeNull();

    act(() => bulk?.bulkCommit({ variables: [{ value: 'one' }, { value: 'two' }] }));
    expect(screen.getByText('2 indicators created')).toBeDefined();
  });

  it('shows the add to the container in progress, then its result', () => {
    const feedback = (progress: { done: number; total: number; inProgress: boolean }) => ({
      onBulkStart: vi.fn(),
      onBulkCompleted: vi.fn(),
      onBulkEnd: vi.fn(),
      containerType: 'Report',
      progress,
      resultMessage: '2 entities added to the Report',
    });
    const Harness = () => {
      const { BulkResult } = useBulkCommit<FakeMutation>({ commit: vi.fn() });
      return <BulkResult variablesToString={(v) => v.value} />;
    };
    const { rerender } = testRender(
      <CreationFeedbackContext.Provider value={{ silenceCreationSuccess: true, bulkCreation: feedback({ done: 1, total: 2, inProgress: true }) }}>
        <Harness />
      </CreationFeedbackContext.Provider>,
    );

    expect(screen.getByText('Entities added to the Report')).toBeDefined();
    expect(screen.getByText('1/2')).toBeDefined();
    expect(screen.queryByText('2 entities added to the Report')).toBeNull();

    rerender(
      <CreationFeedbackContext.Provider value={{ silenceCreationSuccess: true, bulkCreation: feedback({ done: 2, total: 2, inProgress: false }) }}>
        <Harness />
      </CreationFeedbackContext.Provider>,
    );

    expect(screen.queryByText('Entities added to the Report')).toBeNull();
    expect(screen.getByText('2/2')).toBeDefined();
    expect(screen.getByText('2 entities added to the Report')).toBeDefined();
  });
});
