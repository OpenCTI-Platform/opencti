import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import type { DashboardVariable } from '../dashboard-types';
import { useDashboardVariableMutations, variableToInput } from './useDashboardVariableMutations';

const commit = vi.hoisted(() => vi.fn());
vi.mock('../../../utils/hooks/useApiMutation', () => ({ default: () => [commit, false] }));

const sector: DashboardVariable = { id: 'a', name: 'Sector', type: 'entity', entityTypes: ['Sector'], restriction: { mode: 'none' }, defaultValue: 's1' };

describe('variableToInput', () => {
  it('serializes restriction filters as a backend JSON string', () => {
    const input = variableToInput({
      ...sector,
      restriction: { mode: 'filters', filters: { mode: 'and', filters: [{ id: 'f', key: 'entity_type', values: ['Sector'], operator: 'eq', mode: 'or' }], filterGroups: [] } },
    });
    expect(input.restriction?.mode).toBe('filters');
    expect(typeof input.restriction?.filters).toBe('string');
    expect(JSON.parse(input.restriction?.filters as string).filters[0].key).toEqual(['entity_type']);
  });
  it('round-trips a selection restriction', () => {
    const input = variableToInput({ ...sector, restriction: { mode: 'selection', values: ['s1', 's2'] } });
    expect(input.restriction).toEqual({ mode: 'selection', values: ['s1', 's2'] });
  });
  it('round-trips a restriction of mode none', () => {
    const input = variableToInput(sector);
    expect(input.restriction).toEqual({ mode: 'none' });
    expect(input).toMatchObject({ id: 'a', name: 'Sector', type: 'entity', entityTypes: ['Sector'], defaultValue: 's1' });
  });
  it('omits the type specific fields that do not apply', () => {
    const input = variableToInput({ id: 'b', name: 'N', type: 'text', restriction: { mode: 'none' }, defaultValue: 'x' });
    expect(input).not.toHaveProperty('entityTypes');
    expect(input).not.toHaveProperty('vocabularyCategory');
  });
});

describe('useDashboardVariableMutations', () => {
  beforeEach(() => {
    commit.mockReset();
    commit.mockImplementation(({ onCompleted }) => onCompleted?.());
  });

  it('upsert sends the workspace id and the variable input', async () => {
    const { result } = renderHook(() => useDashboardVariableMutations('ws-1'));
    await result.current.upsert(sector);
    expect(commit).toHaveBeenCalledTimes(1);
    expect(commit.mock.calls[0][0].variables).toMatchObject({ id: 'ws-1', input: { id: 'a', name: 'Sector' } });
  });

  it('remove sends the workspace id and the variable id', async () => {
    const { result } = renderHook(() => useDashboardVariableMutations('ws-1'));
    await result.current.remove('a');
    expect(commit.mock.calls[0][0].variables).toEqual({ id: 'ws-1', variableId: 'a' });
  });

  it('rejects when the mutation fails', async () => {
    commit.mockImplementation(({ onError }) => onError?.(new Error('boom')));
    const { result } = renderHook(() => useDashboardVariableMutations('ws-1'));
    await expect(result.current.remove('a')).rejects.toThrow('boom');
  });
});

describe('setAsDefaults', () => {
  beforeEach(() => {
    commit.mockReset();
    commit.mockImplementation(({ onCompleted }) => onCompleted?.());
  });

  it('upserts only the variables whose current value differs from the default, one after the other', async () => {
    const other = { ...sector, id: 'c', defaultValue: 'x' };
    const { result } = renderHook(() => useDashboardVariableMutations('ws-1'));
    await result.current.setAsDefaults([sector, other], new Map([['a', 's2'], ['c', 'x']]));
    expect(commit).toHaveBeenCalledTimes(1);
    expect(commit.mock.calls[0][0].variables.input).toMatchObject({ id: 'a', defaultValue: 's2' });
  });

  it('waits for each upsert before sending the next one', async () => {
    const second = { ...sector, id: 'c', defaultValue: 'x' };
    const completions: Array<() => void> = [];
    commit.mockImplementation(({ onCompleted }) => completions.push(() => onCompleted?.()));
    const { result } = renderHook(() => useDashboardVariableMutations('ws-1'));
    const done = result.current.setAsDefaults([sector, second], new Map([['a', 's2'], ['c', 'y']]));
    await Promise.resolve();
    expect(commit).toHaveBeenCalledTimes(1);
    completions[0]();
    await vi.waitFor(() => expect(commit).toHaveBeenCalledTimes(2));
    expect(commit.mock.calls[1][0].variables.input).toMatchObject({ id: 'c', defaultValue: 'y' });
    completions[1]();
    await done;
  });

  it('stops on the first error', async () => {
    const second = { ...sector, id: 'c', defaultValue: 'x' };
    commit.mockImplementation(({ onError }) => onError?.(new Error('boom')));
    const { result } = renderHook(() => useDashboardVariableMutations('ws-1'));
    await expect(result.current.setAsDefaults([sector, second], new Map([['a', 's2'], ['c', 'y']]))).rejects.toThrow('boom');
    expect(commit).toHaveBeenCalledTimes(1);
  });
});
