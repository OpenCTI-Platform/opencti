import { describe, it, expect } from 'vitest';
import { act } from '@testing-library/react';
import { testRenderHook } from '../../../utils/tests/test-render';
import useVariableValueLabels from './useVariableValueLabels';
import type { DashboardVariableShape } from './DashboardVariableValueInput';

const label: DashboardVariableShape = { type: 'label', restriction: { mode: 'none' } };

const renderLabels = (variable: DashboardVariableShape, values: string[]) => testRenderHook(() => useVariableValueLabels(variable, values));

describe('useVariableValueLabels', () => {
  it('resolves entity ids through the filters representatives', () => {
    const { relayEnv, hook } = renderLabels(label, ['label-1', 'label-2']);
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.variables.filters).toEqual({
      mode: 'and',
      filterGroups: [],
      filters: [{ key: ['id'], values: ['label-1', 'label-2'], operator: 'eq', mode: 'or' }],
    });
    act(() => {
      relayEnv.mock.resolve(operation, {
        data: {
          filtersRepresentatives: [
            { representativeId: 'label-1', value: 'malicious', entity_type: 'Label', color: null },
            { representativeId: 'label-2', value: 'benign', entity_type: 'Label', color: null },
          ],
        },
      });
    });
    expect(hook.result.current).toEqual(new Map([['label-1', 'malicious'], ['label-2', 'benign']]));
  });

  it('labels an unresolvable id Restricted instead of showing the raw id', () => {
    const { relayEnv, hook } = renderLabels(label, ['deleted-id', 'hidden-id']);
    act(() => {
      relayEnv.mock.resolveMostRecentOperation({
        data: { filtersRepresentatives: [{ representativeId: 'hidden-id', value: null, entity_type: null, color: null }] },
      });
    });
    expect(hook.result.current).toEqual(new Map([['deleted-id', 'Restricted'], ['hidden-id', 'Restricted']]));
  });

  it('has no label while the representatives are loading', () => {
    const { hook } = renderLabels(label, ['label-1']);
    expect(hook.result.current.size).toBe(0);
  });

  it('labels a failed resolution Restricted', () => {
    const { relayEnv, hook } = renderLabels(label, ['label-1']);
    act(() => {
      relayEnv.mock.rejectMostRecentOperation(new Error('boom'));
    });
    expect(hook.result.current).toEqual(new Map([['label-1', 'Restricted']]));
  });

  it.each([
    ['text', ['Energy']],
    ['boolean', ['true']],
    ['vocabulary', ['high']],
  ] as const)('uses the value itself as label for a %s variable, without query', (type, values) => {
    const { relayEnv, hook } = renderLabels({ type, restriction: { mode: 'none' } }, [...values]);
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(hook.result.current).toEqual(new Map(values.map((v) => [v, v])));
  });

  it('labels an entityType variable value with the translated type name, without query', () => {
    const { relayEnv, hook } = renderLabels({ type: 'entityType', restriction: { mode: 'none' } }, ['Threat-Actor-Group', 'Malware']);
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(hook.result.current).toEqual(new Map([['Threat-Actor-Group', 'Threat Actor Group'], ['Malware', 'Malware']]));
  });

  it('does not query when there is no id to resolve', () => {
    const { relayEnv, hook } = renderLabels(label, ['']);
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(hook.result.current.size).toBe(0);
  });
});
