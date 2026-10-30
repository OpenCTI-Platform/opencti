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
    expect(hook.result.current.labels).toEqual(new Map([['label-1', 'malicious'], ['label-2', 'benign']]));
    expect(hook.result.current.restricted.size).toBe(0);
  });

  it('labels an unresolvable id Restricted instead of showing the raw id', () => {
    const { relayEnv, hook } = renderLabels(label, ['deleted-id', 'hidden-id']);
    act(() => {
      relayEnv.mock.resolveMostRecentOperation({
        data: { filtersRepresentatives: [{ representativeId: 'hidden-id', value: null, entity_type: null, color: null }] },
      });
    });
    expect(hook.result.current.labels).toEqual(new Map([['deleted-id', 'Restricted'], ['hidden-id', 'Restricted']]));
    expect(hook.result.current.restricted).toEqual(new Set(['deleted-id', 'hidden-id']));
  });

  it('does not flag as restricted an entity that is really named Restricted', () => {
    const { relayEnv, hook } = renderLabels(label, ['named-id', 'deleted-id']);
    act(() => {
      relayEnv.mock.resolveMostRecentOperation({
        data: { filtersRepresentatives: [{ representativeId: 'named-id', value: 'Restricted', entity_type: 'Label', color: null }] },
      });
    });
    expect(hook.result.current.labels).toEqual(new Map([['named-id', 'Restricted'], ['deleted-id', 'Restricted']]));
    expect(hook.result.current.restricted).toEqual(new Set(['deleted-id']));
  });

  describe('kill chain phase', () => {
    const phase: DashboardVariableShape = { type: 'killChainPhase', killChainName: 'mitre-attack', restriction: { mode: 'none' } };
    const resolvePhases = (relayEnv: ReturnType<typeof renderLabels>['relayEnv'], representatives: Record<string, string>) => act(() => {
      relayEnv.mock.resolveMostRecentOperation({
        data: {
          filtersRepresentatives: Object.entries(representatives)
            .map(([representativeId, value]) => ({ representativeId, value, entity_type: 'Kill-Chain-Phase', color: null })),
        },
      });
    });

    it('labels a phase `[kill chain] phase`, as the options of the value input are', () => {
      const { relayEnv, hook } = renderLabels(phase, ['phase-1']);
      resolvePhases(relayEnv, { 'phase-1': 'persistence' });
      expect(hook.result.current.labels).toEqual(new Map([['phase-1', '[mitre-attack] persistence']]));
      expect(hook.result.current.restricted.size).toBe(0);
    });

    it('does not prefix a label that already carries its kill chain', () => {
      const { relayEnv, hook } = renderLabels(phase, ['phase-1']);
      resolvePhases(relayEnv, { 'phase-1': '[mitre-attack] persistence' });
      expect(hook.result.current.labels).toEqual(new Map([['phase-1', '[mitre-attack] persistence']]));
    });

    it('keeps Restricted unprefixed for a phase that cannot be resolved', () => {
      const { relayEnv, hook } = renderLabels(phase, ['gone-id']);
      resolvePhases(relayEnv, {});
      expect(hook.result.current.labels).toEqual(new Map([['gone-id', 'Restricted']]));
      expect(hook.result.current.restricted).toEqual(new Set(['gone-id']));
    });

    it('labels a phase of a variable without kill chain name by its name alone', () => {
      const { relayEnv, hook } = renderLabels({ type: 'killChainPhase', restriction: { mode: 'none' } }, ['phase-1']);
      resolvePhases(relayEnv, { 'phase-1': 'persistence' });
      expect(hook.result.current.labels).toEqual(new Map([['phase-1', 'persistence']]));
    });
  });

  it('has no label while the representatives are loading', () => {
    const { hook } = renderLabels(label, ['label-1']);
    expect(hook.result.current.labels.size).toBe(0);
    expect(hook.result.current.restricted.size).toBe(0);
  });

  it('labels a failed resolution Restricted', () => {
    const { relayEnv, hook } = renderLabels(label, ['label-1']);
    act(() => {
      relayEnv.mock.rejectMostRecentOperation(new Error('boom'));
    });
    expect(hook.result.current.labels).toEqual(new Map([['label-1', 'Restricted']]));
    expect(hook.result.current.restricted).toEqual(new Set(['label-1']));
  });

  it.each([
    ['text', ['Energy']],
    ['boolean', ['true']],
    ['vocabulary', ['high']],
  ] as const)('uses the value itself as label for a %s variable, without query', (type, values) => {
    const { relayEnv, hook } = renderLabels({ type, restriction: { mode: 'none' } }, [...values]);
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(hook.result.current.labels).toEqual(new Map(values.map((v) => [v, v])));
    expect(hook.result.current.restricted.size).toBe(0);
  });

  it('labels an entityType variable value with the translated type name, without query', () => {
    const { relayEnv, hook } = renderLabels({ type: 'entityType', restriction: { mode: 'none' } }, ['Threat-Actor-Group', 'Malware']);
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(hook.result.current.labels).toEqual(new Map([['Threat-Actor-Group', 'Threat Actor Group'], ['Malware', 'Malware']]));
  });

  it('does not query when there is no id to resolve', () => {
    const { relayEnv, hook } = renderLabels(label, ['']);
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(hook.result.current.labels.size).toBe(0);
  });
});
