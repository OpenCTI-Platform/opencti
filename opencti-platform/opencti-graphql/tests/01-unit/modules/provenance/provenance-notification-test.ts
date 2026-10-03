import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { computeListeningTriggers, describeProvenanceChange } from '../../../../src/modules/provenance/provenance-notification';
import { computeProvenanceChange } from '../../../../src/modules/provenance/provenance-write';
import { resolveCorroborationThreshold } from '../../../../src/modules/notification/notification-domain';
import type { BasicStoreEntityTrigger } from '../../../../src/modules/notification/notification-types';
import type { StoreAssertion } from '../../../../src/modules/provenance/provenance-types';

const trigger = (id: string, overrides: Partial<BasicStoreEntityTrigger> = {}) => ({
  internal_id: id,
  trigger_type: 'live',
  trigger_scope: 'knowledge',
  event_types: ['corroboration'],
  ...overrides,
}) as BasicStoreEntityTrigger;

const assertion = (sourceId: string): StoreAssertion => ({
  source_id: sourceId,
  source_kind: 'connector',
  source_name: sourceId,
  first_asserted_at: '2026-01-01T00:00:00.000Z',
  last_asserted_at: '2026-01-01T00:00:00.000Z',
  assert_count: 1,
  confidence: 50,
  work_id: null,
});

const conflictValue = (hash: string) => ({
  value_hash: hash,
  display: hash,
  value: JSON.stringify(hash),
  source_id: 's',
  source_kind: 'connector' as const,
  source_name: 's',
  confidence: 50,
  last_asserted_at: '2026-01-01T00:00:00.000Z',
});

describe('Provenance triggers', () => {
  it('should fire corroboration triggers once, when the threshold is crossed', () => {
    const triggers = [
      trigger('default'),
      trigger('three', { corroboration_threshold: 3 }),
      trigger('digest', { trigger_type: 'digest' }),
      trigger('activity', { trigger_scope: 'activity' }),
      trigger('create', { event_types: ['create'] }),
    ];
    expect(Array.from(computeListeningTriggers(triggers, { corroboration: { from: 1, to: 2 } }).keys())).toEqual(['default']);
    expect(Array.from(computeListeningTriggers(triggers, { corroboration: { from: 2, to: 3 } }).keys())).toEqual(['three']);
    expect(computeListeningTriggers(triggers, { corroboration: { from: 3, to: 4 } }).size).toEqual(0);
    expect(computeListeningTriggers(triggers, {}).size).toEqual(0);
  });

  it('should fire conflict triggers when a source proposes a new value', () => {
    const triggers = [trigger('conflict', { event_types: ['conflict', 'corroboration'] })];
    expect(computeListeningTriggers(triggers, { conflictFields: [] }).size).toEqual(0);
    expect(computeListeningTriggers(triggers, { conflictFields: ['description'] }).get('conflict')).toEqual(['conflict']);
    expect(computeListeningTriggers(triggers, { conflictFields: ['description'], corroboration: { from: 1, to: 2 } }).get('conflict')).toEqual(['corroboration', 'conflict']);
    expect(describeProvenanceChange('conflict', { conflictFields: ['name', 'description'] })).toEqual('has conflicting values from sources on name, description');
    expect(describeProvenanceChange('corroboration', { corroboration: { from: 1, to: 2 } })).toEqual('is now corroborated by 2 sources');
  });

  it('should compute the corroboration and conflicts change of a write', () => {
    const element = {
      x_opencti_assertions: [assertion('a')],
      x_opencti_conflicts: [{ field: 'description', values: [conflictValue('known')] }],
    };
    expect(computeProvenanceChange(element, ['a'])).toEqual({ corroboration: undefined, conflictFields: [], newConflictValues: 0 });
    expect(computeProvenanceChange(element, ['b']).corroboration).toEqual({ from: 1, to: 2 });
    const conflicts = computeProvenanceChange(element, ['a'], [
      { field: 'description', value: conflictValue('known') },
      { field: 'description', value: conflictValue('new') },
      { field: 'name', value: conflictValue('other') },
    ]);
    expect(conflicts.conflictFields).toEqual(['description', 'name']);
    expect(conflicts.newConflictValues).toEqual(2);
  });

  it('should count every source, including the ones no longer detailed in the bounded assertions', () => {
    const manySources = Array.from({ length: 250 }, (_, index) => `source-${index}`);
    const element = { x_opencti_assertions: [assertion('source-249')], assertion_source_ids: manySources };
    expect(computeProvenanceChange(element, ['source-0']).corroboration).toBeUndefined();
    expect(computeProvenanceChange(element, ['source-250']).corroboration).toEqual({ from: 250, to: 251 });
  });

  it('should default and bound the corroboration threshold', () => {
    expect(resolveCorroborationThreshold(['create'], undefined)).toBeNull();
    expect(resolveCorroborationThreshold(['corroboration'], undefined)).toEqual(2);
    expect(resolveCorroborationThreshold(['corroboration'], 5)).toEqual(5);
    expect(() => resolveCorroborationThreshold(['corroboration'], 1)).toThrow();
    expect(() => resolveCorroborationThreshold(['corroboration'], 201)).toThrow();
  });
});
