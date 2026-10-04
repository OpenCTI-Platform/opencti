import { describe, expect, it } from 'vitest';
import { buildRelationshipStates, relationshipStateActions } from '../../../../src/modules/timeMachine/timeMachine-relationships';
import type { TimeMachineHistoryEvent } from '../../../../src/modules/timeMachine/timeMachine-types';

const relationshipEvent = (
  id: string,
  timestamp: string,
  scope: string,
  changes: Array<{ key: string; added?: string[]; removed?: string[] }> = [],
  userId = 'user-1',
): TimeMachineHistoryEvent => ({
  id: `${id}-${timestamp}`,
  timestamp,
  event_scope: scope,
  user_id: userId,
  context_id: id,
  context_entity_type: 'uses',
  context_entity_name: 'APT uses Mimikatz',
  from_id: 'source-id',
  to_id: 'target-id',
  changes: changes.map(({ key, added = [], removed = [] }) => ({
    field: `uses--${key}`,
    changes_added: added.map((raw) => ({ raw })),
    changes_removed: removed.map((raw) => ({ raw })),
  })),
});

describe('Time machine relationship states', () => {
  it('should fold creations, deletions, revocations and confidence changes per relationship', () => {
    const states = buildRelationshipStates([
      relationshipEvent('rel-deleted', '2026-02-02T00:00:00.000Z', 'delete'),
      relationshipEvent('rel-transient', '2026-02-01T00:00:00.000Z', 'create'),
      relationshipEvent('rel-transient', '2026-02-03T00:00:00.000Z', 'delete'),
      relationshipEvent('rel-revoked', '2026-02-04T00:00:00.000Z', 'update', [{ key: 'revoked', added: ['true'], removed: ['false'] }]),
      relationshipEvent('rel-confidence', '2026-02-05T00:00:00.000Z', 'update', [{ key: 'confidence', added: ['60'], removed: ['40'] }]),
      relationshipEvent('rel-confidence', '2026-02-06T00:00:00.000Z', 'update', [{ key: 'confidence', added: ['90'], removed: ['60'] }]),
    ]);
    expect(states.get('rel-deleted')?.deleted).toEqual('2026-02-02T00:00:00.000Z');
    expect(states.get('rel-deleted')?.created).toBeUndefined();
    expect(states.get('rel-transient')?.created).toBeDefined();
    expect(states.get('rel-transient')?.deleted).toBeDefined();
    expect(states.get('rel-revoked')?.revoked_before).toEqual('false');
    expect(states.get('rel-revoked')?.revoked_after).toEqual('true');
    // First value of the period before, last value of the period after
    expect(states.get('rel-confidence')?.confidence_before).toEqual(40);
    expect(states.get('rel-confidence')?.confidence_after).toEqual(90);
    expect(states.get('rel-confidence')?.from_id).toEqual('source-id');
    expect(states.get('rel-confidence')?.relationship_type).toEqual('uses');
  });

  it('should process events in chronological order whatever their input order', () => {
    const states = buildRelationshipStates([
      relationshipEvent('rel', '2026-02-06T00:00:00.000Z', 'update', [{ key: 'confidence', added: ['90'], removed: ['60'] }]),
      relationshipEvent('rel', '2026-02-05T00:00:00.000Z', 'update', [{ key: 'confidence', added: ['60'], removed: ['40'] }]),
    ]);
    expect(states.get('rel')?.confidence_before).toEqual(40);
    expect(states.get('rel')?.confidence_after).toEqual(90);
    expect(states.get('rel')?.confidence_at).toEqual('2026-02-06T00:00:00.000Z');
  });

  it('should attribute each kind of change to its own author', () => {
    const states = buildRelationshipStates([
      relationshipEvent('rel', '2026-02-01T00:00:00.000Z', 'update', [{ key: 'revoked', added: ['true'], removed: ['false'] }], 'revoker'),
      relationshipEvent('rel', '2026-02-02T00:00:00.000Z', 'update', [{ key: 'confidence', added: ['80'], removed: ['50'] }], 'analyst'),
      relationshipEvent('rel', '2026-02-03T00:00:00.000Z', 'update', [{ key: 'description', added: ['new'], removed: ['old'] }], 'editor'),
      relationshipEvent('rel-deleted', '2026-02-01T00:00:00.000Z', 'create', [], 'creator'),
      relationshipEvent('rel-deleted', '2026-02-04T00:00:00.000Z', 'delete', [], 'deleter'),
    ]);
    expect(states.get('rel')?.revoked_by).toEqual('revoker');
    expect(states.get('rel')?.confidence_by).toEqual('analyst');
    expect(states.get('rel')?.deleted_by).toBeUndefined();
    expect(states.get('rel-deleted')?.created_by).toEqual('creator');
    expect(states.get('rel-deleted')?.deleted_by).toEqual('deleter');
  });

  it('should keep the revocation and confidence changes of a relationship created in the period', () => {
    const states = buildRelationshipStates([
      relationshipEvent('rel-new', '2026-02-01T00:00:00.000Z', 'create'),
      relationshipEvent('rel-new', '2026-02-02T00:00:00.000Z', 'update', [{ key: 'revoked', added: ['true'], removed: ['false'] }]),
      relationshipEvent('rel-new', '2026-02-03T00:00:00.000Z', 'update', [{ key: 'confidence', added: ['80'], removed: ['50'] }]),
      relationshipEvent('rel-transient', '2026-02-01T00:00:00.000Z', 'create'),
      relationshipEvent('rel-transient', '2026-02-02T00:00:00.000Z', 'update', [{ key: 'revoked', added: ['true'], removed: ['false'] }]),
      relationshipEvent('rel-transient', '2026-02-03T00:00:00.000Z', 'delete'),
      relationshipEvent('rel-old', '2026-02-04T00:00:00.000Z', 'delete'),
    ]);
    // Listed as added, then revoked and re-rated after its creation
    expect(relationshipStateActions(states.get('rel-new')!, true)).toEqual(['revoked', 'confidence_changed']);
    // Created in the period but not visible anymore: never described
    expect(relationshipStateActions(states.get('rel-new')!, false)).toEqual([]);
    // Created, revoked and deleted in the period: no net change
    expect(relationshipStateActions(states.get('rel-transient')!, false)).toEqual([]);
    expect(relationshipStateActions(states.get('rel-old')!, false)).toEqual(['removed']);
  });
});
