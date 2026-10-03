import { STIX_CORE_RELATIONSHIPS } from '../../schema/stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { utcDate } from '../../utils/format';
import { changeFieldKey, firstNumber } from './timeMachine-replay';
import type { TimeMachineHistoryEvent } from './timeMachine-types';

export const TIME_MACHINE_RELATIONSHIP_TYPES = [...STIX_CORE_RELATIONSHIPS, STIX_SIGHTING_RELATIONSHIP];

export interface RelationshipEventState {
  relationship_type: string;
  from_id?: string;
  to_id?: string;
  name: string;
  created?: string;
  deleted?: string;
  revoked_before?: string;
  revoked_after?: string;
  revoked_at?: string;
  confidence_before?: number | null;
  confidence_after?: number | null;
  confidence_at?: string;
  user_id?: string;
}

/**
 * Fold the history events of relationships into one state per relationship:
 * creation and deletion dates, first and last revocation flag and confidence of the period.
 */
export const buildRelationshipStates = (events: TimeMachineHistoryEvent[]) => {
  const states = new Map<string, RelationshipEventState>();
  const ascending = [...events].sort((a, b) => utcDate(a.timestamp).diff(utcDate(b.timestamp)));
  for (let index = 0; index < ascending.length; index += 1) {
    const event = ascending[index];
    const state = states.get(event.context_id) ?? {
      relationship_type: event.context_entity_type,
      from_id: event.from_id,
      to_id: event.to_id,
      name: event.context_entity_name,
    };
    state.user_id = event.user_id;
    if (event.event_scope === 'create') state.created = event.timestamp;
    if (event.event_scope === 'delete') state.deleted = event.timestamp;
    if (event.event_scope === 'update') {
      (event.changes ?? []).forEach((change) => {
        const key = changeFieldKey(change.field);
        const added = (change.changes_added ?? []).map((v) => v.raw);
        const removed = (change.changes_removed ?? []).map((v) => v.raw);
        if (key === 'revoked') {
          if (state.revoked_before === undefined) state.revoked_before = removed[0] ?? 'false';
          state.revoked_after = added[0] ?? 'false';
          state.revoked_at = event.timestamp;
        }
        if (key === 'confidence') {
          if (state.confidence_before === undefined) state.confidence_before = firstNumber(removed);
          state.confidence_after = firstNumber(added);
          state.confidence_at = event.timestamp;
        }
      });
    }
    states.set(event.context_id, state);
  }
  return states;
};
