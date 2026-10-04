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
  // Author of each kind of change: a relationship revoked by one user and updated by another later keeps both
  created_by?: string;
  deleted_by?: string;
  revoked_by?: string;
  confidence_by?: string;
}

/**
 * Fold the history events of relationships into one state per relationship:
 * creation and deletion dates, first and last revocation flag and confidence of the period,
 * with the author of the last change of each kind.
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
    if (event.event_scope === 'create') {
      state.created = event.timestamp;
      state.created_by = event.user_id;
    }
    if (event.event_scope === 'delete') {
      state.deleted = event.timestamp;
      state.deleted_by = event.user_id;
    }
    if (event.event_scope === 'update') {
      (event.changes ?? []).forEach((change) => {
        const key = changeFieldKey(change.field);
        const added = (change.changes_added ?? []).map((v) => v.raw);
        const removed = (change.changes_removed ?? []).map((v) => v.raw);
        if (key === 'revoked') {
          if (state.revoked_before === undefined) state.revoked_before = removed[0] ?? 'false';
          state.revoked_after = added[0] ?? 'false';
          state.revoked_at = event.timestamp;
          state.revoked_by = event.user_id;
        }
        if (key === 'confidence') {
          if (state.confidence_before === undefined) state.confidence_before = firstNumber(removed);
          state.confidence_after = firstNumber(added);
          state.confidence_at = event.timestamp;
          state.confidence_by = event.user_id;
        }
      });
    }
    states.set(event.context_id, state);
  }
  return states;
};

export type RelationshipStateAction = 'removed' | 'revoked' | 'unrevoked' | 'confidence_changed';

/**
 * Changes of a relationship during a period, from its folded state, besides its creation.
 * `listedAsAdded`: the relationship was created in the period and is still visible, so it is listed as added; its
 * later revocation and confidence changes follow, measured from its values at creation. A relationship created and
 * deleted in the period made no net change, one created in the period but not visible anymore is never described.
 */
export const relationshipStateActions = (state: RelationshipEventState, listedAsAdded: boolean): RelationshipStateAction[] => {
  if (state.created && state.deleted) return [];
  if (state.deleted) return ['removed'];
  if (state.created && !listedAsAdded) return [];
  const actions: RelationshipStateAction[] = [];
  if (state.revoked_after !== undefined && state.revoked_before !== state.revoked_after) {
    actions.push(state.revoked_after === 'true' ? 'revoked' : 'unrevoked');
  }
  if (state.confidence_after !== undefined && state.confidence_before !== state.confidence_after) {
    actions.push('confidence_changed');
  }
  return actions;
};
