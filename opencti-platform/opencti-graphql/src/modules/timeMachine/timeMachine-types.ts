import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_KNOWLEDGE_SNAPSHOT = 'Knowledge-Snapshot';
export const ENTITY_TYPE_USER_VISIT = 'User-Visit';

// Raw values of every attribute, keyed by attribute name (input name for references).
// Values use the exact raw encoding of history changes (internal ids for references,
// ISO strings for dates, JSON strings for objects) so history changes can be reversed on it.
export type AttributeValues = Record<string, string[]>;

export interface CompactDocument {
  attributes: AttributeValues;
  // Relationship ids by relationship type, capped per type (see snapshot_manager:max_relationship_ids_per_type)
  relationships: Record<string, string[]>;
  // Exact relationship counts by relationship type
  relationships_count: Record<string, number>;
}

// region Knowledge snapshot
export interface BasicStoreEntityKnowledgeSnapshot extends BasicStoreEntity {
  entity_id: string;
  target_entity_type: string;
  snapshot_date: string;
  history_cursor: string;
  snapshot_document: CompactDocument;
}

export interface StoreEntityKnowledgeSnapshot extends StoreEntity {
  entity_id: string;
  target_entity_type: string;
  snapshot_date: string;
  history_cursor: string;
  snapshot_document: CompactDocument;
}

export interface StixKnowledgeSnapshot extends StixObject {
  entity_id: string;
  target_entity_type: string;
  snapshot_date: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region User visit
export interface BasicStoreEntityUserVisit extends BasicStoreEntity {
  user_id: string;
  entity_id: string;
  target_entity_type: string;
  last_seen_at: string;
  previous_seen_at?: string;
}

export interface StoreEntityUserVisit extends StoreEntity {
  user_id: string;
  entity_id: string;
  target_entity_type: string;
  last_seen_at: string;
  previous_seen_at?: string;
}

export interface StixUserVisit extends StixObject {
  user_id: string;
  entity_id: string;
  last_seen_at: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region History events used for replay and diffs
export interface HistoryChangeValue {
  raw: string;
  translated?: string;
}

export interface HistoryChange {
  field: string;
  changes_added?: HistoryChangeValue[];
  changes_removed?: HistoryChangeValue[];
}

export type HistoryEventScope = 'create' | 'update' | 'delete' | 'merge' | string;

export interface TimeMachineHistoryEvent {
  id: string;
  timestamp: string;
  event_scope: HistoryEventScope;
  user_id?: string;
  context_id: string;
  context_entity_type: string;
  context_entity_name: string;
  from_id?: string;
  to_id?: string;
  message?: string;
  changes: HistoryChange[];
}
// endregion

// region Replay
export interface ReplayResult {
  document: AttributeValues;
  exists: boolean;
  complete: boolean;
  warnings: string[];
  replayedEvents: number;
}

export interface AttributeDelta {
  key: string;
  before: string[];
  after: string[];
  added: string[];
  removed: string[];
}
// endregion

// region Relationship changes
export type RelationshipChangeAction = 'added' | 'removed' | 'revoked' | 'unrevoked' | 'confidence_changed';

export interface RelationshipChange {
  relationship_id: string;
  relationship_type: string;
  action: RelationshipChangeAction;
  at: string;
  is_source: boolean;
  target_id: string | null;
  target_type: string | null;
  target_name: string;
  target_deleted: boolean;
  target_restricted: boolean;
  confidence_before: number | null;
  confidence_after: number | null;
  changed_by: string | null;
}

export interface ContainerObjectChange {
  object_id: string;
  object_type: string | null;
  object_name: string;
  action: 'added' | 'removed';
  at: string | null;
  deleted: boolean;
  restricted: boolean;
}
// endregion

// region Landscape diff
export type LandscapeDiffStatus = 'pending' | 'running' | 'complete' | 'failed';

export interface LandscapeDiffInputData {
  filters?: string | null;
  saved_filter_id?: string | null;
  custom_view_id?: string | null;
  entity_types?: string[] | null;
  from: string;
  to: string;
  group_by?: string | null;
}

export interface LandscapeDiffBucket {
  key: string;
  label: string;
  count: number;
}

export interface LandscapeDiffNamedItem {
  id: string;
  // Optional: results computed before these fields existed are still served from the cache
  standard_id?: string | null;
  entity_type: string;
  name: string;
  // ATT&CK external id, techniques only
  x_mitre_id?: string | null;
  count: number;
}

export interface LandscapeDiffEntitySummary {
  entity_id: string;
  standard_id?: string | null;
  entity_type: string;
  name: string;
  created_in_period: boolean;
  revoked_in_period: boolean;
  attributes_changed: number;
  relationships_added: number;
  relationships_removed: number;
  relationships_revoked: number;
  relationships_confidence_changed: number;
  confidence_before: number | null;
  confidence_after: number | null;
  score_before: number | null;
  score_after: number | null;
  change_score: number;
}

export interface LandscapeDiffAggregates {
  entities_in_scope: number;
  entities_changed: number;
  new_entities: number;
  new_entities_by_type: LandscapeDiffBucket[];
  new_relationships: number;
  new_relationships_by_type: LandscapeDiffBucket[];
  removed_relationships: number;
  revocations: number;
  confidence_changes: number;
  score_changes: number;
  new_techniques_by_tactic: LandscapeDiffBucket[];
  // The named lists keep the most frequent items only, the counts are the totals
  new_techniques: LandscapeDiffNamedItem[];
  new_techniques_count: number;
  new_malware: LandscapeDiffNamedItem[];
  new_malware_count: number;
  new_tools: LandscapeDiffNamedItem[];
  new_tools_count: number;
  new_victims_by_sector: LandscapeDiffBucket[];
  new_victims_by_country: LandscapeDiffBucket[];
  new_victims_by_region: LandscapeDiffBucket[];
  new_infrastructure: LandscapeDiffNamedItem[];
  new_infrastructure_count: number;
  new_indicators_count: number;
  groups: LandscapeDiffBucket[];
}

export interface LandscapeDiffState {
  id: string;
  user_id: string;
  // Rights the result was computed with: a result is never returned once the rights of its user changed
  access_fingerprint: string;
  status: LandscapeDiffStatus;
  progress: number;
  total: number;
  input: LandscapeDiffInputData;
  scope_entity_types: string[];
  created_at: string;
  updated_at: string;
  expires_at: string;
  error: string | null;
  truncated: boolean;
  aggregates: LandscapeDiffAggregates | null;
  entities: LandscapeDiffEntitySummary[];
}
// endregion
