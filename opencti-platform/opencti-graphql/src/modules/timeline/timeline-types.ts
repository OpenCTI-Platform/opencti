import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixInternal } from '../../types/stix-2-1-common';
import type { AuthorizedMember } from '../../utils/access';
import { ENTITY_TYPE_INCIDENT } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../case/case-incident/case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from '../case/case-rft/case-rft-types';

export { ENTITY_TYPE_TIMELINE_EVENT, ENTITY_TYPE_TIMELINE_SETTINGS } from './timeline-entity-types';

// Incident is a domain object whose knowledge is held by its relationships,
// the three case types are containers whose knowledge is held by their object refs.
// Dashboard widget of one incident or case timeline (its `container_id` parameter binds it to the case)
export const TIMELINE_WIDGET_TYPE = 'case-timeline';

export const TIMELINE_CONTAINER_TYPES = [
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
  ENTITY_TYPE_CONTAINER_CASE_RFI,
  ENTITY_TYPE_CONTAINER_CASE_RFT,
];
export const isTimelineContainerType = (type: string | undefined | null): boolean => {
  return !!type && TIMELINE_CONTAINER_TYPES.includes(type);
};

export const TIMELINE_LANES = ['adversary', 'evidence', 'response', 'knowledge', 'detection', 'custom'] as const;
export type TimelineLaneValue = typeof TIMELINE_LANES[number];

export const TIMELINE_PRECISIONS = ['exact', 'hour', 'day', 'approximate'] as const;
export type TimelinePrecisionValue = typeof TIMELINE_PRECISIONS[number];

export const TIMELINE_SOURCES = ['derived', 'manual'] as const;
export type TimelineSourceValue = typeof TIMELINE_SOURCES[number];

export const TIMELINE_MILESTONE_KINDS = ['milestone', 'containment', 'eradication', 'recovery', 'notification'] as const;

export const TIMELINE_KINDS = [
  // adversary
  'technique_used',
  'observed_window',
  'sighting',
  'infrastructure_seen',
  'malware_seen',
  'threat_seen',
  'incident_seen',
  // evidence
  'indicator_valid',
  'report_published',
  'reference_published',
  'file_uploaded',
  // response
  'case_opened',
  'task_created',
  'task_due',
  'task_completed',
  'status_changed',
  'assigned',
  'note_added',
  'opinion_added',
  'investigation_step',
  // knowledge
  'object_added',
  'relation_created',
  'merged',
  // detection and validation
  'coverage_result',
  'hunt_run',
  'deployment',
  // analyst milestones
  ...TIMELINE_MILESTONE_KINDS,
] as const;
export type TimelineKindValue = typeof TIMELINE_KINDS[number];

export const TIMELINE_GROUPINGS = ['hour', 'day', 'week'] as const;
export type TimelineGroupingValue = typeof TIMELINE_GROUPINGS[number];

export const TIMELINE_ZOOM_WINDOWS = ['fit', 'day', 'week', 'month', 'quarter', 'year'] as const;
export type TimelineZoomWindowValue = typeof TIMELINE_ZOOM_WINDOWS[number];

// Fields an analyst can set on any event, derived or manual. A regeneration of the
// derived events keeps the value of every field listed in `analyst_fields`.
export const TIMELINE_ANALYST_FIELDS = ['pinned', 'hidden', 'annotation', 'ordering_hint'] as const;
export type TimelineAnalystField = typeof TIMELINE_ANALYST_FIELDS[number];
// The analyst fields of a derived event that can be cleared (pins and hidden flags are booleans, never cleared)
export const TIMELINE_CLEARABLE_ANALYST_FIELDS = ['annotation', 'ordering_hint'] as const;
export type TimelineClearableAnalystField = typeof TIMELINE_CLEARABLE_ANALYST_FIELDS[number];

export const TIMELINE_ANCHOR_KEYS = ['first_adversary_activity', 'first_detection', 'first_response', 'containment', 'closure'] as const;
export type TimelineAnchorKey = typeof TIMELINE_ANCHOR_KEYS[number];

export const ATTRIBUTE_TIMELINE_ANCHORS = 'x_opencti_timeline_anchors';
export const ATTRIBUTE_TIMELINE_EXCHANGE = 'x_opencti_timeline';

export interface TimelineAnchors {
  first_adversary_activity: string | null;
  first_detection: string | null;
  first_response: string | null;
  containment: string | null;
  closure: string | null;
  computed_at: string;
  changed_at: string;
}

/** Anchor values of the derived events a capped timeline does not store, recorded by its regeneration. */
export type TimelineAnchorBounds = Pick<TimelineAnchors, TimelineAnchorKey>;

// region store
// The event title is stored in `name` so that the generic representative and
// full text search apply. description, confidence and external_id are
// inherited from BasicStoreEntity.
export interface BasicStoreEntityTimelineEvent extends BasicStoreEntity {
  container_id: string;
  event_time: string;
  event_end_time?: string | null;
  open_ended?: boolean | null;
  time_precision: TimelinePrecisionValue;
  lane: TimelineLaneValue;
  kind: TimelineKindValue;
  event_source: TimelineSourceValue;
  rule_id?: string | null;
  element_id?: string | null;
  element_type?: string | null;
  pinned: boolean;
  hidden: boolean;
  annotation?: string | null;
  ordering_hint?: number | null;
  analyst_fields?: TimelineAnalystField[];
  restricted_members?: Array<AuthorizedMember>;
  source_state?: TimelineSourceState | null;
  element_access?: TimelineElementAccess | null;
}

/**
 * Who reads the element of a derived event besides its markings (which the event carries), recorded by the regeneration:
 * once the element is deleted, it still decides who may learn of the removal of the event.
 */
export interface TimelineElementAccess {
  restricted_members: AuthorizedMember[];
  granted: string[];
  // The other elements whose data the derived event carries, each read like the element. Recorded with the access of
  // the element only: an event whose element cannot be resolved is read by nobody, whatever its sources.
  sources?: TimelineSourceAccess[];
}

/** An element whose data a derived event carries besides its element, with its access beyond markings (which the event carries). */
export interface TimelineSourceAccess {
  id: string;
  // Recorded while the source exists: once it is deleted, it is read as an element of this type
  entity_type?: string;
  restricted_members: AuthorizedMember[];
  granted: string[];
}

/**
 * State of the run, step or deployment a derived event comes from, as its owner stores it. The values stay raw: each
 * family is labelled by the vocabulary of its owner (investigation step states, hunt verdicts, deployment states).
 */
export interface TimelineSourceState {
  family: 'investigation_run' | 'investigation_step' | 'hunt_run' | 'deployment';
  state?: string | null;
  verdict?: string | null;
  validation?: string | null;
  // Investigation run and goal-plan action an investigation event belongs to
  run_id?: string | null;
  step?: string | null;
}

export interface StoreEntityTimelineEvent extends StoreEntity, BasicStoreEntityTimelineEvent {
}

export interface TimelinePendingAnnotation {
  event_id: string;
  pinned?: boolean;
  hidden?: boolean;
  annotation?: string | null;
  ordering_hint?: number | null;
  /** Highest confidence of a timeline event the importer of the annotation could change when importing it. */
  max_confidence?: number | null;
  /** User who imported the annotation: it applies to the event the derivation produces only when this user can read it. */
  importer_id?: string | null;
}

/**
 * A derived event the cap of its case leaves out while it carries analyst fields, recorded by the regeneration: its
 * annotation keeps travelling in the STIX exchange, checked like the stored events, until the event is within the cap again.
 */
export interface TimelineCappedAnnotatedEvent {
  internal_id: string;
  rule_id: string;
  kind: TimelineKindValue;
  element_id: string;
  markings: string[];
  element_access?: TimelineElementAccess | null;
  analyst_fields: TimelineAnalystField[];
  pinned: boolean;
  hidden: boolean;
  annotation?: string | null;
  ordering_hint?: number | null;
}

/** Settings and generation state of a container timeline, stored as the non-indexed `timeline_state` object. */
export interface TimelineSettingsState {
  enabled_lanes: TimelineLaneValue[];
  default_grouping: TimelineGroupingValue;
  default_zoom_window: TimelineZoomWindowValue;
  hidden_kinds: TimelineKindValue[];
  pending_annotations?: TimelinePendingAnnotation[];
  derivation_truncated?: boolean;
  capped_anchor_bounds?: TimelineAnchorBounds | null;
  capped_annotated_events?: TimelineCappedAnnotatedEvent[];
  generated_at?: string | null;
}

/** A settings document as loaded: its stored state is exposed flat, like the other attributes. */
export interface BasicStoreEntityTimelineSettings extends BasicStoreEntity, TimelineSettingsState {
  container_id: string;
  timeline_state?: Partial<TimelineSettingsState>;
}

export const TIMELINE_DEFAULT_SETTINGS = {
  enabled_lanes: [...TIMELINE_LANES] as TimelineLaneValue[],
  default_grouping: 'day' as TimelineGroupingValue,
  default_zoom_window: 'fit' as TimelineZoomWindowValue,
  hidden_kinds: [] as TimelineKindValue[],
};

export interface StoreEntityTimelineSettings extends StoreEntity, BasicStoreEntityTimelineSettings {
}
// endregion

// region stix
export interface StixTimelineEvent extends StixInternal {
  container_ref: string;
  event_time: string;
  event_end_time?: string;
  precision: TimelinePrecisionValue;
  lane: TimelineLaneValue;
  kind: TimelineKindValue;
  title: string;
  description?: string;
  source: TimelineSourceValue;
}

export interface StixTimelineSettings extends StixInternal {
  container_ref: string;
}

// Content of the timeline STIX extension carried by the timeline containers.
// Only analyst contributions travel: manual events and the annotations put on
// derived events. Derived events are recomputed by the receiving platform.
export interface StixTimelineExtensionEvent {
  id: string;
  external_id?: string;
  event_time: string;
  event_end_time?: string;
  precision: TimelinePrecisionValue;
  lane: TimelineLaneValue;
  kind: TimelineKindValue;
  title: string;
  description?: string;
  element_ref?: string;
  confidence?: number;
  ordering_hint?: number;
  pinned?: boolean;
  hidden?: boolean;
  annotation?: string;
  object_marking_refs?: string[];
  created_by_ref?: string;
}

export interface StixTimelineExtensionAnnotation {
  rule_id: string;
  kind: TimelineKindValue;
  element_ref: string;
  pinned?: boolean;
  hidden?: boolean;
  annotation?: string;
  ordering_hint?: number;
  // An absent field leaves the receiving event unchanged: the fields an analyst cleared are named, STIX has no null value
  cleared_fields?: TimelineClearableAnalystField[];
}

export interface StixTimelineExtension {
  extension_type: 'property-extension';
  events: StixTimelineExtensionEvent[];
  annotations: StixTimelineExtensionAnnotation[];
}

// Denormalized copy of the timeline STIX extension stored on the container
// (side channel, no stream event) so that every STIX conversion of the container
// carries the analyst contributions without an extra query.
export interface StoreTimelineExchange {
  events: StixTimelineExtensionEvent[];
  annotations: StixTimelineExtensionAnnotation[];
}
// endregion
