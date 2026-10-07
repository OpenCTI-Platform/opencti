import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type AttributeDefinition, authorizedMembers, type BasicStoreAttribute, type ObjectAttribute, type RawObjectAttribute } from '../../schema/attribute-definition';
import { createdBy, objectMarking } from '../../schema/stixRefRelationship';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import {
  ATTRIBUTE_TIMELINE_ANCHORS,
  ATTRIBUTE_TIMELINE_EXCHANGE,
  ENTITY_TYPE_TIMELINE_EVENT,
  ENTITY_TYPE_TIMELINE_SETTINGS,
  type StixTimelineEvent,
  type StixTimelineSettings,
  type StoreEntityTimelineEvent,
  type StoreEntityTimelineSettings,
  TIMELINE_ANALYST_FIELDS,
  TIMELINE_CONTAINER_TYPES,
  TIMELINE_KINDS,
  TIMELINE_LANES,
  TIMELINE_PRECISIONS,
  TIMELINE_SOURCES,
} from './timeline-types';
import { convertTimelineEventToStix, convertTimelineSettingsToStix } from './timeline-converter';

const containerIdAttribute: AttributeDefinition = {
  name: 'container_id',
  label: 'Timeline container',
  type: 'string',
  format: 'id',
  entityTypes: TIMELINE_CONTAINER_TYPES,
  mandatoryType: 'internal',
  editDefault: false,
  multiple: false,
  upsert: false,
  update: false,
  isFilterable: true,
};

const TIMELINE_EVENT_DEFINITION: ModuleDefinition<StoreEntityTimelineEvent, StixTimelineEvent> = {
  type: {
    id: 'timeline-event',
    name: ENTITY_TYPE_TIMELINE_EVENT,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      // Ids are computed by the timeline engine: deterministic for derived events, random for manual events.
      [ENTITY_TYPE_TIMELINE_EVENT]: () => uuidv4(),
    },
  },
  attributes: [
    containerIdAttribute,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'event_time', label: 'Event time', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'event_end_time', label: 'Event end time', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    // A window started without a known end (a run still running, a deployment still active): stored only when true
    { name: 'open_ended', label: 'Open-ended window', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: true },
    { name: 'time_precision', label: 'Time precision', type: 'string', format: 'enum', values: [...TIMELINE_PRECISIONS], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'lane', label: 'Timeline lane', type: 'string', format: 'enum', values: [...TIMELINE_LANES], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'kind', label: 'Timeline event kind', type: 'string', format: 'enum', values: [...TIMELINE_KINDS], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'event_source', label: 'Timeline event source', type: 'string', format: 'enum', values: [...TIMELINE_SOURCES], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: true },
    { name: 'rule_id', label: 'Timeline derivation rule', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: true },
    { name: 'element_id', label: 'Element ID', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'element_type', label: 'Timeline element type', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'pinned', label: 'Pinned on timeline', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'hidden', label: 'Hidden on timeline', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'annotation', label: 'Analyst annotation', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'confidence', label: 'Confidence', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'ordering_hint', label: 'Timeline ordering hint', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'analyst_fields', label: 'Timeline analyst fields', type: 'string', format: 'enum', values: [...TIMELINE_ANALYST_FIELDS], mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, update: false, isFilterable: false },
    { name: 'external_id', label: 'External id', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: true },
    // State of the run, step or deployment an event comes from, only read with the event: not indexed
    { name: 'source_state', label: 'Timeline source state', type: 'object', format: 'raw', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: false },
    { name: 'element_access', label: 'Timeline element access', type: 'object', format: 'raw', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: false },
    authorizedMembers,
  ],
  relations: [],
  relationsRefs: [{ ...createdBy, mandatoryType: 'no' }, objectMarking],
  representative: (stix: StixTimelineEvent) => stix.title,
  converter_2_1: convertTimelineEventToStix,
};
registerDefinition(TIMELINE_EVENT_DEFINITION);

const TIMELINE_SETTINGS_DEFINITION: ModuleDefinition<StoreEntityTimelineSettings, StixTimelineSettings> = {
  type: {
    id: 'timeline-settings',
    name: ENTITY_TYPE_TIMELINE_SETTINGS,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_TIMELINE_SETTINGS]: () => uuidv4(),
    },
  },
  attributes: [
    containerIdAttribute,
    // Settings, pending annotations and generation state are only read with their container: one non-indexed object
    { name: 'timeline_state', label: 'Timeline settings and state', type: 'object', format: 'raw', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, update: false, isFilterable: false },
    authorizedMembers,
  ],
  relations: [],
  representative: (stix: StixTimelineSettings) => stix.name,
  converter_2_1: convertTimelineSettingsToStix,
};
registerDefinition(TIMELINE_SETTINGS_DEFINITION);

// region attributes carried by the timeline containers (written through the side channel, never by users)
export const timelineAnchorsAttribute: ObjectAttribute = {
  name: ATTRIBUTE_TIMELINE_ANCHORS,
  label: 'Timeline anchors',
  type: 'object',
  format: 'standard',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  update: false,
  isFilterable: true,
  mappings: [
    { name: 'first_adversary_activity', label: 'First adversary activity', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'first_detection', label: 'First detection', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'first_response', label: 'First response', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'containment', label: 'Containment', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'closure', label: 'Closure', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'computed_at', label: 'Timeline anchors computed at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'changed_at', label: 'Timeline anchors changed at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  sortBy: { path: `${ATTRIBUTE_TIMELINE_ANCHORS}.first_adversary_activity`, type: 'date' },
};

// Holds a StoreTimelineExchange, stored but not indexed
export const timelineExchangeAttribute: RawObjectAttribute<BasicStoreAttribute> = {
  name: ATTRIBUTE_TIMELINE_EXCHANGE,
  label: 'Timeline contributions',
  type: 'object',
  format: 'raw',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: false,
  update: false,
  isFilterable: false,
};

TIMELINE_CONTAINER_TYPES.forEach((type) => {
  schemaAttributesDefinition.registerAttributes(type, [timelineAnchorsAttribute, timelineExchangeAttribute]);
});
// endregion
