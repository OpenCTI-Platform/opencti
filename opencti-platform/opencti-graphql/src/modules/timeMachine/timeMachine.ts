import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_INTERNAL_OBJECT, ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import {
  ENTITY_TYPE_KNOWLEDGE_SNAPSHOT,
  ENTITY_TYPE_USER_VISIT,
  type StixKnowledgeSnapshot,
  type StixUserVisit,
  type StoreEntityKnowledgeSnapshot,
  type StoreEntityUserVisit,
} from './timeMachine-types';
import { convertKnowledgeSnapshotToStix, convertUserVisitToStix } from './timeMachine-converter';

const KNOWLEDGE_SNAPSHOT_DEFINITION: ModuleDefinition<StoreEntityKnowledgeSnapshot, StixKnowledgeSnapshot> = {
  type: {
    id: 'knowledgeSnapshots',
    name: ENTITY_TYPE_KNOWLEDGE_SNAPSHOT,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_KNOWLEDGE_SNAPSHOT]: () => uuidv4(),
    },
  },
  attributes: [
    {
      name: 'entity_id',
      label: 'Snapshot entity',
      type: 'string',
      format: 'id',
      entityTypes: [ABSTRACT_STIX_CORE_OBJECT],
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
    },
    { name: 'target_entity_type', label: 'Snapshot entity type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'snapshot_date', label: 'Snapshot date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'history_cursor', label: 'History cursor', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    // Compact document (raw attribute values and relationship ids), never indexed
    { name: 'snapshot_document', label: 'Snapshot document', type: 'object', format: 'raw', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixKnowledgeSnapshot) => {
    return `${stix.entity_id} @ ${stix.snapshot_date}`;
  },
  converter_2_1: convertKnowledgeSnapshotToStix,
};
registerDefinition(KNOWLEDGE_SNAPSHOT_DEFINITION);

const USER_VISIT_DEFINITION: ModuleDefinition<StoreEntityUserVisit, StixUserVisit> = {
  type: {
    id: 'userVisits',
    name: ENTITY_TYPE_USER_VISIT,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_USER_VISIT]: () => uuidv4(),
    },
  },
  attributes: [
    {
      name: 'user_id',
      label: 'User',
      type: 'string',
      format: 'id',
      entityTypes: [ENTITY_TYPE_USER],
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
    },
    {
      name: 'entity_id',
      label: 'Visited entity',
      type: 'string',
      format: 'id',
      entityTypes: [ABSTRACT_STIX_CORE_OBJECT],
      mandatoryType: 'internal',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
    },
    { name: 'target_entity_type', label: 'Visited entity type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'last_seen_at', label: 'Last seen at', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'previous_seen_at', label: 'Previously seen at', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixUserVisit) => {
    return `${stix.user_id} @ ${stix.entity_id}`;
  },
  converter_2_1: convertUserVisitToStix,
};
registerDefinition(USER_VISIT_DEFINITION);
