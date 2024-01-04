import { v4 as uuidv4 } from 'uuid';
import { normalizeName } from '../../schema/identifier';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_INGESTION_RSS, type StixIngestionRss, type StoreEntityIngestionRss } from './ingestion-types';
import { convertIngestionRssToStix } from './ingestion-converter';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';

const INGESTION_RSS_DEFINITION: ModuleDefinition<StoreEntityIngestionRss, StixIngestionRss> = {
  type: {
    id: 'ingestion-rss',
    name: ENTITY_TYPE_INGESTION_RSS,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_INGESTION_RSS]: () => uuidv4(),
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'uri', label: 'URI', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    {
      name: 'user_id',
      label: 'User ID',
      type: 'string',
      format: 'id',
      entityTypes: [ENTITY_TYPE_USER],
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: true,
      isFilterable: true
    },
    { name: 'report_types', label: 'Report types', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'created_by_ref', label: 'Created by', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: false },
    { name: 'object_marking_refs', label: 'Marking', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: true, upsert: true, isFilterable: false },
    { name: 'current_state_date', label: 'Current state date', type: 'date', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'ingestion_running', label: 'Ingestion running', type: 'boolean', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixIngestionRss) => {
    return stix.name;
  },
  converter: convertIngestionRssToStix
};

registerDefinition(INGESTION_RSS_DEFINITION);
