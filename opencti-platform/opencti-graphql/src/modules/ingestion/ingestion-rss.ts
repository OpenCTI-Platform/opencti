import { v4 as uuidv4 } from 'uuid';
import { normalizeName } from '../../schema/identifier';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_INGESTION_RSS, type StixIngestionRss, type StoreEntityIngestionRss } from './ingestion-types';
import { convertIngestionRssToStix } from './ingestion-converter';
import ingestionTypeDefs from './ingestion-rss.graphql';
import ingestionRssResolvers from './ingestion-rss-resolver';

const INGESTION_RSS_DEFINITION: ModuleDefinition<StoreEntityIngestionRss, StixIngestionRss> = {
  type: {
    id: 'ingestion-rss',
    name: ENTITY_TYPE_INGESTION_RSS,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  graphql: {
    schema: ingestionTypeDefs,
    resolver: ingestionRssResolvers,
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
    { name: 'name', label: 'Name', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'uri', label: 'URI', type: 'string', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'user_id', label: 'User ID', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'report_types', label: 'Report types', type: 'string', mandatoryType: 'external', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'created_by_ref', label: 'Created by', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: false },
    { name: 'object_marking_refs', label: 'Marking', type: 'string', mandatoryType: 'external', editDefault: true, multiple: true, upsert: true, isFilterable: false },
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
