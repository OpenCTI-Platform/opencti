import { v4 as uuidv4 } from 'uuid';
import { normalizeName } from '../../schema/identifier';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_INGESTION, StixIngestion, StoreEntityIngestion } from './ingestion-types';
import { convertIngestionToStix } from './ingestion-converter';
import ingestionTypeDefs from './ingestion.graphql';
import ingestionResolvers from './ingestion-resolver';

const INGESTION_DEFINITION: ModuleDefinition<StoreEntityIngestion, StixIngestion> = {
  type: {
    id: 'ingestion',
    name: ENTITY_TYPE_INGESTION,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  graphql: {
    schema: ingestionTypeDefs,
    resolver: ingestionResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_INGESTION]: () => uuidv4(),
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'uri', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'user_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'report_types', type: 'string', mandatoryType: 'external', multiple: true, upsert: true },
    { name: 'created_by_ref', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'object_marking_refs', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'current_state_date', type: 'date', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'ingestion_running', type: 'boolean', mandatoryType: 'external', multiple: false, upsert: true },
  ],
  relations: [],
  representative: (stix: StixIngestion) => {
    return stix.name;
  },
  converter: convertIngestionToStix
};

registerDefinition(INGESTION_DEFINITION);
