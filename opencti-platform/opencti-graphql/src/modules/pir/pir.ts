import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_PIR, type StixPir, type StoreEntityPir } from './pir-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import convertEntityPirToStix from './pir-converter';
import { createdAt, creators, updatedAt } from '../../schema/attribute-definition';
import { isFeatureEnabled } from '../../config/conf';

const ENTITY_PIR_DEFINITION: ModuleDefinition<StoreEntityPir, StixPir> = {
  type: {
    id: 'pir',
    name: ENTITY_TYPE_PIR,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_PIR]: () => uuidv4()
    },
  },
  attributes: [
    createdAt,
    updatedAt,
    creators,
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'pirCriteria', label: 'Pir Criteria', type: 'object', format: 'flat', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'pirFilters', label: 'Pir Filters', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'lastEventId', label: 'Last event id', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixPir) => stix.name,
  converter_2_1: convertEntityPirToStix
};

if (isFeatureEnabled('Pir')) registerDefinition(ENTITY_PIR_DEFINITION);
