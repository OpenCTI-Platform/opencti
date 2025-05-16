import { v4 as uuidv4 } from 'uuid';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_PIR, type StixPIR, type StoreEntityPIR } from './pir-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import convertEntityPIRToStix from './pir-converter';
import { createdAt, creators, updatedAt } from '../../schema/attribute-definition';

const ENTITY_PIR_DEFINITION: ModuleDefinition<StoreEntityPIR, StixPIR> = {
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
    { name: 'pirCriteria', label: 'PIR Criteria', type: 'object', format: 'flat', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'pirFilters', label: 'PIR Filters', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'lastEventId', label: 'Last event id', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (stix: StixPIR) => stix.name,
  converter_2_1: convertEntityPIRToStix
};

registerDefinition(ENTITY_PIR_DEFINITION);
