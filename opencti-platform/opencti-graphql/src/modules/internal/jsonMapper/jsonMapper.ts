import { v4 as uuidv4 } from 'uuid';
import type { ModuleDefinition } from '../../../schema/module';
import { registerDefinition } from '../../../schema/module';
import type { StixJsonMapper, StoreEntityJsonMapper } from './jsonMapper-types';
import { ENTITY_TYPE_JSON_MAPPER } from './jsonMapper-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { normalizeName } from '../../../schema/identifier';
import convertJsonMapperToStix from './jsonMapper-converter';

const CSV_MAPPER_DEFINITION: ModuleDefinition<StoreEntityJsonMapper, StixJsonMapper> = {
  type: {
    id: 'jsonmapper',
    name: ENTITY_TYPE_JSON_MAPPER,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_JSON_MAPPER]: () => uuidv4()
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'variables', label: 'Variables', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'representations', label: 'Representations', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
  ],
  relations: [],
  representative: (instance: StixJsonMapper) => {
    return instance.name;
  },
  converter: convertJsonMapperToStix
};

registerDefinition(CSV_MAPPER_DEFINITION);
