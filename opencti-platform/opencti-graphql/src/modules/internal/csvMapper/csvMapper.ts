import type { ModuleDefinition } from '../../../schema/module';
import { registerDefinition } from '../../../schema/module';
import type { StixCsvMapper, StoreEntityCsvMapper } from './csvMapper-types';
import { ENTITY_TYPE_CSV_MAPPER } from './csvMapper-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import csvMapperTypeDefs from './csvMapper.graphql';
import csvMapperResolvers from './csvMapper-resolvers';
import { NAME_FIELD, normalizeName } from '../../../schema/identifier';
import convertCsvMapperToStix from './csvMapper-converter';

const CSV_MAPPER_DEFINITION: ModuleDefinition<StoreEntityCsvMapper, StixCsvMapper> = {
  type: {
    id: 'csvmapper',
    name: ENTITY_TYPE_CSV_MAPPER,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  graphql: {
    schema: csvMapperTypeDefs,
    resolver: csvMapperResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CSV_MAPPER]: [{ src: NAME_FIELD }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', type: 'string', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'has_header', type: 'boolean', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'separator', type: 'string', mandatoryType: 'internal', multiple: false, upsert: false },
    { name: 'representations', type: 'json', mandatoryType: 'internal', multiple: false, upsert: false },
  ],
  relations: [],
  representative: (instance: StixCsvMapper) => {
    return instance.name;
  },
  converter: convertCsvMapperToStix
};

registerDefinition(CSV_MAPPER_DEFINITION);
