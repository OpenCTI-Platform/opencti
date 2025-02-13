import { v4 as uuidv4 } from 'uuid';
import type { ModuleDefinition } from '../../../schema/module';
import { registerDefinition } from '../../../schema/module';
import type { StixCsvMapper, StoreEntityCsvMapper } from './csvMapper-types';
import { ENTITY_TYPE_CSV_MAPPER } from './csvMapper-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../../schema/general';
import { normalizeName } from '../../../schema/identifier';
import convertCsvMapperToStix from './csvMapper-converter';
import './deprecated/csvMapper-deprecated';

const CSV_MAPPER_DEFINITION: ModuleDefinition<StoreEntityCsvMapper, StixCsvMapper> = {
  type: {
    id: 'csvmapper',
    name: ENTITY_TYPE_CSV_MAPPER,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CSV_MAPPER]: () => uuidv4()
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'has_header', label: 'Header', type: 'boolean', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'separator', label: 'Separator', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'representations', label: 'Representations', type: 'string', format: 'json', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'skipLineChar', label: 'Skip line character', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  relations: [],
  representative: (instance: StixCsvMapper) => {
    return instance.name;
  },
  converter: convertCsvMapperToStix
};

registerDefinition(CSV_MAPPER_DEFINITION);
