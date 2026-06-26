import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import type { StixDataSanity, StoreEntityDataSanity } from './dataSanity-types';
import { ENTITY_TYPE_DATA_SANITY_EXECUTION } from './dataSanity-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import convertDataSanityToStix from './dataSanity-converter';
import { v4 as uuidv4 } from 'uuid';

const DATA_SANITY_DEFINITION: ModuleDefinition<StoreEntityDataSanity, StixDataSanity> = {
  type: {
    id: 'dataSanity',
    name: ENTITY_TYPE_DATA_SANITY_EXECUTION,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_DATA_SANITY_EXECUTION]: () => uuidv4(),
    },
  },
  attributes: [
    { name: 'operation_name', label: 'Operation name', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'last_run_date', label: 'Last run date', type: 'date', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'last_execution_time', label: 'Last execution time (ms)', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'last_failure_message', label: 'Last failure message', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'force_run', label: 'Force run', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  representative: (stix: StixDataSanity) => {
    return stix.operation_name;
  },
  converter_2_1: convertDataSanityToStix,
};

registerDefinition(DATA_SANITY_DEFINITION);
