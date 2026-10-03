import { type InternalObjectModuleDefinition, registerInternalObjectDefinition } from '../../schema/module';
import { ENTITY_TYPE_DATA_SANITY_EXECUTION } from './dataSanity-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { v4 as uuidv4 } from 'uuid';

const DATA_SANITY_DEFINITION: InternalObjectModuleDefinition = {
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
    { name: 'last_run_success', label: 'Last run success', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'last_run_message', label: 'Last run message', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'last_run_output', label: 'Last run output', type: 'string', format: 'json', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: false },
    { name: 'force_run', label: 'Force run', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'is_running', label: 'Is running', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
};

registerInternalObjectDefinition(DATA_SANITY_DEFINITION);
