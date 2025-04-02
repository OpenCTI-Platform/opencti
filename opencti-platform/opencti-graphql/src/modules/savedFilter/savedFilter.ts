import { v4 as uuidv4 } from 'uuid';
import convertSavedFiltersToStix from './savedFilter-converter';
import { ENTITY_TYPE_SAVED_FILTER, type StoreEntitySavedFilter, type StixSavedFilter } from './savedFilter-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { isFeatureEnabled } from '../../config/conf';
import { creators, createdAt } from '../../schema/attribute-definition';

const SAVED_FILTER_DEFINITION: ModuleDefinition<StoreEntitySavedFilter, StixSavedFilter> = {
  type: {
    id: 'saved-filter',
    name: ENTITY_TYPE_SAVED_FILTER,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_SAVED_FILTER]: () => uuidv4()
    },
  },
  attributes: [
    creators,
    createdAt,
    {
      name: 'name',
      label: 'Name',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true
    },
    {
      name: 'filters',
      label: 'Filters',
      type: 'string',
      format: 'text',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false
    },
    {
      name: 'scope',
      label: 'Scope',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false
    }
  ],
  relations: [],
  representative: (instance: StixSavedFilter) => {
    return instance.name;
  },
  converter_2_1: convertSavedFiltersToStix,
};

const isSavedFiltersEnabled = isFeatureEnabled('SAVED_FILTERS');

if (isSavedFiltersEnabled) {
  registerDefinition(SAVED_FILTER_DEFINITION);
}
