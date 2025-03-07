import { v4 as uuidv4 } from 'uuid';
import { ENTITY_TYPE_USER } from 'src/schema/internalObject';
import convertSavedFiltersToStix from './savedFilter-converter';
import { ENTITY_TYPE_SAVED_FILTER, type StoreEntitySavedFilter, type StixSavedFilter } from './savedFilter-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { isFeatureEnabled } from '../../config/conf';

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
    {
      name: 'user',
      label: 'User',
      type: 'string',
      format: 'id',
      entityTypes: [ENTITY_TYPE_USER],
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: true,
      isFilterable: true
    },
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
      name: 'filter',
      label: 'Filter',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: false,
      multiple: true,
      upsert: false,
      isFilterable: true
    },
    {
      name: 'scope',
      label: 'Scope',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: false,
      multiple: true,
      upsert: false,
      isFilterable: true
    }
  ],
  relations: [],
  representative: (instance: StixSavedFilter) => {
    return instance.name;
  },
  converter: convertSavedFiltersToStix,
};

const isSavedFiltersEnabled = isFeatureEnabled('SAVED_FILTERS');

if (isSavedFiltersEnabled) {
  registerDefinition(SAVED_FILTER_DEFINITION);
}
