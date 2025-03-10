import type { StixSavedFilter, StoreEntitySavedFilter } from './savedFilter-types';
import { buildStixObject } from '../../database/stix-converter';

const convertSavedFiltersToStix = (instance: StoreEntitySavedFilter): StixSavedFilter => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    filters: instance.filters,
    scope: instance.scope,
  };
};

export default convertSavedFiltersToStix;
