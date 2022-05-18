import { buildRefRelationKey } from '../schema/general';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import { RELATION_INDICATES } from '../schema/stixCoreRelationship';

// eslint-disable-next-line import/prefer-default-export
export const GlobalFilters = {
  createdBy: buildRefRelationKey(RELATION_CREATED_BY),
  markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
  labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
  indicates: buildRefRelationKey(RELATION_INDICATES),
  containedBy: buildRefRelationKey(RELATION_OBJECT),
};

export const TYPE_FILTER = 'entity_type';
export const adaptFiltersFrontendFormat = (filters) => {
  const adaptedFilters = {};
  const filterEntries = Object.entries(filters);
  for (let index = 0; index < filterEntries.length; index += 1) {
    const [key, values] = filterEntries[index];
    if (key.endsWith('start_date') || key.endsWith('_gt')) {
      const workingKey = key.replace('_start_date', '').replace('_gt', '');
      adaptedFilters[workingKey] = { operator: 'gt', values };
    } else if (key.endsWith('end_date') || key.endsWith('_lt')) {
      const workingKey = key.replace('_end_date', '').replace('_lt', '');
      adaptedFilters[workingKey] = { operator: 'lt', values };
    } else if (key.endsWith('_lte')) {
      const workingKey = key.replace('_lte', '');
      adaptedFilters[workingKey] = { operator: 'lte', values };
    } else {
      adaptedFilters[key] = { operator: 'eq', values };
    }
  }
  return adaptedFilters;
};

export const convertFiltersToQueryOptions = (filters, opts = {}) => {
  const { after, before, defaultTypes = [], field = 'updated_at', orderMode = 'asc' } = opts;
  const queryFilters = [];
  const types = [...defaultTypes];
  if (filters) {
    const adaptedFilters = adaptFiltersFrontendFormat(filters);
    const filterEntries = Object.entries(adaptedFilters);
    for (let index = 0; index < filterEntries.length; index += 1) {
      // eslint-disable-next-line prefer-const
      let [key, { operator, values }] = filterEntries[index];
      if (key === TYPE_FILTER) {
        types.push(...values.map((v) => v.id));
      } else {
        queryFilters.push({ key: GlobalFilters[key] || key, values: values.map((v) => v.id), operator });
      }
    }
  }
  if (after) {
    queryFilters.push({ key: field, values: [after], operator: 'gte' });
  }
  if (before) {
    queryFilters.push({ key: field, values: [before], operator: 'lte' });
  }
  return { types, orderMode, orderBy: [field, 'internal_id'], filters: queryFilters };
};
