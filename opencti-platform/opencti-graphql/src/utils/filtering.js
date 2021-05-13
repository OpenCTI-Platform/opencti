import { REL_INDEX_PREFIX } from '../schema/general';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import { RELATION_INDICATES } from '../schema/stixCoreRelationship';

// eslint-disable-next-line import/prefer-default-export
export const GlobalFilters = {
  createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
  markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
  labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
  indicates: `${REL_INDEX_PREFIX}${RELATION_INDICATES}.internal_id`,
  containedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`,
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
