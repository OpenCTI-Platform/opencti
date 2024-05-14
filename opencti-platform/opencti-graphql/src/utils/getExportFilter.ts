import type { StoreMarkingDefinition } from '../types/store';
import { getExportContentMarkings } from './getExportContentMarkings';
import { isNotEmptyField } from '../database/utils';

type GetExportFilterType = {
  markingList: StoreMarkingDefinition[];
  contentMaxMarkings: string[];
  objectIdsList: string[];
};

export const getExportFilter = async ({ markingList, contentMaxMarkings, objectIdsList }: GetExportFilterType) => {
  const contentMarkings = contentMaxMarkings.length ? await getExportContentMarkings(markingList, contentMaxMarkings) : [];

  const access_filters = contentMarkings.length ? [
    { key: 'objectMarking', mode: 'and', operator: 'not_eq', values: contentMarkings },
  ] : [];

  const markingFilter = {
    mode: 'and',
    filters: access_filters,
    filterGroups: [],
  };

  const mainFilter = {
    mode: 'and',
    filters: [...access_filters],
    filterGroups: []
  };
  if (isNotEmptyField(objectIdsList)) {
    mainFilter.filters.push({
      key: 'ids',
      values: objectIdsList,
      mode: 'or',
      operator: 'eq'
    });
  }

  return { markingFilter, mainFilter };
};
