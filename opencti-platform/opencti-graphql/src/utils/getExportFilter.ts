import type { StoreMarkingDefinition } from '../types/store';
import { getExportContentMarkings } from './getExportContentMarkings';

type GetExportFilterType = {
  markingList: StoreMarkingDefinition[];
  contentMaxMarkings: string[];
  objectIdsList: string[];
};

export const getExportFilter = async ({ markingList, contentMaxMarkings, objectIdsList }: GetExportFilterType) => {
  const contentMarkings = contentMaxMarkings.length ? await getExportContentMarkings(markingList, contentMaxMarkings) : [];

  const filters = contentMarkings.length ? [
    { key: 'objectMarking', mode: 'and', operator: 'not_eq', values: contentMarkings },
  ] : [];

  const markingFilter = {
    mode: 'or',
    filters,
    filterGroups: [],
  };

  const mainFilter = {
    mode: 'and',
    filters: [],
    filterGroups: [
      {
        mode: 'or',
        filters: [{ key: 'id', values: objectIdsList }],
        filterGroups: [],
      },
      markingFilter
    ]
  };

  return { markingFilter, mainFilter };
};
