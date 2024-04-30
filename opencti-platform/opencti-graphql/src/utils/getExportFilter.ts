import type { StoreMarkingDefinition } from '../types/store';
import { getExportContentMarkings } from './getExportContentMarkings';

type GetExportFilterType = {
  markingList: StoreMarkingDefinition[];
  contentMaxMarkings: string[];
  objectIdsList: string[];
};

export const getExportFilter = async ({ markingList, contentMaxMarkings, objectIdsList }: GetExportFilterType) => {
  const contentMarkings = await getExportContentMarkings(markingList, contentMaxMarkings);

  const markingFilter = {
    mode: 'or',
    filters: [
      { key: 'objectMarking', mode: 'or', operator: 'eq', values: contentMarkings },
      { key: 'objectMarking', mode: 'or', operator: 'nil', values: [] },
    ],
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
