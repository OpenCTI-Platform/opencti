import type { StoreMarkingDefinition } from '../types/store';
import { getExportContentMarkings } from './getExportContentMarkings';

type GetExportFilterType = {
  type: 'simple' | 'full';
  markingList: StoreMarkingDefinition[];
  contentMaxMarkings: string[];
  objectIdsList: string[];
};

export const getExportFilter = async ({ type, markingList, contentMaxMarkings, objectIdsList }: GetExportFilterType) => {
  const contentMarkings = await getExportContentMarkings(markingList, contentMaxMarkings);

  const simpleTypeFilter = [{ key: 'id', values: objectIdsList }];

  const fullTypeFilter = [...simpleTypeFilter, {
    key: 'regardingOf',
    values: [
      { key: 'id', values: objectIdsList },
      { key: 'relationship_type', values: [] },
    ]
  }];

  return {
    mode: 'and',
    filters: [],
    filterGroups: [
      {
        mode: 'or',
        filters: type === 'simple' ? simpleTypeFilter : fullTypeFilter,
        filterGroups: [],
      },
      {
        mode: 'or',
        filters: [
          { key: 'objectMarking', mode: 'or', operator: 'eq', values: contentMarkings },
          { key: 'objectMarking', mode: 'or', operator: 'nil', values: [] },
        ],
        filterGroups: [],
      }
    ]
  };
};
