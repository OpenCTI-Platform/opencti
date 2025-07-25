import { GqlFilterGroup } from '../../../utils/filters/filtersUtils';

// eslint-disable-next-line import/prefer-default-export
export const pirHistoryFilterGroup = (pirId: string): GqlFilterGroup => {
  return {
    mode: 'and',
    filters: [
      {
        key: ['event_type'],
        values: ['create', 'delete', 'mutation'], // retro-compatibility
      },
    ],
    filterGroups: [
      {
        mode: 'or',
        filters: [
          {
            key: ['event_scope'],
            values: ['create', 'delete', 'update'],
          },
          {
            key: ['event_scope'],
            values: [], // if event_scope is null, event_type is not
            operator: 'nil',
          },
        ],
        filterGroups: [],
      },
      {
        mode: 'or',
        filters: [
          {
            key: ['context_data.pir_ids'],
            values: [pirId],
          },
        ],
        filterGroups: [],
      },
      {
        mode: 'or',
        filters: [
          {
            operator: 'not_eq',
            key: ['context_data.entity_type'],
            values: ['indicates'],
          },
        ],
        filterGroups: [],
      },
    ],
  };
};
