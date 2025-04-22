import { type FilterGroup, FilterMode, FilterOperator } from '../../generated/graphql';

interface PIRCriterion {
  filters: FilterGroup
  weight: number
}

export interface PIR {
  id: string
  name: string
  // Criteria are filters with a weight,
  // they are used to compute matching score.
  criteria: PIRCriterion[]
  // Filters do not count when computing score, their role
  // is to exclude some data (low confidence for example).
  filters: FilterGroup
}

export const FAKE_PIR: PIR = {
  id: '2b271fe3-8fdb-4df4-9b1f-bc55202dfa23',
  name: 'PIR about Energy sector in France',
  filters: {
    mode: FilterMode.And,
    filterGroups: [],
    filters: [{
      key: ['confidence'],
      values: ['80'],
      operator: FilterOperator.Gt,
      mode: FilterMode.Or
    }]
  },
  criteria: [
    {
      weight: 2,
      filters: {
        mode: FilterMode.And,
        filterGroups: [],
        filters: [
          { key: ['entity_type'], values: ['targets'] },
          { key: ['toId'], values: ['7ca7cad1-2618-489a-a74c-9a8e321fd963'] },
        ]
      }
    },
    {
      weight: 1,
      filters: {
        mode: FilterMode.And,
        filterGroups: [],
        filters: [
          { key: ['entity_type'], values: ['targets'] },
          { key: ['toId'], values: ['eed96959-31bd-43c9-a8f4-fffde144af52'] },
        ]
      }
    }
  ]
};
