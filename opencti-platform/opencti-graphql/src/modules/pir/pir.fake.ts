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
  id: '028ecfc0-d4d0-4f1c-a6b2-91c446eeb7c2', // existing id to be able to add meta rel involving the PIR
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
          { key: ['toId'], values: ['6bcb82c5-e440-4589-976e-5e28a99db3b3'] },
        ]
      }
    }
  ]
};
