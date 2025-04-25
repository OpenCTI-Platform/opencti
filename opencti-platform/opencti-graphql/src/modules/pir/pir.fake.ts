import { type FilterGroup, FilterMode, FilterOperator } from '../../generated/graphql';

interface PIRCriterion {
  id: string
  filters: FilterGroup
  weight: number
}

export interface PIR {
  id: string
  name: string
  // Criteria are filters with a weight,
  // they are used to compute matching score.
  pirCriteria: PIRCriterion[]
  // Filters do not count when computing score, their role
  // is to exclude some data (low confidence for example).
  pirFilters: FilterGroup
}

// TODO PIR !!! id should be in a trigger filter to update the Resolved filters cache
export const FAKE_PIR: PIR = {
  id: '028ecfc0-d4d0-4f1c-a6b2-91c446eeb7c2', // existing id to be able to add meta rel involving the PIR
  name: 'PIR about Energy sector in France',
  pirFilters: {
    mode: FilterMode.And,
    filterGroups: [],
    filters: [{
      key: ['confidence'],
      values: ['80'],
      operator: FilterOperator.Gt,
      mode: FilterMode.Or
    }]
  },
  pirCriteria: [
    {
      id: '1795b286-bbbb-4516-a330-a1c525efb947',
      weight: 2,
      filters: {
        mode: FilterMode.And,
        filterGroups: [],
        filters: [
          { key: ['entity_type'], values: ['targets'] },
          { key: ['toId'], values: ['e783195e-6445-4b45-9076-b489a7f97e59'] }, // CATHIA France
        ]
      }
    },
    {
      id: '509ba0c6-4629-4fc2-bde9-12a110ea051e',
      weight: 1,
      filters: {
        mode: FilterMode.And,
        filterGroups: [],
        filters: [
          { key: ['entity_type'], values: ['targets'] },
          { key: ['toId'], values: ['6bcb82c5-e440-4589-976e-5e28a99db3b3'] },
        ]
      }
    },
    {
      id: 'b03f5d74-d80a-4628-bf18-5266ed2e0291',
      weight: 1,
      filters: {
        mode: FilterMode.And,
        filterGroups: [],
        filters: [
          { key: ['entity_type'], values: ['targets'] },
          { key: ['toId'], values: ['db3ae45b-ed00-4417-8835-312693eb940f'] }, // Cathia Western Europe
        ]
      }
    }
  ]
};
