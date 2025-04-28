import { FilterMode, FilterOperator } from '../../generated/graphql';
import type { ParsedPIR, PIRCriterion } from './pir-types';

const LANDRY_CRITERIA: PIRCriterion[] = [
  // Targets France
  {
    id: '1795b286-bbbb-4516-a330-a1c525efb947',
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
  // Targets Spain
  {
    id: 'b03f5d74-d80a-4628-bf18-5266ed2e0291',
    weight: 1,
    filters: {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        { key: ['entity_type'], values: ['targets'] },
        { key: ['toId'], values: ['6ce17f4b-8172-41e7-961f-ab071ca6dc30'] },
      ]
    }
  },
  // Targets Germany
  {
    id: 'b03f5d74-d80a-4628-bf18-5266ed2e0291',
    weight: 1,
    filters: {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        { key: ['entity_type'], values: ['targets'] },
        { key: ['toId'], values: ['9d49262b-3d1f-42cf-ae47-67e72212d80b'] },
      ]
    }
  }
];

const CATHIA_CRITERIA: PIRCriterion[] = [
  // Targets France
  {
    id: '1795b286-bbbb-4516-a330-a1c525efb947',
    weight: 2,
    filters: {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        { key: ['entity_type'], values: ['targets'] },
        { key: ['toId'], values: ['e783195e-6445-4b45-9076-b489a7f97e59'] },
      ]
    }
  },
  // Targets Europe
  {
    id: 'b03f5d74-d80a-4628-bf18-5266ed2e0291',
    weight: 1,
    filters: {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        { key: ['entity_type'], values: ['targets'] },
        { key: ['toId'], values: ['db3ae45b-ed00-4417-8835-312693eb940f'] },
      ]
    }
  }
];

// TODO PIR !!! id should be in a trigger filter to update the Resolved filters cache
export const FAKE_PIR: ParsedPIR = {
  id: '04aae53f-9991-48cf-8f94-5b20256a7546', // existing id to be able to add meta rel involving the PIR
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
  pirCriteria: [...LANDRY_CRITERIA, ...CATHIA_CRITERIA]
};
