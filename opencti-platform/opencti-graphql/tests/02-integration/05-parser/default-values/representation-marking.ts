import { type CsvMapperRepresentation, CsvMapperRepresentationType } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../../../src/schema/stixMetaObject';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../../../../src/modules/administrativeArea/administrativeArea-types';

export const repMarking = {
  id: 'representation-marking',
  type: CsvMapperRepresentationType.entity,
  target: {
    entity_type: ENTITY_TYPE_MARKING_DEFINITION,
  },
  attributes: [
    {
      key: 'definition_type',
      column: {
        column_name: 'F',
      },
    },
    {
      key: 'definition',
      column: {
        column_name: 'G',
      },
    },
    {
      key: 'x_opencti_order',
      column: {
        column_name: 'H',
      },
    }
  ]
};

export const repAreaMarking: (policy: string | undefined) => CsvMapperRepresentation = (policy) => ({
  id: 'representation-area-marking',
  type: CsvMapperRepresentationType.entity,
  target: {
    entity_type: ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA,
  },
  attributes: [
    {
      key: 'name',
      column: {
        column_name: 'A',
      },
    },
    {
      key: 'objectMarking',
      default_values: policy ? [policy] : undefined,
      based_on: {
        representations: ['representation-marking']
      }
    }
  ]
});
