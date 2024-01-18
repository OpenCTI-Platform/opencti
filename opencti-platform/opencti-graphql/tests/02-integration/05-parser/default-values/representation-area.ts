import { type CsvMapperRepresentation, CsvMapperRepresentationType } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../../../../src/modules/administrativeArea/administrativeArea-types';

export const repArea: CsvMapperRepresentation = {
  id: 'representation-area',
  type: CsvMapperRepresentationType.entity,
  target: {
    entity_type: ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA,
  },
  attributes: [
    {
      key: 'name',
      column: {
        column_name: 'B',
      },
    },
    {
      key: 'confidence',
      column: {
        column_name: 'C',
      },
    },
    {
      key: 'description',
      column: {
        column_name: 'D',
      },
    },
    {
      key: 'latitude',
      column: {
        column_name: 'E',
      },
    },
    {
      key: 'longitude',
      column: {
        column_name: 'F',
      },
    },
    {
      key: 'createdBy',
      based_on: {
        representations: ['representation-individual']
      }
    }
  ]
};

export const repAreaWithDefault: (creator: string) => CsvMapperRepresentation = (creator) => ({
  id: 'representation-area-default',
  type: CsvMapperRepresentationType.entity,
  target: {
    entity_type: ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA,
  },
  attributes: [
    {
      key: 'name',
      column: {
        column_name: 'B',
      },
    },
    {
      key: 'confidence',
      default_values: ['97'],
      column: {
        column_name: 'C',
      },
    },
    {
      key: 'description',
      default_values: ['hello area'],
      column: {
        column_name: 'D',
      },
    },
    {
      key: 'latitude',
      default_values: ['5.55'],
      column: {
        column_name: 'E',
      },
    },
    {
      key: 'longitude',
      default_values: ['6.66'],
      column: {
        column_name: 'F',
      },
    },
    {
      key: 'createdBy',
      default_values: [creator],
      based_on: {
        representations: ['representation-individual']
      }
    }
  ]
});
