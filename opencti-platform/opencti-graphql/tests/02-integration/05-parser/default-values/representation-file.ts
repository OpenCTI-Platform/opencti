import { type CsvMapperRepresentation, CsvMapperRepresentationType } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE } from '../../../../src/schema/stixCyberObservable';

export const repFile: CsvMapperRepresentation = {
  id: 'representation-file',
  type: CsvMapperRepresentationType.entity,
  target: {
    entity_type: ENTITY_HASHED_OBSERVABLE_STIX_FILE
  },
  attributes: [
    {
      key: 'MD5',
      column: {
        column_name: 'B'
      }
    },
    {
      key: 'SHA-1',
      column: {
        column_name: 'C'
      }
    },
    {
      key: 'SHA-256',
      column: {
        column_name: 'A'
      }
    }
  ]
};
