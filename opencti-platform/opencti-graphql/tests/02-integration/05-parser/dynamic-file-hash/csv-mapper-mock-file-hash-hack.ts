import { type CsvMapperParsed, CsvMapperRepresentationType, Operator } from '../../../../src/modules/internal/csvMapper/csvMapper-types';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE } from '../../../../src/schema/stixCyberObservable';

export const csvMapperMockFileHashHack: Partial<CsvMapperParsed> = {
  id: 'mapper-mock-file-hash-hack',
  has_header: true,
  separator: ',',
  representations: [
    {
      id: 'file-sha256',
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_HASHED_OBSERVABLE_STIX_FILE,
        column_based: {
          column_reference: 'H',
          operator: Operator.Eq,
          value: 'sha256'
        }
      },
      attributes: [
        {
          key: 'SHA-256',
          column: {
            column_name: 'I',
          },
        },
        {
          key: 'name',
          column: {
            column_name: 'A',
          },
        },
      ]
    },
    {
      id: 'file-md5',
      type: CsvMapperRepresentationType.Entity,
      target: {
        entity_type: ENTITY_HASHED_OBSERVABLE_STIX_FILE,
        column_based: {
          column_reference: 'H',
          operator: Operator.Eq,
          value: 'md5'
        }
      },
      attributes: [
        {
          key: 'MD5',
          column: {
            column_name: 'I',
          },
        },
        {
          key: 'name',
          column: {
            column_name: 'A',
          },
        },
      ]
    },
  ]
};
